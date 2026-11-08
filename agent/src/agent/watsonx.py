"""Granite chat transport. The application, not native function calls, owns tools."""
import json
import os
import threading
import time

import httpx

from .inference import check_cancel
from .model import Completion

MODEL = 'ibm/granite-4-h-small'
IAM_URL = 'https://iam.cloud.ibm.com/identity/token'
SERVICE_URL = 'https://us-south.ml.cloud.ibm.com'


class Watsonx:
    backend = 'watsonx'
    supports_cancellation = True
    name = source_name = MODEL
    revision = None

    def __init__(self, *, api_key=None, project_id=None, url=None, client=None, budget=None):
        self._api_key = api_key if api_key is not None else os.getenv('WATSONX_APIKEY', '')
        self._project_id = project_id if project_id is not None else os.getenv('WATSONX_PROJECT_ID', '')
        self._url = (url or os.getenv('WATSONX_URL', SERVICE_URL)).rstrip('/')
        if self._url != SERVICE_URL:
            raise ValueError('WATSONX_URL must use the configured IBM us-south endpoint')
        self._client = client or httpx.Client(follow_redirects=False, trust_env=False)
        self._lock = threading.Lock()
        self._iam_lock = threading.Lock()
        self._token = None
        self._expires = 0
        self.budget = budget

    def warmup(self):
        if not self._api_key or not self._project_id:
            raise RuntimeError('watsonx runtime credentials are missing')

    def close(self):
        self._client.close()
        if hasattr(self.budget, 'close'):
            self.budget.close()

    def _post(self, url, deadline, **kwargs):
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('model deadline exceeded')
        try:
            response = self._client.post(url, timeout=httpx.Timeout(remaining, connect=min(5, remaining)), **kwargs)
        except httpx.HTTPError:
            raise RuntimeError('IBM service connection failed; showing recorded answers.') from None
        return response

    def _bearer(self, deadline):
        with self._iam_lock:
            return self._refresh_bearer(deadline)

    def _refresh_bearer(self, deadline):
        if self._token and time.time() < self._expires-60:
            return self._token
        response = self._post(IAM_URL, deadline, data={
            'grant_type': 'urn:ibm:params:oauth:grant-type:apikey', 'apikey': self._api_key},
            headers={'Accept': 'application/json'})
        if response.status_code != 200:
            raise RuntimeError('IBM authentication unavailable; showing recorded answers.')
        try:
            body = response.json()
            self._token, self._expires = body['access_token'], int(body['expiration'])
            if not isinstance(self._token, str) or self._expires <= time.time():
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise RuntimeError('IBM authentication response invalid') from None
        return self._token

    def complete(self, messages, max_tokens, deadline, cancel_event=None):
        with self._lock:
            if cancel_event is not None:
                check_cancel(cancel_event)
            if time.monotonic() >= deadline:
                raise TimeoutError('model deadline exceeded')
            self.warmup()
            # MLX renders Granite's template locally. The chat endpoint renders it
            # server-side: send identical role/content messages, never template text.
            # Tool choice is existing schema-bound JSON, with no API tools supplied.
            if any(m.get('role') not in {'system', 'user', 'assistant'} or not isinstance(m.get('content'), str) for m in messages):
                raise ValueError('unsupported chat message format')
            if not 1 <= max_tokens <= 1024:
                raise ValueError('generation token limit outside allowed range')
            # UTF-8 byte count plus a generous per-message template allowance is
            # an upper bound for Granite byte-level tokenization, before generation.
            upper = len(json.dumps(messages, ensure_ascii=False).encode()) + 512*len(messages) + max_tokens
            reservation = self.budget.reserve(upper) if self.budget else None
            token = self._bearer(deadline)
            if cancel_event is not None:
                check_cancel(cancel_event)
            payload = {'model_id': MODEL, 'project_id': self._project_id, 'messages': messages,
                       'max_tokens': max_tokens, 'temperature': 0, 'response_format': {'type': 'json_object'},
                       'time_limit': max(1, int((deadline-time.monotonic())*1000))}
            response = self._post(self._url+'/ml/v1/text/chat', deadline, params={'version': '2024-05-31'},
                                  headers={'Authorization': 'Bearer '+token}, json=payload)
            if response.status_code != 200:
                if response.status_code == 401:
                    self._token = None
                # Never expose IBM response bodies, request headers, or exceptions.
                raise RuntimeError(f'IBM inference unavailable (HTTP {response.status_code}); showing recorded answers.')
            try:
                body = response.json()
                usage = body['usage']
                prompt, generated, total = (usage[k] for k in ('prompt_tokens', 'completion_tokens', 'total_tokens'))
                if any(type(v) is not int or v < 0 for v in (prompt, generated, total)) or total != prompt+generated:
                    raise ValueError()
            except (KeyError, TypeError, ValueError):
                raise RuntimeError('IBM usage response invalid; token reservation retained') from None
            if self.budget:
                self.budget.settle(reservation, total)
            metrics = {'prompt_tokens': prompt, 'generation_tokens': generated, 'total_tokens': total, 'backend': self.backend}
            try:
                message = body['choices'][0]['message']
                if message.get('tool_calls') or message.get('function_call'):
                    raise RuntimeError('unexpected native tool call; no tool was executed')
                content = message['content']
                if not isinstance(content, str):
                    raise ValueError()
            except (KeyError, IndexError, TypeError, ValueError):
                raise RuntimeError('IBM chat response format invalid') from None
            if cancel_event is not None:
                check_cancel(cancel_event)
            return Completion(content, metrics)
