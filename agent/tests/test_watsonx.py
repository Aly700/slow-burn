import json
import threading
import time

import httpx
import pytest

from agent.model import create_model
from agent.config import Settings
from agent.watsonx import Watsonx
from agent.budget import TokenBudget, DailyLimit


def backend(tmp_path, handler, limit=10000):
    budget = TokenBudget(tmp_path / 'budget.sqlite', limit)
    model = Watsonx(api_key='test-only-value', project_id='test-project',
                    client=httpx.Client(transport=httpx.MockTransport(handler)), budget=budget)
    return model, budget


def test_chat_keeps_messages_and_counts_usage_and_caches_iam(tmp_path):
    requests = []
    messages = [{'role': 'system', 'content': 'Return JSON.'}, {'role': 'user', 'content': '{"phase":"tools"}'}]
    def handler(request):
        requests.append(request)
        if request.url.host == 'iam.cloud.ibm.com':
            return httpx.Response(200, json={'access_token': 'test-bearer', 'expiration': int(time.time()) + 3600})
        body = json.loads(request.content)
        assert body['messages'] == messages
        assert body['model_id'] == 'ibm/granite-4-h-small'
        assert body['max_tokens'] == 120 and body['temperature'] == 0
        assert body['response_format'] == {'type': 'json_object'} and 'tools' not in body
        return httpx.Response(200, json={'choices': [{'message': {'content': '{"tools":["queue"]}'}}],
                                       'usage': {'prompt_tokens': 20, 'completion_tokens': 8, 'total_tokens': 28}})
    model, budget = backend(tmp_path, handler)
    for _ in range(2):
        result = model.complete(messages, 120, time.monotonic()+5)
        assert json.loads(result.text)['tools'] == ['queue']
        assert result.metrics['total_tokens'] == 28
    assert len([r for r in requests if r.url.host == 'iam.cloud.ibm.com']) == 1
    assert budget.status()['used_tokens'] == 56


def test_native_tool_calls_rejected_without_execution_and_charged(tmp_path):
    def handler(request):
        if request.url.host == 'iam.cloud.ibm.com':
            return httpx.Response(200, json={'access_token': 'test-bearer', 'expiration': int(time.time())+3600})
        return httpx.Response(200, json={'choices': [{'message': {'tool_calls': [{'function': {'name': 'file_fix_ticket'}}]}}],
                                       'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15}})
    model, budget = backend(tmp_path, handler)
    with pytest.raises(RuntimeError, match='unexpected native tool call'):
        model.complete([{'role': 'user', 'content': 'JSON'}], 20, time.monotonic()+5)
    assert budget.status()['used_tokens'] == 15


def test_error_body_never_escapes_and_uncertain_usage_stays_reserved(tmp_path):
    def handler(request):
        if request.url.host == 'iam.cloud.ibm.com':
            return httpx.Response(200, json={'access_token': 'test-bearer', 'expiration': int(time.time())+3600})
        return httpx.Response(500, text='private upstream detail')
    model, budget = backend(tmp_path, handler)
    with pytest.raises(RuntimeError) as exc:
        model.complete([{'role': 'user', 'content': 'JSON'}], 20, time.monotonic()+5)
    assert 'private upstream detail' not in str(exc.value)
    assert budget.status()['used_tokens'] > 20


def test_budget_atomic_persistent_and_rolls_over_by_utc_day(tmp_path):
    path = tmp_path / 'budget.sqlite'
    budget = TokenBudget(path, 100, day=lambda: '2026-11-08')
    reservation = budget.reserve(80)
    with pytest.raises(DailyLimit):
        TokenBudget(path, 100, day=lambda: '2026-11-08').reserve(21)
    budget.settle(reservation, 30)
    assert budget.status()['used_tokens'] == 30
    assert TokenBudget(path, 100, day=lambda: '2026-11-09').status()['used_tokens'] == 0


def test_limit_and_cancellation_do_not_contact_provider(tmp_path):
    def handler(request):
        pytest.fail('unexpected network call')
    model, _ = backend(tmp_path, handler, limit=0)
    with pytest.raises(DailyLimit):
        model.complete([{'role': 'user', 'content': 'JSON'}], 20, time.monotonic()+5)
    from agent.inference import GenerationCancelled
    event = threading.Event(); event.set()
    with pytest.raises(GenerationCancelled):
        model.complete([], 20, time.monotonic()+5, event)


def test_default_backend_is_still_mlx(monkeypatch):
    monkeypatch.delenv('SLOWBURN_MODEL_BACKEND', raising=False)
    assert create_model(Settings()).backend == 'mlx'
    monkeypatch.setenv('SLOWBURN_MODEL_BACKEND', 'invalid')
    with pytest.raises(ValueError):
        create_model(Settings())
