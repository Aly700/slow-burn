"""Public HTTP boundary. No prompt, query string, or credential logging."""
from collections import deque
import asyncio
import ipaddress
import os
import time
from urllib.parse import urlsplit

from starlette.responses import PlainTextResponse, JSONResponse, Response

from .budget import DAILY_MESSAGE

READ_ONLY = 'Public mode is read-only; ticket filing is disabled.'
LOCAL_ORIGIN = r'http://(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?'


def allowed_origin(origin):
    if origin == 'https://aly700.github.io':
        return True
    try:
        url = urlsplit(origin)
        return (url.scheme == 'http' and url.hostname in {'localhost', '127.0.0.1', '::1'}
                and not url.username and not url.password and not url.path and not url.query and not url.fragment
                and (url.port is None or 0 < url.port <= 65535))
    except ValueError:
        return False


def fallback(code, message):
    # EventSource hides HTTP error bodies; an explicit error event reaches the page.
    import json
    return Response('event: error\ndata: '+json.dumps({'code': code, 'message': message})+'\n\n',
                    media_type='text/event-stream', headers={'Cache-Control': 'no-store'})


class PublicBoundary:
    def __init__(self, app, settings, model):
        self.app, self.settings, self.model = app, settings, model
        self.windows = {}
        self.trusted = [ipaddress.ip_network(s.strip()) for s in os.getenv('SLOWBURN_TRUSTED_PROXIES', '').split(',') if s.strip()]

    def client_ip(self, scope, headers):
        peer = (scope.get('client') or ('unknown', 0))[0]
        def trusted(value):
            try:
                return any(ipaddress.ip_address(value) in net for net in self.trusted)
            except ValueError:
                return False
        # Trust forwarded addresses only behind explicitly configured proxies.
        if trusted(peer):
            for address in reversed(headers.get('x-forwarded-for', '').split(',')):
                address = address.strip()
                try:
                    ipaddress.ip_address(address)
                except ValueError:
                    return peer
                if not trusted(address):
                    return address
        return peer

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = {k.decode('latin1').lower(): v.decode('latin1') for k, v in scope['headers']}
        async def respond(response):
            await response(scope, receive, send)
        origin = headers.get('origin')
        if origin and not allowed_origin(origin):
            return await respond(PlainTextResponse('Origin is not allowed.', status_code=403))
        path, method = scope['path'], scope['method']
        if len(scope.get('query_string', b'')) > 16384 or len(path) > 256:
            return await respond(PlainTextResponse('Request is too large.', status_code=413))
        if method == 'POST' and path.endswith('/approval'):
            return await respond(PlainTextResponse(READ_ONLY, status_code=403))
        if method not in {'GET', 'POST', 'OPTIONS', 'HEAD'}:
            return await respond(PlainTextResponse('Method is not allowed.', status_code=405))
        if method == 'POST':
            try:
                length = int(headers.get('content-length', '0'))
            except ValueError:
                return await respond(PlainTextResponse('Invalid request size.', status_code=400))
            if length > 16384 or length < 0:
                return await respond(PlainTextResponse('Request is too large.', status_code=413))
            body = bytearray()
            while True:
                message = await receive()
                if message['type'] == 'http.disconnect':
                    return
                body.extend(message.get('body', b''))
                if len(body) > 16384:
                    return await respond(PlainTextResponse('Request is too large.', status_code=413))
                if not message.get('more_body'):
                    break
            delivered = False
            original_receive = receive
            async def bounded_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
                return await original_receive()
            receive = bounded_receive
        inference = method != 'OPTIONS' and (path == '/ask' or (path.startswith('/live/') and path != '/live/health') or (path == '/runs' and method == 'POST'))
        if inference:
            now = time.monotonic()
            # Expire idle entries and bound address cardinality as well as requests.
            self.windows = {ip: q for ip, q in self.windows.items() if q and q[-1] > now-self.settings.rate_window}
            ip = self.client_ip(scope, headers)
            if len(self.windows) >= 10000 and ip not in self.windows:
                return await respond(JSONResponse({'detail': 'Service busy, showing recorded answers.'}, status_code=429))
            q = self.windows.setdefault(ip, deque())
            while q and q[0] <= now-self.settings.rate_window:
                q.popleft()
            if len(q) >= self.settings.rate_limit:
                return await respond(JSONResponse({'detail': 'Rate limit reached, showing recorded answers.'}, status_code=429,
                                                  headers={'Retry-After': str(self.settings.rate_window)}))
            q.append(now)
            budget = getattr(self.model, 'budget', None)
            try:
                exhausted = budget and (await asyncio.to_thread(budget.status))['exhausted']
            except RuntimeError:
                return await respond(fallback('budget_unavailable', 'Daily token budget unavailable; showing recorded answers.'))
            if exhausted:
                response = fallback('daily_limit', DAILY_MESSAGE) if method == 'GET' else JSONResponse({'detail': DAILY_MESSAGE}, status_code=429)
                return await respond(response)
        return await self.app(scope, receive, send)
