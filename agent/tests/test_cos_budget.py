import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from agent.budget import DailyLimit
from agent.cos_budget import CosBudget


def test_conditional_budget_is_global_across_clients_and_restarts():
    state = {}; lock = threading.Lock()
    def server(request):
        with lock:
            key = str(request.url)
            value = state.get(key)
            if request.method == 'GET':
                return httpx.Response(404) if value is None else httpx.Response(200, content=value[0], headers={'ETag':value[1]})
            if (value is None and request.headers.get('if-none-match') != '*') or (value is not None and request.headers.get('if-match') != value[1]):
                return httpx.Response(412)
            state[key] = (request.content, hashlib.sha256(request.content).hexdigest())
            return httpx.Response(200)
    def budget():
        return CosBudget('https://s3.us-south.cloud-object-storage.appdomain.cloud/test/budget', 100,
                         lambda:'test-token', client=httpx.Client(transport=httpx.MockTransport(server)))
    def reserve(_):
        try: return budget().reserve(60)
        except DailyLimit: return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(reserve, range(2)))
    assert sum(v is not None for v in receipts) == 1
    assert budget().status()['used_tokens'] == 60
    budget().settle(next(v for v in receipts if v), 20)
    assert budget().status()['used_tokens'] == 20
    assert budget().status()['exhausted']


def test_unavailable_or_corrupt_durable_budget_fails_closed():
    for response in (httpx.Response(500, text='private error'), httpx.Response(200, json={'bad':'state'}, headers={'ETag':'x'})):
        budget = CosBudget('https://s3.us-south.cloud-object-storage.appdomain.cloud/test/budget', 100,
                           lambda:'test-token', client=httpx.Client(transport=httpx.MockTransport(lambda r:response)))
        with pytest.raises(RuntimeError, match='budget unavailable') as exc:
            budget.reserve(20)
        assert 'private error' not in str(exc.value)
