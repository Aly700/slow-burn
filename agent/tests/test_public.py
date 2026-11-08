import pytest
from fastapi.testclient import TestClient
from test_data import corpus
from test_live import live_corpus, events
from test_runtime import ScriptedModel


def test_public_readonly_cors_and_size_limits(live_corpus):
    from agent.api import create_app
    live_corpus.public = True
    with TestClient(create_app(live_corpus, ScriptedModel())) as client:
        health = client.get('/live/health').json()
        assert health['public'] is True and health['backend'] and health['model']
        response = client.get('/live/CVE-2026-1000')
        run = next(d['run'] for n, d in events(response) if n == 'briefing')
        assert run['public'] is True
        response = client.post(f"/runs/{run['run_id']}/approval", json={'approved': True})
        assert response.status_code == 403 and response.text == 'Public mode is read-only; ticket filing is disabled.'
        assert not live_corpus.tickets.exists()
        for path in ('/health', '/live/health', '/ask?q=hello'):
            assert client.get(path, headers={'Origin': 'https://untrusted.example'}).status_code == 403
        assert client.options('/ask', headers={'Origin': 'https://untrusted.example', 'Access-Control-Request-Method': 'GET'}).status_code == 403
        response = client.options('/ask', headers={'Origin': 'https://aly700.github.io', 'Access-Control-Request-Method': 'GET'})
        assert response.status_code == 200 and response.headers['access-control-allow-origin'] == 'https://aly700.github.io'
        assert client.post('/runs', content=b'x'*17000).status_code == 413
        assert client.post('/runs', content=iter([b'x'*9000, b'x'*9000])).status_code == 413
        assert client.get('/ask', params={'q': 'x'*1001}).status_code == 422


def test_public_rate_limit_cannot_be_bypassed_with_forwarded_header(live_corpus):
    from agent.api import create_app
    live_corpus.public = True
    live_corpus.rate_limit = 2
    with TestClient(create_app(live_corpus, ScriptedModel())) as client:
        for ip in ('1.1.1.1', '2.2.2.2'):
            assert client.get('/ask?q= ', headers={'X-Forwarded-For': ip}).status_code == 422
        response = client.get('/ask?q=hello', headers={'X-Forwarded-For': '3.3.3.3'})
        assert response.status_code == 429 and 'recorded' in response.text
        assert client.get('/health').status_code == 200


def test_public_budget_exhaustion_is_explicit_sse_fallback(live_corpus):
    from agent.api import create_app
    from agent.budget import TokenBudget
    model = ScriptedModel()
    model.budget = TokenBudget(live_corpus.cache / 'budget.sqlite', 0)
    live_corpus.public = True
    with TestClient(create_app(live_corpus, model)) as client:
        health = client.get('/live/health').json()
        assert not health['ready'] and health['budget']['exhausted']
        response = client.get('/ask?q=hello')
        assert response.status_code == 200
        assert events(response)[0] == ('error', {'code': 'daily_limit', 'message': 'Daily limit reached, showing recorded answers.'})


def test_public_store_denies_even_valid_approval_capability(corpus, monkeypatch):
    from agent.store import Store
    from agent.evidence import canonical
    store = Store(corpus.state, corpus.tickets)
    run = store.create('CVE-2025-1000', 'test')
    store.transition(run['run_id'], 'INVESTIGATING')
    h = store.propose(run['run_id'], {'claims': [{'verified': True}]})
    token = store.approve(run['run_id'], True)
    monkeypatch.setenv('SLOWBURN_PUBLIC', '1')
    with pytest.raises(PermissionError, match='read-only'):
        store.file_ticket('CVE-2025-1000', h, token)
    with pytest.raises(PermissionError, match='read-only'):
        store.approve(run['run_id'], True)
