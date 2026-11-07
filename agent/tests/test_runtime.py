import asyncio
import json

import pytest
from test_data import corpus


class ScriptedModel:
    name = 'test-protocol-model'
    def warmup(self):
        return None
    def complete(self, messages, max_tokens, deadline):
        from agent.model import Completion
        body = json.loads(messages[-1]['content'])
        if body['phase'] == 'tools':
            output = {'tools': ['vendor_history', 'signal_timeline']}
        else:
            output = {'verdict': 'watch', 'claim_ids': [c['id'] for c in body['facts'][:3]], 'action_id': 'investigate', 'confidence': .5}
        return Completion(json.dumps(output), {'generation_tokens': 40, 'generation_tps': 1000.0})


@pytest.mark.asyncio
async def test_runtime_verifies_real_mcp_evidence_and_stops_at_approval(corpus):
    from agent.client import ToolClient
    from agent.runtime import Runner
    from agent.store import Store
    store = Store(corpus.state, corpus.tickets)
    run = store.create('CVE-2025-1000', ScriptedModel.name)
    async with ToolClient(corpus) as client:
        await Runner(corpus, store, ScriptedModel()).run(run['run_id'], client)
    result = store.get(run['run_id'])
    assert result['state'] == 'WAITING_APPROVAL'
    assert result['verifier']['claims_verified'] >= 1
    assert all(c['verified'] for c in result['briefing']['claims'])
    assert result['policy']['write_allowed'] is False
    assert not corpus.tickets.exists()


@pytest.mark.asyncio
async def test_invalid_model_output_exhausts_repairs_and_fails(corpus):
    from agent.client import ToolClient
    from agent.model import Completion
    from agent.runtime import Runner
    from agent.store import Store
    class Broken(ScriptedModel):
        def complete(self, *args, **kwargs):
            return Completion('not valid JSON', {})
    store = Store(corpus.state, corpus.tickets)
    run = store.create('CVE-2025-1000', Broken.name)
    async with ToolClient(corpus) as client:
        await Runner(corpus, store, Broken()).run(run['run_id'], client)
    result = store.get(run['run_id'])
    assert result['state'] == 'FAILED'
    assert result['briefing'] is None
    assert result['metrics']['model_calls'] <= corpus.max_turns


@pytest.mark.asyncio
async def test_injected_description_cannot_authorize_a_ticket(corpus):
    from agent.client import ToolClient
    from agent.runtime import Runner
    from agent.store import Store
    store = Store(corpus.state, corpus.tickets)
    run = store.create('CVE-2025-1000', ScriptedModel.name)
    async with ToolClient(corpus, fixture='injection-subtle') as client:
        await Runner(corpus, store, ScriptedModel()).run(run['run_id'], client)
    result = store.get(run['run_id'])
    assert result['injection']['detected']
    assert result['injection']['write_probe']['allowed'] is False
    assert not corpus.tickets.exists()


def test_api_approve_deny_and_trace(corpus):
    from fastapi.testclient import TestClient
    from agent.api import create_app
    with TestClient(create_app(corpus, ScriptedModel())) as client:
        def completed():
            response = client.post('/runs', json={'cve_id': 'CVE-2025-1000'})
            assert response.status_code == 202
            rid = response.json()['run_id']
            import time
            for _ in range(100):
                run = client.get('/runs/' + rid).json()
                if run['state'] not in {'RECEIVED', 'INVESTIGATING'}:
                    break
                time.sleep(.01)
            assert run['state'] == 'WAITING_APPROVAL'
            return rid
        rid = completed()
        response = client.post(f'/runs/{rid}/approval', json={'approve': True})
        assert response.status_code == 200
        assert response.json()['state'] == 'TICKET_FILED'
        assert client.post(f'/runs/{rid}/approval', json={'approve': True}).json()['state'] == 'TICKET_FILED'
        assert len(corpus.tickets.read_text().splitlines()) == 1
        other = completed()
        assert client.post(f'/runs/{other}/approval', json={'approve': False}).json()['state'] == 'REJECTED'
        assert client.post(f'/runs/{other}/approval', json={'approve': True}).status_code == 409
        assert client.get(f'/runs/{other}/trace').json()['trace']
        assert client.post(f'/runs/{other}/approval', headers={'Origin': 'https://untrusted.example'}, json={'approve': True}).status_code == 403
        assert client.post('/runs', json={'cve_id': '../../private'}).status_code == 422


@pytest.mark.asyncio
async def test_proposal_not_exposed_until_policy_probe_finishes(corpus):
    from agent.client import ToolClient
    from agent.runtime import Runner
    from agent.store import Store
    store = Store(corpus.state, corpus.tickets)
    run = store.create('CVE-2025-1000', ScriptedModel.name)
    entered, release = asyncio.Event(), asyncio.Event()
    async with ToolClient(corpus) as client:
        class DelayedProbe:
            async def call(self, name, args):
                if name == 'file_fix_ticket':
                    entered.set()
                    await release.wait()
                return await client.call(name, args)
        task = asyncio.create_task(Runner(corpus, store, ScriptedModel()).run(run['run_id'], DelayedProbe()))
        await asyncio.wait_for(entered.wait(), 3)
        try:
            assert store.get(run['run_id'])['state'] == 'INVESTIGATING'
        finally:
            release.set()
            await task


@pytest.mark.asyncio
async def test_all_unknown_claims_fail_and_remain_counted(corpus):
    from agent.client import ToolClient
    from agent.model import Completion
    from agent.runtime import Runner
    from agent.store import Store
    class UnknownFacts(ScriptedModel):
        def complete(self, messages, max_tokens, deadline):
            if json.loads(messages[-1]['content'])['phase'] == 'tools':
                return super().complete(messages, max_tokens, deadline)
            return Completion(json.dumps({'verdict':'fix_now', 'claim_ids':['fabricated'], 'action_id':'remediate', 'confidence':.9}), {})
    store = Store(corpus.state, corpus.tickets)
    run = store.create('CVE-2025-1000', UnknownFacts.name)
    async with ToolClient(corpus) as client:
        await Runner(corpus, store, UnknownFacts()).run(run['run_id'], client)
    result = store.get(run['run_id'])
    assert result['state'] == 'FAILED'
    assert result['briefing'] is None
    assert result['verifier']['claims_total'] == 1
    assert result['verifier']['claims_verified'] == 0
    assert result['verifier']['dropped'][0]['id'] == 'fabricated'
