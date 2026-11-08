import asyncio
import csv
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient
from test_data import corpus, write_csv
from test_runtime import ScriptedModel


@pytest.fixture
def live_corpus(corpus):
    corpus.snapshot_month = None
    with (corpus.data/'vulnerabilities.csv').open() as f:
        rows = list(csv.DictReader(f))
    rows.append({**rows[0], 'cve_id':'CVE-2026-1000','published':'2026-01-01'})
    write_csv(corpus.data/'vulnerabilities.csv', rows)
    return corpus


def events(response):
    result = []
    for block in response.text.split('\n\n'):
        if block.startswith('event: '):
            lines = block.splitlines()
            result.append((lines[0][7:],json.loads(lines[1][6:])))
    return result


def test_live_stream_schema_order_unknown_injection_and_approval(live_corpus):
    from agent.api import create_app
    with TestClient(create_app(live_corpus, ScriptedModel())) as client:
        health = client.get('/live/health').json()
        assert health['ready'] and health['loaded_at'] and health['model']
        response = client.get('/live/CVE-2026-1000')
        assert response.status_code == 200
        assert response.headers['content-type'].startswith('text/event-stream')
        stream = events(response)
        names = [name for name,_ in stream]
        assert names[0] == 'start' and names[-1] == 'done'
        assert [d['state'] for n,d in stream if n=='state'] == ['RECEIVED','INVESTIGATING','VERIFIED','WAITING_APPROVAL']
        assert names.index('tool_call') < names.index('tool_result') < names.index('claim') < names.index('briefing')
        calls = {d['call_id']:i for i,(n,d) in enumerate(stream) if n=='tool_call'}
        for i,(name,data) in enumerate(stream):
            assert isinstance(data['t_ms'],int)
            if name=='tool_result':
                assert calls[data['call_id']] < i and len(data['preview']) <= 8 and data['ms'] >= 0
            if name=='claim':
                assert {'id','text','evidence','verified','reason'} <= data.keys()
        run = next(d['run'] for n,d in stream if n=='briefing')
        assert run['list']=='live' and run['briefing']['verdict'] in {'fix_now','watch','defer'}
        assert not (live_corpus.artifacts/'agent_runs/CVE-2026-1000.json').exists()
        assert (live_corpus.cache/'live_runs'/f"{run['run_id']}.json").exists()
        accepted = client.post(f"/runs/{run['run_id']}/approval",json={'approved':True,'briefing_hash':run['briefing_hash']})
        assert accepted.json()['state']=='TICKET_FILED'
        assert json.loads((live_corpus.cache/'live_runs'/f"{run['run_id']}.json").read_text())['state']=='TICKET_FILED'
        unknown = events(client.get('/live/CVE-2026-9999'))
        assert unknown[0][0]=='start' and unknown[-1][0]=='done'
        assert 'error' in [n for n,_ in unknown] and 'briefing' not in [n for n,_ in unknown]
        attack = events(client.get('/live/CVE-2026-1000?fixture=injection-direct'))
        r = next(d['run'] for n,d in attack if n=='briefing')
        assert r['injection']['detected'] and not r['policy']['write_allowed']
        assert r['fixture']=='injection-direct'


def test_hosted_origin_private_network_preflight(live_corpus):
    from agent.api import create_app
    with TestClient(create_app(live_corpus,ScriptedModel())) as client:
        headers={'Origin':'https://aly700.github.io','Access-Control-Request-Method':'GET','Access-Control-Request-Private-Network':'true'}
        response=client.options('/live/CVE-2026-1000',headers=headers)
        assert response.status_code==200
        assert response.headers['access-control-allow-origin']=='https://aly700.github.io'
        assert response.headers['access-control-allow-private-network']=='true'
        response=client.options('/live/CVE-2026-1000',headers=dict(headers,Origin='https://untrusted.example'))
        assert response.status_code==400 and 'access-control-allow-private-network' not in response.headers


def test_unverified_claim_is_streamed_as_dropped(live_corpus):
    from agent.api import create_app
    from agent.model import Completion
    class AddsUnknown(ScriptedModel):
        def complete(self,messages,max_tokens,deadline):
            result=super().complete(messages,max_tokens,deadline)
            if json.loads(messages[-1]['content'])['phase']=='briefing':
                value=json.loads(result.text);value['claim_ids'].append('invented-fact')
                return Completion(json.dumps(value),{})
            return result
    with TestClient(create_app(live_corpus,AddsUnknown())) as client:
        stream=events(client.get('/live/CVE-2026-1000'))
        dropped=[data for kind,data in stream if kind=='claim' and not data['verified']]
        assert len(dropped)==1 and dropped[0]['id']=='invented-fact' and dropped[0]['reason']
        run=next(data['run'] for kind,data in stream if kind=='briefing')
        assert run['verifier']['dropped'][0]['id']=='invented-fact'
        assert all(c['id']!='invented-fact' for c in run['briefing']['claims'])


class ControlledModel(ScriptedModel):
    supports_cancellation=True
    def __init__(self):
        self.entered=threading.Event()
        self.release=threading.Event()
        self.active=0
        self.maximum=0
    def complete(self,messages,max_tokens,deadline,cancel_event=None):
        from agent.inference import GenerationCancelled
        self.active+=1; self.maximum=max(self.maximum,self.active)
        self.entered.set()
        try:
            while not self.release.wait(.005):
                if cancel_event and cancel_event.is_set(): raise GenerationCancelled('cancelled')
                if time.monotonic()>deadline: raise TimeoutError('deadline')
            return super().complete(messages,max_tokens,deadline)
        finally:
            self.active-=1


@pytest.mark.asyncio
async def test_queue_and_cancellation_do_not_overlap_generations(live_corpus):
    from agent.api import create_app
    from agent.store import Store
    model=ControlledModel();app=create_app(live_corpus,model)
    async with app.router.lifespan_context(app):
        service=app.state.service
        first=service.submit('CVE-2026-1000')
        await asyncio.wait_for(asyncio.to_thread(model.entered.wait),3)
        second=service.submit('CVE-2026-1000')
        assert any(e['event']=='state' and e['data'].get('queued') for e in second.events)
        second.cancel();first.cancel()
        await asyncio.wait_for(first.finished.wait(),3)
        await asyncio.wait_for(second.finished.wait(),3)
        store=Store(live_corpus.state,live_corpus.tickets)
        for job in [first,second]:
            run=store.get(job.run_id)
            assert run['state']=='FAILED' and run['error']['code']=='cancelled' and run['briefing'] is None
        assert model.maximum==1 and model.active==0
        assert not live_corpus.tickets.exists()


@pytest.mark.asyncio
async def test_stream_disconnect_cancels_active_run(live_corpus):
    from agent.api import create_app
    from agent.store import Store
    model=ControlledModel();app=create_app(live_corpus,model)
    incoming=asyncio.Queue();await incoming.put({'type':'http.request','body':b'','more_body':False})
    started=asyncio.Event();pieces=[]
    async def send(message):
        if message['type']=='http.response.body':
            pieces.append(message.get('body',b''))
            if b'event: start' in message.get('body',b''): started.set()
    scope={'type':'http','asgi':{'version':'3.0','spec_version':'2.0'},'http_version':'1.1','method':'GET','scheme':'http','path':'/live/CVE-2026-1000','raw_path':b'/live/CVE-2026-1000','query_string':b'','root_path':'','headers':[],'client':('127.0.0.1',9999),'server':('127.0.0.1',8765)}
    async with app.router.lifespan_context(app):
        request=asyncio.create_task(app(scope,incoming.get,send))
        await asyncio.wait_for(started.wait(),1)
        await asyncio.wait_for(asyncio.to_thread(model.entered.wait),3)
        await incoming.put({'type':'http.disconnect'})
        await asyncio.wait_for(request,3)
        rid=json.loads(b''.join(pieces).decode().split('data: ',1)[1].split('\n',1)[0])['run_id']
        await asyncio.wait_for(app.state.service.queue.join(),3)
        run=Store(live_corpus.state,live_corpus.tickets).get(rid)
        assert run['error']['code']=='cancelled' and run['briefing'] is None


@pytest.mark.asyncio
async def test_archive_failure_finishes_stream_and_worker_continues(live_corpus,monkeypatch):
    from agent.api import create_app
    import agent.live as module
    original=module.save_record
    count=0
    def fail_once(*args):
        nonlocal count
        count+=1
        if count==1: raise PermissionError('test archive unavailable')
        return original(*args)
    monkeypatch.setattr(module,'save_record',fail_once)
    app=create_app(live_corpus,ScriptedModel())
    async with app.router.lifespan_context(app):
        service=app.state.service
        first=service.submit('CVE-2026-1000');second=service.submit('CVE-2026-1000')
        await asyncio.wait_for(service.queue.join(),3)
        assert first.finished.is_set() and second.finished.is_set()
        assert first.events[-1]['event']=='done' and any(e['event']=='error' for e in first.events)
        assert any(e['event']=='briefing' for e in second.events)
        assert service.error is None and not service.jobs


@pytest.mark.asyncio
async def test_fatal_worker_cancellation_terminalizes_active_and_pending(live_corpus):
    from agent.api import create_app
    from agent.store import Store
    model=ControlledModel();app=create_app(live_corpus,model)
    async with app.router.lifespan_context(app):
        service=app.state.service
        first=service.submit('CVE-2026-1000')
        await asyncio.wait_for(asyncio.to_thread(model.entered.wait),3)
        second=service.submit('CVE-2026-1000')
        service.worker.cancel()
        await asyncio.wait_for(asyncio.gather(service.worker,return_exceptions=True),3)
        await asyncio.wait_for(service.queue.join(),1)
        store=Store(live_corpus.state,live_corpus.tickets)
        for job in [first,second]:
            assert job.finished.is_set() and job.events[-1]['event']=='done'
            assert any(e['event']=='error' for e in job.events)
            assert store.get(job.run_id)['state']=='FAILED'
        assert model.active==0 and not service.jobs


def test_approval_cache_failure_does_not_hide_committed_ticket(live_corpus,monkeypatch):
    import agent.api as module
    with TestClient(module.create_app(live_corpus,ScriptedModel())) as client:
        stream=events(client.get('/live/CVE-2026-1000'))
        run=next(d['run'] for n,d in stream if n=='briefing')
        original=module.save_record
        def fail(*args): raise PermissionError('archive unavailable')
        monkeypatch.setattr(module,'save_record',fail)
        url=f"/runs/{run['run_id']}/approval"
        accepted=client.post(url,json={'approved':True})
        assert accepted.status_code==200 and accepted.json()['state']=='TICKET_FILED'
        assert accepted.json()['cache_warning']
        monkeypatch.setattr(module,'save_record',original)
        assert client.post(url,json={'approved':True}).status_code==200
        assert len(live_corpus.tickets.read_text().splitlines())==1
        assert json.loads((live_corpus.cache/'live_runs'/f"{run['run_id']}.json").read_text())['state']=='TICKET_FILED'
