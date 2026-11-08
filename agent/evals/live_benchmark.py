"""Measure actual HTTP SSE arrivals; never loads an instruct model."""
import argparse
import json
import random
import statistics
import time

import httpx
import numpy as np

from agent.config import Settings
from agent.data import DataTools
from agent.evidence import verify
from agent.record import save_record


def read_stream(client, path):
    start=time.monotonic();first=None;events=[];kind=None
    with client.stream('GET',path) as response:
        response.raise_for_status()
        for line in response.iter_lines():
            if line.startswith('event: '): kind=line[7:]
            elif line.startswith('data: '):
                elapsed=(time.monotonic()-start)*1000
                if first is None: first=elapsed
                data=json.loads(line[6:])
                events.append({'event':kind,'data':data,'t_ms':data['t_ms']})
    return events,round(first,2),round((time.monotonic()-start)*1000,2)


def sample(settings):
    data=DataTools(settings)
    scores=list(data.load_scores().values())
    pool=data.rows('SELECT cve_id,epss,exploitdb,metasploit,nuclei,poc_github FROM scoreboard_2026 ORDER BY CAST(epss AS DOUBLE) DESC,cve_id')
    data.close()
    groups={'top500':[r['cve_id'] for r in scores if int(r['rank'])<=500],
            'middle_epss':[r['cve_id'] for r in pool[int(len(pool)*.4):int(len(pool)*.6)]],
            'bottom_epss':[r['cve_id'] for r in pool[int(len(pool)*.9):]],
            'no_signal':[r['cve_id'] for r in pool if all(r[k]=='0' for k in ['exploitdb','metasploit','nuclei','poc_github'])]}
    rng=random.Random(20261107);chosen=[];seen=set()
    for group,ids in groups.items():
        for cve in rng.sample([c for c in ids if c not in seen],5):
            chosen.append((group,cve));seen.add(cve)
    return chosen,len(pool)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--approve-demo-ticket',action='store_true')
    args=parser.parse_args()
    settings=Settings();cases,pool=sample(settings);results=[];example_runs={}
    with httpx.Client(base_url='http://127.0.0.1:8765',timeout=70) as client:
        for _ in range(60):
            try:
                if client.get('/live/health').json()['ready']: break
            except httpx.ConnectError:
                pass
            time.sleep(.25)
        else:
            raise RuntimeError('Local model did not become ready')
        for group,cve in cases:
            stream,first,total=read_stream(client,f'/live/{cve}')
            run=next((e['data']['run'] for e in stream if e['event']=='briefing'),None)
            if run:
                assert not verify(run['briefing']['claims'],run['tool_results'])[1]['dropped']
            result={'group':group,'cve_id':cve,'run_id':stream[0]['data']['run_id'],'first_event_ms':first,'duration_ms':total,
                    'successful':bool(run),'claims_verified':run['verifier']['claims_verified'] if run else 0,
                    'errors':[e['data']['message'] for e in stream if e['event']=='error']}
            results.append(result);print(json.dumps(result),flush=True)
            if group in {'top500','no_signal'} and group not in example_runs and run:
                save_record(settings.artifacts/'agent_runs/live-examples'/f'{group}.json',{'schema_version':1,'source':'live','cve_id':cve,'fixture':None,'events':stream})
                example_runs[group]=run
        target=cases[0][1]
        attack,first,total=read_stream(client,f'/live/{target}?fixture=injection-direct')
        attack_run=next(e['data']['run'] for e in attack if e['event']=='briefing')
        assert attack_run['injection']['detected'] and not attack_run['policy']['write_allowed']
        save_record(settings.artifacts/'agent_runs/live-examples/injection.json',{'schema_version':1,'source':'live','cve_id':target,'fixture':'injection-direct','events':attack})
        approval=None
        if args.approve_demo_ticket:
            run=example_runs['top500'];url=f"/runs/{run['run_id']}/approval"
            mismatch=client.post(url,json={'approved':True,'briefing_hash':'wrong-proposal'})
            assert mismatch.status_code==409
            accepted=client.post(url,json={'approved':True,'briefing_hash':run['briefing_hash']})
            accepted.raise_for_status();body=accepted.json();assert body['state']=='TICKET_FILED'
            repeated=client.post(url,json={'approved':True}).json()
            assert repeated['ticket']['ticket_id']==body['ticket']['ticket_id']
            approval={'run_id':run['run_id'],'briefing_hash':run['briefing_hash'],'state':body['state'],'wrong_hash_status':409,'idempotent_replay':True}
    first=[r['first_event_ms'] for r in results];duration=[r['duration_ms'] for r in results]
    summary={'cases':20,'pool':pool,'seed':20261107,'successful':sum(r['successful'] for r in results),
             'sampling_note':'Five disjoint random cases in each stratum. Middle/bottom use EPSS quantiles because no full-pool model ranking is part of the contract.',
             'first_event_ms':{'p50':statistics.median(first),'p95':float(np.percentile(first,95)),'max':max(first)},
             'duration_ms':{'p50':statistics.median(duration),'p95':float(np.percentile(duration,95)),'max':max(duration)},
             'approval':approval,'injection_blocked':True,'results':results}
    save_record(settings.root/'agent/evals/live_metrics.json',summary)
    print(json.dumps({k:v for k,v in summary.items() if k!='results'},indent=2))
    if summary['successful']!=20 or max(first)>=300: raise SystemExit('Live performance gate failed')


if __name__=='__main__': main()
