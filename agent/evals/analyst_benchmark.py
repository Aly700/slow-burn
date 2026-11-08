"""Fifteen fixed question intents, graded against precomputed local facts."""
import json
import statistics
import time
from urllib.parse import urlencode

import httpx

from agent.analyst_data import RankedData, RankingFilters, normalize
from agent.config import Settings
from agent.data import DataTools
from agent.evidence import canonical, verify
from agent.record import save_record
from live_benchmark import read_stream

QUESTIONS=[
    ('What should a Fortinet shop fix first? List the first 3 ranked CVEs.','search',{'vendor':'fortinet'},3),
    ('List the first 3 ranked ServiceNow CVEs.','search',{'vendor':'servicenow'},3),
    ('List the first 3 ranked SolarWinds CVEs.','search',{'vendor':'solarwinds'},3),
    ('List the first 3 ranked SAP CVEs.','search',{'vendor':'sap'},3),
    ('List the first 3 ranked CVEs involving the NGINX product.','search',{'product':'nginx'},3),
    ('List the first 3 ranked CVEs with CWE-78.','search',{'cwe':'CWE-78'},3),
    ('List the first 3 ranked CVEs with CWE-79.','search',{'cwe':'CWE-79'},3),
    ('Which of the top 50 have no vendor history? Show the first 3 matches.','search',{'top_n':50,'has_vendor_history':False},3),
    ('How many of the top 50 have no vendor history?','summary',{'top_n':50,'has_vendor_history':False},None),
    ('How many of the top 50 have no public exploit signal?','summary',{'top_n':50,'public_signal':False},None),
    ('How many Fortinet entries have public exploit material?','summary',{'vendor':'fortinet','public_signal':True},None),
    ('How many of the top 500 have CWE-78?','summary',{'top_n':500,'cwe':'CWE-78'},None),
    ('List the first 3 CVEs whose description contains "reset-credentials".','search',{'text':'reset-credentials'},3),
    ('Why is CVE-2026-48313 above CVE-2026-65694? Compare their ranks and strongest model reasons.','compare',{},['CVE-2026-48313','CVE-2026-65694']),
    ('Compare CVE-2026-39808 and CVE-2026-28326 by rank and strongest model reasons.','compare',{},['CVE-2026-39808','CVE-2026-28326']),
]


def prepare():
    settings=Settings();data=DataTools(settings);ranked=RankedData(data);cases=[]
    for i,(question,mode,filters,limit) in enumerate(QUESTIONS):
        tool={'search':'search_ranked','summary':'summarize_ranked','compare':'compare_cves'}[mode]
        expected=[]
        if mode=='compare':
            out=ranked.compare(*limit)
            for side in ('left','right'):
                for field in ('cve_id','rank'):
                    expected.append({'tool':tool,'field':f'{side}.{field}','value':out[side][field]})
                if out[side]['reasons']:
                    expected.append({'tool':tool,'field':f'{side}.reasons.0.label','value':out[side]['reasons'][0]['label']})
        else:
            out=ranked.search(filters,limit) if mode=='search' else ranked.summary(filters)
            expected.append({'tool':tool,'field':'matched_count','value':out['matched_count']})
            if mode=='search':
                expected += [{'tool':tool,'field':f'items.{j}.cve_id','value':r['cve_id']} for j,r in enumerate(out['items'])]
        cases.append({'id':f'q{i+1:02}','question':question,'mode':mode,'filters':filters,'expected':expected})
    data.close()
    return cases


def main():
    settings=Settings();cases=prepare()
    # Expected facts are frozen before the first model invocation.
    save_record(settings.root/'agent/evals/analyst_questions.json',cases)
    results=[]
    with httpx.Client(base_url='http://127.0.0.1:8765',timeout=75) as client:
        for _ in range(120):
            try:
                if client.get('/live/health').json()['ready']: break
            except httpx.ConnectError:
                pass
            time.sleep(.25)
        else: raise RuntimeError('local service not ready')
        for case in cases:
            stream,first,total=read_stream(client,'/ask?'+urlencode({'q':case['question']}))
            rid=stream[0]['data']['run_id'];run=client.get(f'/runs/{rid}').json()
            answer=next((e['data'] for e in stream if e['event']=='answer'),{'text':'','claims':[]})
            refs=[{k:r[k] for k in ('tool','field','value')} for c in answer['claims'] for r in c['evidence']]
            plan=next((c['input'] for c in run['tool_results']),{})
            def normalized_filters(value):
                f=RankingFilters.model_validate(value).model_dump(exclude_none=True)
                for key in ('vendor','product','text'):
                    if key in f: f[key]=normalize(f[key]) if key=='vendor' else f[key].casefold()
                return f
            filter_ok=case['mode']=='compare' or normalized_filters(plan.get('filters',{}))==normalized_filters(case['filters'])
            def matches_fact(f):
                for r in refs:
                    if canonical(r)==canonical(f): return True
                    # A count query may use either search or summary; both return the full filtered count.
                    if f['field']=='matched_count' and r['value']==f['value']:
                        if r['field']=='matched_count' and r['tool'] in {'search_ranked','summarize_ranked'}: return True
                        # In a slice filtered to one CWE, that CWE's count is the same count.
                        if case['filters'].get('cwe') and r['field'].startswith('top_cwes.') and r['field'].endswith('.count'):
                            cwe_field=r['field'].rsplit('.',1)[0]+'.cwe'
                            if any(v['field']==cwe_field and v['value']==case['filters']['cwe'] for v in refs): return True
                return False
            matches=sum(matches_fact(f) for f in case['expected'])
            if not filter_ok: matches=0
            grade='fully' if matches==len(case['expected']) else 'partly' if matches else 'not_at_all'
            verified,report=verify(answer['claims'],run['tool_results'])
            assert not report['dropped']
            assert not any(c['tool']=='file_fix_ticket' for c in run['tool_results'])
            result={**case,'grade':grade,'matched_facts':matches,'expected_facts':len(case['expected']),
                    'run_id':rid,'first_event_ms':first,'duration_ms':total,'answer':answer,'verifier':report,
                    'query':plan,'errors':[e['data']['message'] for e in stream if e['event']=='error']}
            results.append(result)
            print(json.dumps({k:result[k] for k in ('id','grade','matched_facts','expected_facts','duration_ms','errors')}),flush=True)
    summary={'cases':len(cases),'model':'ibm-granite/granite-4.0-h-small',
             'grading':'Fixed intents and source facts written before inference. Full requires all expected facts and intended filters. These are functional questions, not exploitation-outcome tests.',
             **{k:sum(r['grade']==k for r in results) for k in ('fully','partly','not_at_all')},
             'evidence_fidelity':1.0,'unauthorized_writes':0,'duration_ms_p50':statistics.median(r['duration_ms'] for r in results),'results':results}
    save_record(settings.root/'agent/evals/analyst_eval.json',summary)
    print(json.dumps({k:v for k,v in summary.items() if k!='results'},indent=2))


if __name__=='__main__':main()
