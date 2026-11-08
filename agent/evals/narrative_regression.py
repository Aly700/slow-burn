"""Compare clean evidence availability without loading an instruct model."""
import argparse
import json

from agent.cards import evidence_cards
from agent.config import Settings
from agent.data import DataTools
from agent.evidence import verify
from agent.narrative import describe
from agent.record import save_record
from agent.safety import scan_text


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--baseline',action='store_true');args=parser.parse_args()
    settings=Settings();cache=settings.cache/'narrative_before.json'
    if args.baseline:
        if cache.exists(): raise SystemExit('baseline already frozen')
        prior=json.loads((settings.artifacts/'redteam_eval.json').read_text())
        data=DataTools(settings);rows=[]
        for r in prior['clean_detector_results']:
            row=data.get_cve(r['cve_id']);call={'call_id':'t1','tool':'get_cve','output':row}
            rows.append({'cve_id':r['cve_id'],'row':row,'cards':evidence_cards([call]),'profile':describe(row),'detected':bool(scan_text(row['description']))})
        top=[]
        for r in sorted(data.load_scores().values(),key=lambda r:int(r['rank']))[:15]:
            run=json.loads((settings.artifacts/'agent_runs'/f"{r['cve_id']}.json").read_text())
            top.append({'cve_id':r['cve_id'],'run':run,'cards':evidence_cards(run['tool_results'])})
        data.close();save_record(cache,{'clean':rows,'top15':top});print('frozen 100 clean descriptions and 15 recorded runs');return
    baseline=json.loads(cache.read_text());diffs=[]
    for entry in baseline['clean']:
        row=entry['row'];call={'call_id':'t1','tool':'get_cve','output':row}
        cards=evidence_cards([call]);assert not verify(cards,[call])[1]['dropped']
        texts={c['text'] for c in cards};old={c['text'] for c in entry['cards']}
        diffs.append({'cve_id':entry['cve_id'],'detected_before':entry['detected'],'detected_after':bool(scan_text(row['description'])),
                      'removed':[c['text'] for c in entry['cards'] if c['text'] not in texts],
                      'added':[c['text'] for c in cards if c['text'] not in old],
                      'categories_before':sorted({c['category'] for c in entry['cards']}),'categories_after':sorted({c['category'] for c in cards})})
    top=[]
    for entry in baseline['top15']:
        old=entry['run'];cards=evidence_cards(old['tool_results']);texts={c['text'] for c in cards}
        path=settings.artifacts/'agent_runs'/f"{entry['cve_id']}.json";current=json.loads(path.read_text())
        fresh=current['run_id']!=old['run_id']
        now_text={c['text'] for c in current['briefing']['claims']}
        top.append({'cve_id':entry['cve_id'],'headline_before':old['briefing']['headline'],'headline_after':current['briefing']['headline'] if fresh else None,
                    'rerecorded':fresh,'old_claims_no_longer_available':[c['text'] for c in old['briefing']['claims'] if c['text'] not in texts],
                    'recorded_claims_removed':[c['text'] for c in old['briefing']['claims'] if c['text'] not in now_text] if fresh else [],
                    'recorded_claims_added':[c['text'] for c in current['briefing']['claims'] if c['text'] not in {v['text'] for v in old['briefing']['claims']}] if fresh else [],
                    'action_before':old['briefing']['action'],'action_after':current['briefing']['action'] if fresh else None})
    report={'clean_cases':100,'false_positives_before':sum(r['detected_before'] for r in diffs),'false_positives_after':sum(r['detected_after'] for r in diffs),
            'clean_cases_with_removed_claims':sum(bool(r['removed']) for r in diffs),'clean_removed_claims':sum(len(r['removed']) for r in diffs),
            'top15_old_claims_no_longer_available':sum(len(r['old_claims_no_longer_available']) for r in top),
            'clean_results':diffs,'top15':top}
    save_record(settings.root/'agent/evals/narrative_regression.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in {'clean_results','top15'}}))


if __name__=='__main__':main()
