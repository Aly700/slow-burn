"""Independently check committed-format recordings against their own evidence ledgers."""
import csv
import json
from pathlib import Path

from agent.evidence import verify
from agent.store import digest

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = {'run_id','cve_id','state','states_seen','model','started_at','duration_ms','briefing','verifier','policy','injection','trace'}
STATES = {'RECEIVED','INVESTIGATING','VERIFIED','WAITING_APPROVAL','TICKET_FILED','REJECTED','FAILED'}


def main():
    with (ROOT / 'artifacts/scores_2026_top5000.csv').open() as f:
        top = [r['cve_id'] for r in sorted(csv.DictReader(f), key=lambda r: int(r['rank']))[:15]]
    for cve in top:
        assert (ROOT / f'artifacts/agent_runs/{cve}.json').exists(), cve
    count = 0
    for path in (ROOT / 'artifacts/agent_runs').rglob('*.json'):
        run = json.loads(path.read_text())
        assert REQUIRED <= run.keys(), path
        assert run['state'] in STATES, path
        assert run['states_seen'][-1] == run['state'], path
        if run['state'] == 'FAILED':
            continue
        assert run['briefing']['verdict'] in {'fix_now','watch','defer'}, path
        kept, report = verify(run['briefing']['claims'], run['tool_results'])
        assert kept and not report['dropped'], (path, report)
        assert digest(run['briefing']) == run['briefing_hash'], path
        assert run['verifier']['claims_total'] == run['verifier']['claims_verified'] + len(run['verifier']['dropped']), path
        if run['state'] == 'WAITING_APPROVAL':
            assert not run['policy']['write_allowed'], path
        if run['state'] == 'TICKET_FILED':
            assert run['approval']['approved'] is True and run['policy']['write_allowed'], path
        if run['state'] == 'REJECTED':
            assert run['approval']['approved'] is False and not run['policy']['write_allowed'], path
        count += 1
    print(json.dumps({'recordings_checked': count, 'top15_present': True, 'all_claims_resolve': True, 'all_briefing_hashes_match': True}))


if __name__ == '__main__':
    main()
