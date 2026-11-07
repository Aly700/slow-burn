"""Exercise explicit approve/deny decisions against the local demo API."""
import argparse
import json
from pathlib import Path
import time

import httpx

from agent.config import Settings
from agent.record import save_record


def main():
    parser = argparse.ArgumentParser(description='Verify the local API using an explicitly approved demo ticket')
    parser.add_argument('--approve-demo-ticket', action='store_true', required=True)
    args = parser.parse_args()
    settings = Settings()
    with httpx.Client(base_url='http://127.0.0.1:8765', timeout=65) as client:
        for _ in range(40):
            try:
                health = client.get('/health')
                if health.status_code == 200 and health.json()['ready']:
                    break
            except httpx.ConnectError:
                pass
            time.sleep(.5)
        else:
            raise SystemExit('Local API did not become ready')
        def investigate(cve):
            response = client.post('/runs', json={'cve_id': cve})
            response.raise_for_status()
            rid = response.json()['run_id']
            for _ in range(110):
                run = client.get('/runs/' + rid).json()
                if run['state'] not in {'RECEIVED','INVESTIGATING'}:
                    break
                time.sleep(.5)
            assert run['state'] == 'WAITING_APPROVAL', run.get('error')
            return run
        run = investigate('CVE-2026-8037')
        rid = run['run_id']
        result = client.post(f'/runs/{rid}/approval', json={'approve': True, 'briefing_hash': run['briefing_hash']})
        result.raise_for_status()
        accepted = result.json()
        assert accepted['state'] == 'TICKET_FILED'
        assert accepted['tool_results'][-1]['output']['allowed'] is True
        replay = client.post(f'/runs/{rid}/approval', json={'approve': True}).json()
        assert replay['ticket']['ticket_id'] == accepted['ticket']['ticket_id']
        save_record(settings.artifacts / 'agent_runs/approval-accepted.json', accepted)
        run = investigate('CVE-2022-25369')
        rid = run['run_id']
        result = client.post(f'/runs/{rid}/approval', json={'approve': False})
        result.raise_for_status()
        rejected = result.json()
        assert rejected['state'] == 'REJECTED'
        assert client.post(f'/runs/{rid}/approval', json={'approve': True}).status_code == 409
        assert client.get(f'/runs/{rid}/trace').json()['trace']
        save_record(settings.artifacts / 'agent_runs/approval-rejected.json', rejected)
        tickets = [json.loads(line) for line in settings.tickets.read_text().splitlines()]
        keys = [ticket['idempotency_key'] for ticket in tickets]
        assert len(keys) == len(set(keys))
        print(json.dumps({'approved_state': accepted['state'], 'rejected_state': rejected['state'], 'idempotent_replay': True,
                          'unique_local_tickets': len(keys), 'approved_write_traced': True}))


if __name__ == '__main__':
    main()
