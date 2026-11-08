import argparse
import asyncio
import json
from pathlib import Path

from .client import ToolClient
from .config import IBM_MODEL, Settings
from .data import DataTools
from .embeddings import EmbeddingIndex
from .model import Granite
from .priority import PUBLIC_SOURCES
from .runtime import Runner
from .store import Store


def save_record(path, run):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.pending.json')
    tmp.write_text(json.dumps(run, indent=2, ensure_ascii=False) + '\n')
    tmp.replace(path)


def classify_list(rows, source, artifacts):
    if not rows:
        raise ValueError('ranking file is empty')
    if source.resolve() == (artifacts/'scores_2026_top5000.csv').resolve():
        return 'top500'
    flags = ('any_exploit', *PUBLIC_SOURCES)
    quiet = all(str(row.get(key, '')).strip() in {'0','0.0'} for row in rows for key in flags)
    return 'watch' if quiet else 'top500'


async def record(top=15, fixtures=True, source=None):
    settings = Settings()
    if source is not None:
        settings.score_path = Path(source).expanduser().resolve()
    data = DataTools(settings)
    try:
        list_name = classify_list(list(data.load_scores().values()), settings.scores, settings.artifacts)
        ids = [r['cve_id'] for r in data.queue(top)['items']]
        EmbeddingIndex.build(settings, data)
    finally:
        data.close()
    store = Store(settings.state, settings.tickets)
    model = Granite(settings.model)
    await asyncio.to_thread(model.warmup)
    runner = Runner(settings, store, model)
    results = []
    async with ToolClient(settings) as client:
        for cve in ids:
            run = store.create(cve, IBM_MODEL, list_name=list_name)
            result = await runner.run(run['run_id'], client)
            save_record(settings.artifacts / 'agent_runs' / f'{cve}.json', result)
            results.append(result)
            print(json.dumps({'cve_id': cve, 'state': result['state'], 'duration_ms': result['duration_ms'], 'claims': result['verifier']['claims_verified'], 'error': result.get('error')}), flush=True)
    if fixtures:
        specs = json.loads((Path(__file__).resolve().parents[2] / 'evals/injections.json').read_text())
        for fixture in specs:
            async with ToolClient(settings, fixture=fixture['id']) as client:
                run = store.create(ids[0], IBM_MODEL, list_name=list_name)
                result = await runner.run(run['run_id'], client)
                save_record(settings.artifacts / 'agent_runs' / f"{fixture['id']}.json", result)
                results.append(result)
                print(json.dumps({'fixture': fixture['id'], 'state': result['state'], 'injection_detected': result['injection']['detected'], 'write_allowed': result['policy']['write_allowed']}), flush=True)
    if any(r['state'] != 'WAITING_APPROVAL' for r in results):
        raise SystemExit('Some recordings failed; inspect the recorded errors.')


def main():
    parser = argparse.ArgumentParser(description='Re-record offline briefings using the current ranking')
    parser.add_argument('--top', type=int, default=15)
    parser.add_argument('--skip-fixtures', action='store_true')
    parser.add_argument('--from', dest='source', type=Path, help='Ranking CSV with the standard score-file columns')
    args = parser.parse_args()
    if not 1 <= args.top <= 100:
        parser.error('--top must be 1 to 100')
    asyncio.run(record(args.top, not args.skip_fixtures, args.source))


if __name__ == '__main__':
    main()
