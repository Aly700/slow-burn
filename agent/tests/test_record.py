import csv
import json

import pytest
from test_data import corpus, write_csv
from test_runtime import ScriptedModel


@pytest.mark.asyncio
async def test_alternate_csv_records_watch_run_through_real_mcp(corpus, monkeypatch):
    import agent.record as module
    from agent.evidence import verify
    from agent.store import Store
    with corpus.scores.open() as stream:
        row = next(csv.DictReader(stream))
    row.update(score='.005', any_exploit='0', exploitdb='0', metasploit='0', nuclei='0', poc_github='0')
    source = corpus.artifacts / 'different-ranking.csv'
    write_csv(source,[row])
    monkeypatch.setattr(module, 'Settings', lambda: corpus)
    monkeypatch.setattr(module, 'Granite', lambda name: ScriptedModel())
    monkeypatch.setattr(module.EmbeddingIndex, 'build', lambda *args: None)
    await module.record(top=1, fixtures=False, source=source)
    recorded = json.loads((corpus.artifacts/'agent_runs/CVE-2025-1000.json').read_text())
    assert recorded['list'] == 'watch'
    assert recorded['state'] == 'WAITING_APPROVAL'
    assert recorded['briefing']['verdict'] == 'watch'
    assert 'Check exposure' in recorded['briefing']['headline']
    assert 'next maintenance window' in recorded['briefing']['action']
    assert 'emergency' not in recorded['briefing']['action']
    assert not verify(recorded['briefing']['claims'],recorded['tool_results'])[1]['dropped']
    assert Store(corpus.state,corpus.tickets).get(recorded['run_id'])['list'] == 'watch'
    assert not corpus.tickets.exists()


def test_record_cli_accepts_from_path(monkeypatch, tmp_path):
    import agent.record as module
    seen = {}
    async def fake_record(top, fixtures, source):
        seen.update(top=top,fixtures=fixtures,source=source)
    monkeypatch.setattr(module, 'record', fake_record)
    source = tmp_path/'watch.csv'
    monkeypatch.setattr('sys.argv',['agent.record','--from',str(source),'--top','8','--skip-fixtures'])
    module.main()
    assert seen == {'top':8,'fixtures':False,'source':source}


def test_default_ranking_stays_top500_and_missing_signals_are_not_watch(corpus):
    from agent.record import classify_list
    quiet = dict.fromkeys(['any_exploit','exploitdb','metasploit','nuclei','poc_github'],'0')
    assert classify_list([quiet],corpus.scores,corpus.artifacts) == 'top500'
    other = corpus.artifacts/'any-ranking.csv'
    assert classify_list([quiet],other,corpus.artifacts) == 'watch'
    assert classify_list([dict(quiet,nuclei='1')],other,corpus.artifacts) == 'top500'
    assert classify_list([dict(quiet,poc_github='')],other,corpus.artifacts) == 'top500'
    with pytest.raises(ValueError,match='empty'):
        classify_list([],other,corpus.artifacts)
