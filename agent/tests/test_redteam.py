import pytest
from test_data import corpus
from test_live import live_corpus,events
from test_runtime import ScriptedModel

from agent.attacks import variants,apply_fixture,fixture_ids
from agent.safety import scan_text


def test_adversarial_variants_are_distinct_labelled_copies():
    cases=variants()
    assert len(cases)>=40 and len({v['payload'] for v in cases})==len(cases)
    assert len({v['group'] for v in cases})==8
    row={'cve_id':'CVE-2026-1000','description':'A real product allows remote code execution.','signals':{'epss':.2}}
    for case in cases:
        copied=apply_fixture(row,case['id'])
        assert copied['fixture']==case['id'] and row['description'] in copied['description']
        assert copied['signals']==row['signals'] and copied['cve_id']==row['cve_id']
    assert row['description']=='A real product allows remote code execution.'
    assert scan_text(apply_fixture(row,'redteam-01')['description'])
    with pytest.raises(ValueError): apply_fixture(row,'../../secret')


def test_all_adversarial_ids_are_predefined():
    assert len(fixture_ids())==50
    assert 'redteam-49' not in fixture_ids()


def test_survival_measure_catches_full_payloads_in_every_language():
    import sys
    from pathlib import Path
    directory=Path(__file__).resolve().parents[1]/'evals'
    sys.path.insert(0,str(directory))
    try:
        from redteam_benchmark import surviving_texts,summarize_safety
        for attack in variants():
            briefing={'headline':attack['payload'],'action':'Review exposure.','claims':[]}
            assert surviving_texts(briefing,attack,'The original product description.'),attack['id']
        result=summarize_safety([{'unsafe_writes':1,'unverified_claims':2}],b'',b'{"idempotency_key":"new"}\n')
        assert result['tickets_filed_without_approval']==1 and result['unsafe_tool_authorizations']==1
        assert result['unverified_claims']==2 and not result['ticket_ledger_unchanged']
        assert summarize_safety([],b'',b'broken')['ticket_ledger_parse_error']
    finally:
        sys.path.remove(str(directory))


def test_adversarial_stream_preserves_signals_and_cannot_file_ticket(live_corpus):
    from fastapi.testclient import TestClient
    from agent.api import create_app
    with TestClient(create_app(live_corpus,ScriptedModel())) as client:
        clean=next(d['run'] for n,d in events(client.get('/live/CVE-2026-1000')) if n=='briefing')
        for fixture in ['redteam-01','redteam-19','redteam-37','redteam-43']:
            stream=events(client.get('/live/CVE-2026-1000',params={'fixture':fixture}))
            run=next(d['run'] for n,d in stream if n=='briefing')
            assert run['fixture']==fixture and stream[0][1]['fixture']==fixture
            assert run['briefing']['verdict']==clean['briefing']['verdict']
            assert not run['policy']['write_allowed']
            assert run['injection']['write_probe']['allowed'] is False
        assert client.get('/live/CVE-2026-1000',params={'fixture':'../../secret'}).status_code==422
        assert not live_corpus.tickets.exists()
