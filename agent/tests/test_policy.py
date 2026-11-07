import copy
from concurrent.futures import ThreadPoolExecutor

import pytest


def briefing():
    return {"verdict": "watch", "headline": "Review CVE-2025-1000", "claims": [{"id": "c1", "text": "EPSS is 0.1.", "evidence": [{"tool": "get_cve", "field": "signals.epss", "value": 0.1}], "verified": True}], "action": "Check installed versions.", "confidence": 0.5}


def ready(tmp_path):
    from agent.store import Store
    s = Store(tmp_path / "state.sqlite", tmp_path / "tickets.jsonl")
    r = s.create("CVE-2025-1000", "test")
    s.transition(r["run_id"], "INVESTIGATING")
    s.propose(r["run_id"], briefing())
    return s, r["run_id"]


def test_no_token_cannot_write(tmp_path):
    s, rid = ready(tmp_path)
    r = s.get(rid)
    with pytest.raises(PermissionError):
        s.file_ticket(r["cve_id"], r["briefing_hash"], "invented")
    assert not (tmp_path / "tickets.jsonl").exists()


def test_approval_is_bound_to_cve_hash_and_immutable_action(tmp_path):
    s, rid = ready(tmp_path)
    r = s.get(rid)
    token = s.approve(rid, True)
    for cve, digest in [("CVE-2025-9999", r["briefing_hash"]), (r["cve_id"], "wrong")]:
        with pytest.raises(PermissionError):
            s.file_ticket(cve, digest, token)
    changed = copy.deepcopy(r["briefing"])
    changed["action"] = "Changed after approval"
    with pytest.raises(ValueError):
        s.propose(rid, changed)
    assert s.file_ticket(r["cve_id"], r["briefing_hash"], token)["ticket_id"]
    assert s.get(rid)["state"] == "TICKET_FILED"


def test_replay_concurrent_writes_append_only_once(tmp_path):
    s, rid = ready(tmp_path)
    r = s.get(rid)
    token = s.approve(rid, True)
    def write(_):
        return s.file_ticket(r["cve_id"], r["briefing_hash"], token)
    with ThreadPoolExecutor(max_workers=6) as ex:
        tickets = list(ex.map(write, range(12)))
    assert len({t["ticket_id"] for t in tickets}) == 1
    assert len((tmp_path / "tickets.jsonl").read_text().splitlines()) == 1


def test_reject_is_terminal_and_revokes_authority(tmp_path):
    s, rid = ready(tmp_path)
    r = s.get(rid)
    token = s.approve(rid, True)
    s.approve(rid, False)
    assert s.get(rid)["state"] == "REJECTED"
    with pytest.raises((PermissionError, ValueError)):
        s.approve(rid, True)
    with pytest.raises(PermissionError):
        s.file_ticket(r["cve_id"], r["briefing_hash"], token)


def test_expired_approval_fails(tmp_path):
    s, rid = ready(tmp_path)
    r = s.get(rid)
    token = s.approve(rid, True, ttl=-1)
    with pytest.raises(PermissionError):
        s.file_ticket(r["cve_id"], r["briefing_hash"], token)


def test_no_unverified_or_empty_proposal(tmp_path):
    from agent.store import Store
    s = Store(tmp_path / "state.sqlite", tmp_path / "tickets.jsonl")
    r = s.create("CVE-2025-1000", "test")
    s.transition(r["run_id"], "INVESTIGATING")
    b = briefing()
    b["claims"] = []
    with pytest.raises(ValueError):
        s.propose(r["run_id"], b)
    with pytest.raises(ValueError):
        s.transition(r["run_id"], "TICKET_FILED")


def test_decision_cannot_race_a_committed_ticket_intent(tmp_path, monkeypatch):
    s, rid = ready(tmp_path)
    r = s.get(rid)
    token = s.approve(rid, True)
    original = s.flush_tickets
    def interrupted():
        raise OSError('simulated crash before file append')
    monkeypatch.setattr(s, 'flush_tickets', interrupted)
    with pytest.raises(OSError):
        s.file_ticket(r['cve_id'], r['briefing_hash'], token)
    with pytest.raises(ValueError):
        s.approve(rid, False)
    monkeypatch.setattr(s, 'flush_tickets', original)
    s.recover()
    assert s.get(rid)['state'] == 'TICKET_FILED'
    assert len((tmp_path / 'tickets.jsonl').read_text().splitlines()) == 1


def test_recovery_records_delivery_after_append_before_final_state(tmp_path, monkeypatch):
    s, rid = ready(tmp_path)
    r = s.get(rid)
    token = s.approve(rid, True)
    original = s.flush_tickets
    def crash_after_append():
        original()
        raise OSError('simulated stop after durable append')
    monkeypatch.setattr(s, 'flush_tickets', crash_after_append)
    with pytest.raises(OSError):
        s.file_ticket(r['cve_id'], r['briefing_hash'], token)
    monkeypatch.setattr(s, 'flush_tickets', original)
    s.recover()
    s.recover()
    run = s.get(rid)
    assert run['state'] == 'TICKET_FILED'
    deliveries = [c for c in run['tool_results'] if c['tool'] == 'file_fix_ticket' and c['output'].get('allowed')]
    assert len(deliveries) == 1
    assert any(t.get('purpose') == 'recovered approved ticket delivery' for t in run['trace'])
    assert len((tmp_path / 'tickets.jsonl').read_text().splitlines()) == 1
