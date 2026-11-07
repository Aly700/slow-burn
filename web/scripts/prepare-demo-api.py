"""Import recorded proposals into an isolated local demo store without resetting decisions."""
import json
from pathlib import Path

from agent.evidence import canonical
from agent.store import Store, digest

web = Path(__file__).resolve().parents[1]
store = Store(web / ".runtime/triage.sqlite", web / ".runtime/tickets.jsonl")
added = 0
for path in sorted((web.parent / "artifacts/agent_runs").glob("CVE-*.json")):
    run = json.loads(path.read_text())
    if run.get("state") != "WAITING_APPROVAL":
        continue
    briefing = run.get("briefing") or {}
    if not briefing.get("claims") or not all(claim.get("verified") is True for claim in briefing["claims"]):
        raise ValueError(f"Unverified proposal: {path.name}")
    if run.get("briefing_hash") != digest(briefing):
        raise ValueError(f"Briefing hash mismatch: {path.name}")
    with store.db() as db:
        added += db.execute("INSERT OR IGNORE INTO runs(id, body) VALUES (?, ?)", (run["run_id"], canonical(run))).rowcount
print(f"Imported {added} recorded proposals. Existing decisions retained.")
print(f"State: {store.path}")
print(f"Tickets: {store.tickets}")
