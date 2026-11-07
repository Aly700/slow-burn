from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
import uuid

from .evidence import canonical

TRANSITIONS = {
    "RECEIVED": {"INVESTIGATING", "FAILED"},
    "INVESTIGATING": {"VERIFIED", "FAILED"},
    "VERIFIED": {"WAITING_APPROVAL", "FAILED"},
    "WAITING_APPROVAL": {"REJECTED", "TICKET_FILED", "FAILED"},
    "REJECTED": set(), "TICKET_FILED": set(), "FAILED": set(),
}


def digest(briefing):
    return hashlib.sha256(canonical(briefing).encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: Path, tickets: Path):
        self.path, self.tickets = Path(path), Path(tickets)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.tickets.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS approvals(token_hash TEXT PRIMARY KEY, run_id TEXT NOT NULL,
                    cve_id TEXT NOT NULL, briefing_hash TEXT NOT NULL, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS tickets(idempotency_key TEXT PRIMARY KEY, body TEXT NOT NULL);
            """)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            with db:
                yield db
        finally:
            db.close()

    def _get(self, db, run_id):
        row = db.execute("SELECT body FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(run_id)
        return json.loads(row[0])

    def _put(self, db, run):
        db.execute("INSERT OR REPLACE INTO runs VALUES (?,?)", (run["run_id"], canonical(run)))

    def create(self, cve_id, model):
        run = {"run_id": "run_" + uuid.uuid4().hex, "cve_id": cve_id, "state": "RECEIVED",
               "states_seen": ["RECEIVED"], "model": model, "started_at": now(), "duration_ms": 0,
               "briefing": None, "verifier": {"claims_total": 0, "claims_verified": 0, "dropped": []},
               "policy": {"write_requested": False, "write_allowed": False, "reason": "no human approval for this briefing hash"},
               "injection": {"detected": False, "spans": []}, "trace": [], "tool_results": []}
        with self.db() as db:
            self._put(db, run)
        return run

    def get(self, run_id):
        with self.db() as db:
            return self._get(db, run_id)

    @staticmethod
    def _transition(run, state):
        if state not in TRANSITIONS[run["state"]]:
            raise ValueError(f"invalid transition {run['state']} -> {state}")
        run["state"] = state
        run["states_seen"].append(state)

    def transition(self, run_id, state):
        if state in {"VERIFIED", "WAITING_APPROVAL", "TICKET_FILED", "REJECTED"}:
            raise ValueError("transition requires verification, approval or ticket operation")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            run = self._get(db, run_id)
            self._transition(run, state)
            self._put(db, run)

    def update(self, run_id, **fields):
        allowed = {"duration_ms", "verifier", "policy", "injection", "trace", "tool_results", "error", "metrics", "fixture", "score_file_sha256", "snapshot_month"}
        if set(fields) - allowed:
            raise ValueError("immutable run field")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            run = self._get(db, run_id)
            run.update(fields)
            self._put(db, run)

    def propose(self, run_id, briefing):
        if not briefing.get("claims") or not all(c.get("verified") is True for c in briefing["claims"]):
            raise ValueError("a proposal requires verified evidence")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            run = self._get(db, run_id)
            if run["state"] != "INVESTIGATING" or run["briefing"] is not None:
                raise ValueError("proposal is immutable")
            self._transition(run, "VERIFIED")
            run["briefing"], run["briefing_hash"] = briefing, digest(briefing)
            self._transition(run, "WAITING_APPROVAL")
            self._put(db, run)
        return run["briefing_hash"]

    def approve(self, run_id, approve: bool, ttl=900):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            run = self._get(db, run_id)
            if run["state"] != "WAITING_APPROVAL":
                raise ValueError("only a waiting run can receive a decision")
            if digest(run["briefing"]) != run["briefing_hash"]:
                raise PermissionError("briefing changed since verification")
            if not approve and run.get("ticket_intent"):
                raise ValueError("the approved ticket is already committed to the delivery outbox")
            db.execute("UPDATE approvals SET revoked=1 WHERE run_id=?", (run_id,))
            run["approval"] = {"approved": approve, "at": now(), "briefing_hash": run["briefing_hash"]}
            token = None
            if not approve:
                self._transition(run, "REJECTED")
                run["policy"] = {"write_requested": True, "write_allowed": False, "reason": "human rejected the proposed action"}
            else:
                token = secrets.token_urlsafe(32)
                db.execute("INSERT INTO approvals VALUES (?,?,?,?,?,0)",
                           (hashlib.sha256(token.encode()).hexdigest(), run_id, run["cve_id"], run["briefing_hash"], time.time() + min(ttl, 900)))
            run["trace"].append({"t_ms": run["duration_ms"], "kind": "policy", "name": "human_approval",
                                 "input": {"approve": approve, "briefing_hash": run["briefing_hash"]},
                                 "output_summary": "approved" if approve else "rejected", "duration_ms": 0})
            self._put(db, run)
            return token

    def file_ticket(self, cve_id, briefing_hash, approval_token):
        operation_started = time.monotonic()
        token_hash = hashlib.sha256(approval_token.encode()).hexdigest()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            approval = db.execute("SELECT run_id,cve_id,briefing_hash,expires,revoked FROM approvals WHERE token_hash=?", (token_hash,)).fetchone()
            if not approval or approval[1:3] != (cve_id, briefing_hash) or approval[3] < time.time() or approval[4]:
                raise PermissionError("no valid human approval for this CVE and exact briefing hash")
            run = self._get(db, approval[0])
            if run["state"] not in {"WAITING_APPROVAL", "TICKET_FILED"} or digest(run["briefing"]) != briefing_hash:
                raise PermissionError("proposal is no longer eligible")
            key = cve_id + ":" + briefing_hash
            existing = db.execute("SELECT body FROM tickets WHERE idempotency_key=?", (key,)).fetchone()
            ticket = json.loads(existing[0]) if existing else {
                "ticket_id": "fix_" + hashlib.sha256(key.encode()).hexdigest()[:20], "idempotency_key": key,
                "cve_id": cve_id, "briefing_hash": briefing_hash, "run_id": run["run_id"],
                "created_at": now(), "briefing": run["briefing"], "destination": "local tickets.jsonl"}
            db.execute("INSERT OR IGNORE INTO tickets VALUES (?,?)", (key, canonical(ticket)))
            run["ticket_intent"] = key
            self._put(db, run)
        self.flush_tickets()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            run = self._get(db, approval[0])
            self._finalize_ticket(run, ticket, round((time.monotonic()-operation_started)*1000))
            self._put(db, run)
        return ticket

    def _finalize_ticket(self, run, ticket, duration_ms=0, recovered=False):
        if run["state"] == "WAITING_APPROVAL":
            self._transition(run, "TICKET_FILED")
        run["ticket"] = {k: ticket[k] for k in ("ticket_id", "idempotency_key", "destination")}
        run["policy"] = {"write_requested": True, "write_allowed": True,
                         "reason": "recovered approved ticket from durable outbox" if recovered else "human approved this immutable briefing"}
        call_id = f"t{len(run['tool_results'])+1}"
        output = {"allowed": True, **run["ticket"]}
        inputs = {"cve_id": run["cve_id"], "briefing_hash": run["briefing_hash"]}
        run["tool_results"].append({"call_id": call_id, "tool": "file_fix_ticket", "input": inputs, "output": output})
        run["trace"].append({"t_ms": round((datetime.now(timezone.utc)-datetime.fromisoformat(run["started_at"])).total_seconds()*1000),
                             "kind": "tool", "name": "file_fix_ticket", "input": {**inputs, "approval_token": "[redacted]"},
                             "call_id": call_id, "output_summary": canonical(output), "duration_ms": duration_ms,
                             "purpose": "recovered approved ticket delivery" if recovered else "human-approved ticket delivery"})

    def flush_tickets(self):
        # Transactional outbox plus a file lock closes the append/retry crash window.
        lock_dir = self.tickets.parent / "cache"
        lock_dir.mkdir(parents=True, exist_ok=True)
        with (lock_dir / (self.tickets.stem + ".lock")).open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.db() as db:
                rows = db.execute("SELECT body FROM tickets ORDER BY rowid").fetchall()
            if not rows:
                return
            with self.tickets.open("a+b") as f:
                f.seek(0)
                raw = f.read()
                if raw and not raw.endswith(b"\n"):
                    valid_end = raw.rfind(b"\n") + 1
                    f.truncate(valid_end)
                    raw = raw[:valid_end]
                seen = {json.loads(line)["idempotency_key"] for line in raw.splitlines() if line}
                f.seek(0, os.SEEK_END)
                for (body,) in rows:
                    key = json.loads(body)["idempotency_key"]
                    if key not in seen:
                        f.write(body.encode() + b"\n")
                        seen.add(key)
                f.flush()
                os.fsync(f.fileno())

    def recover(self):
        self.flush_tickets()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            for (body,) in db.execute("SELECT body FROM runs").fetchall():
                run = json.loads(body)
                if run["state"] in {"RECEIVED", "INVESTIGATING", "VERIFIED"}:
                    self._transition(run, "FAILED")
                    run["error"] = {"code": "worker_restart", "message": "Investigation interrupted; start a new run."}
                    self._put(db, run)
                elif run["state"] == "WAITING_APPROVAL":
                    key = run["cve_id"] + ":" + run["briefing_hash"]
                    ticket = db.execute("SELECT body FROM tickets WHERE idempotency_key=?", (key,)).fetchone()
                    if ticket and run.get("ticket_intent") and run.get("approval", {}).get("approved"):
                        self._finalize_ticket(run, json.loads(ticket[0]), recovered=True)
                        self._put(db, run)
