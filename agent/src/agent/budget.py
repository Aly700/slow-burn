"""Durable, atomic token reservations; uncertain calls retain their full charge."""
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import uuid

DAILY_MESSAGE = 'Daily limit reached, showing recorded answers.'


class DailyLimit(RuntimeError):
    def __init__(self):
        super().__init__(DAILY_MESSAGE)


class TokenBudget:
    def __init__(self, path, limit, day=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.limit = max(0, int(limit))
        self.day = day or (lambda: datetime.now(timezone.utc).date().isoformat())
        with self.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS budget(day TEXT PRIMARY KEY, used INTEGER NOT NULL, blocked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY, day TEXT NOT NULL, amount INTEGER NOT NULL);
            ''')

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def status(self):
        with self.db() as db:
            row = db.execute('SELECT used,blocked FROM budget WHERE day=?', (self.day(),)).fetchone() or (0, 0)
        return {'day': self.day(), 'limit_tokens': self.limit, 'used_tokens': row[0],
                'remaining_tokens': max(0, self.limit-row[0]), 'exhausted': bool(row[1]) or row[0] >= self.limit}

    def reserve(self, amount):
        if amount < 0:
            raise ValueError('invalid token reservation')
        day, rid = self.day(), uuid.uuid4().hex
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR IGNORE INTO budget(day,used) VALUES (?,0)', (day,))
            used, blocked = db.execute('SELECT used,blocked FROM budget WHERE day=?', (day,)).fetchone()
            denied = blocked or used + amount > self.limit
            if denied:
                db.execute('UPDATE budget SET blocked=1 WHERE day=?', (day,))
            else:
                db.execute('UPDATE budget SET used=used+? WHERE day=?', (amount, day))
                db.execute('INSERT INTO reservations VALUES (?,?,?)', (rid, day, amount))
        if denied:
            raise DailyLimit()
        return rid

    def settle(self, rid, actual):
        if actual < 0:
            raise ValueError('invalid token usage')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT day,amount FROM reservations WHERE id=?', (rid,)).fetchone()
            if row is None:
                return
            day, reserved = row
            db.execute('UPDATE budget SET used=used+?, blocked=MAX(blocked,?) WHERE day=?',
                       (actual-reserved, int(actual > reserved), day))
            db.execute('DELETE FROM reservations WHERE id=?', (rid,))

