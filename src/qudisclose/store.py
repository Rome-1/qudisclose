"""Persistence for reports, events, agent artifacts, postmortems and the hunter's coverage map.

Backend-agnostic (see db.py): Postgres in production, SQLite for tests and the offline demo.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from qudisclose.db import SERIAL, Backend, connect
from qudisclose.models import Event, Report, Status

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        external_id TEXT,
        content_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        received_at TEXT NOT NULL,
        paused INTEGER NOT NULL DEFAULT 0,
        body TEXT NOT NULL
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS reports_hash ON reports(content_hash)",
    "CREATE UNIQUE INDEX IF NOT EXISTS reports_external ON reports(source, external_id) WHERE external_id IS NOT NULL",
    """CREATE TABLE IF NOT EXISTS events (
        seq %SERIAL%,
        id TEXT NOT NULL UNIQUE,
        report_id TEXT NOT NULL,
        at TEXT NOT NULL,
        kind TEXT NOT NULL,
        actor TEXT NOT NULL,
        data TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS events_report ON events(report_id, seq)",
    """CREATE TABLE IF NOT EXISTS artifacts (
        report_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        at TEXT NOT NULL,
        body TEXT NOT NULL,
        PRIMARY KEY (report_id, kind)
    )""",
    """CREATE TABLE IF NOT EXISTS hunt_coverage (
        repo TEXT NOT NULL,
        path TEXT NOT NULL,
        last_seen TEXT,
        visits INTEGER NOT NULL DEFAULT 0,
        findings INTEGER NOT NULL DEFAULT 0,
        last_outcome TEXT,
        PRIMARY KEY (repo, path)
    )""",
]
# The events `seq` column is the auto-increment primary key (SERIAL expands per backend); it is
# never written explicitly and orders a report's events stably by insertion order. `id` stays unique.


class Store:
    def __init__(self, dsn: str = ":memory:", backend: Backend | None = None) -> None:
        self.db = backend or connect(dsn)
        self.db.ddl(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # -- reports

    def insert_report(self, r: Report) -> bool:
        """Insert; return False on a duplicate (same content hash or same source/external id)."""
        try:
            self.db.execute(
                "INSERT INTO reports (id, source, external_id, content_hash, status, received_at, paused, body) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (r.id, r.source, r.external_id, r.content_hash, r.status, r.received_at.isoformat(), 0, r.model_dump_json()),
            )
            return True
        except Exception as exc:  # unique-violation on either index
            if _is_unique_violation(exc):
                return False
            raise

    def find_duplicate(self, r: Report) -> Report | None:
        row = self.db.query_one(
            "SELECT body, paused FROM reports WHERE content_hash = ? OR (source = ? AND external_id IS NOT NULL AND external_id = ?)",
            (r.content_hash, r.source, r.external_id),
        )
        return self._load(row[0], row[1]) if row else None

    def save_report(self, r: Report) -> None:
        """Persists everything except `paused`, which has its own column (set_paused) so an in-flight
        pipeline thread can never overwrite a human pause with a stale object."""
        self.db.execute("UPDATE reports SET status = ?, body = ? WHERE id = ?", (r.status, r.model_dump_json(), r.id))

    def set_paused(self, report_id: str, paused: bool) -> None:
        self.db.execute("UPDATE reports SET paused = ? WHERE id = ?", (1 if paused else 0, report_id))

    def is_paused(self, report_id: str) -> bool:
        row = self.db.query_one("SELECT paused FROM reports WHERE id = ?", (report_id,))
        return bool(row and row[0])

    @staticmethod
    def _load(body: str, paused: Any) -> Report:
        r = Report.model_validate_json(body)
        r.paused = bool(paused)
        return r

    def get_report(self, report_id: str) -> Report | None:
        row = self.db.query_one("SELECT body, paused FROM reports WHERE id = ?", (report_id,))
        return self._load(row[0], row[1]) if row else None

    def list_reports(self, status: Status | None = None, limit: int = 100) -> list[Report]:
        if status:
            rows = self.db.query("SELECT body, paused FROM reports WHERE status = ? ORDER BY received_at DESC LIMIT ?", (status, limit))
        else:
            rows = self.db.query("SELECT body, paused FROM reports ORDER BY received_at DESC LIMIT ?", (limit,))
        return [self._load(r[0], r[1]) for r in rows]

    # -- events

    def add_event(self, report_id: str, kind: str, actor: str, **data: Any) -> Event:
        e = Event(report_id=report_id, kind=kind, actor=actor, data=data)
        self.db.execute(
            "INSERT INTO events (id, report_id, at, kind, actor, data) VALUES (?,?,?,?,?,?)",
            (e.id, e.report_id, e.at.isoformat(), e.kind, e.actor, json.dumps(e.data, default=str)),
        )
        return e

    def events(self, report_id: str) -> list[Event]:
        rows = self.db.query(
            "SELECT id, report_id, at, kind, actor, data FROM events WHERE report_id = ? ORDER BY seq", (report_id,)
        )
        return [Event(id=r[0], report_id=r[1], at=datetime.fromisoformat(r[2]), kind=r[3], actor=r[4], data=json.loads(r[5])) for r in rows]

    # -- artifacts

    def put_artifact(self, report_id: str, kind: str, body: Any) -> None:
        payload = body.model_dump_json() if hasattr(body, "model_dump_json") else json.dumps(body, default=str)
        self.db.execute(
            "INSERT INTO artifacts (report_id, kind, at, body) VALUES (?,?,?,?) "
            "ON CONFLICT (report_id, kind) DO UPDATE SET at = excluded.at, body = excluded.body",
            (report_id, kind, datetime.now().isoformat(), payload),
        )

    def get_artifact(self, report_id: str, kind: str) -> dict[str, Any] | None:
        row = self.db.query_one("SELECT body FROM artifacts WHERE report_id = ? AND kind = ?", (report_id, kind))
        return json.loads(row[0]) if row else None

    def artifacts(self, report_id: str) -> dict[str, Any]:
        rows = self.db.query("SELECT kind, body FROM artifacts WHERE report_id = ?", (report_id,))
        return {k: json.loads(b) for k, b in rows}

    # -- hunter coverage map

    def record_visit(self, repo: str, path: str, *, found: bool, outcome: str) -> None:
        self.db.execute(
            "INSERT INTO hunt_coverage (repo, path, last_seen, visits, findings, last_outcome) VALUES (?,?,?,1,?,?) "
            "ON CONFLICT (repo, path) DO UPDATE SET last_seen = excluded.last_seen, "
            "visits = hunt_coverage.visits + 1, findings = hunt_coverage.findings + excluded.findings, "
            "last_outcome = excluded.last_outcome",
            (repo, path, datetime.now().isoformat(), 1 if found else 0, outcome),
        )

    def coverage(self, repo: str) -> dict[str, dict[str, Any]]:
        rows = self.db.query(
            "SELECT path, last_seen, visits, findings, last_outcome FROM hunt_coverage WHERE repo = ?", (repo,)
        )
        return {r[0]: {"last_seen": r[1], "visits": r[2], "findings": r[3], "last_outcome": r[4]} for r in rows}


def _is_unique_violation(exc: Exception) -> bool:
    import sqlite3

    if isinstance(exc, sqlite3.IntegrityError):
        return True
    return exc.__class__.__name__ in ("UniqueViolation", "IntegrityError")
