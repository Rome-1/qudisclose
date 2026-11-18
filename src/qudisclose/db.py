"""Database backend: one small interface over SQLite (tests, offline demo) and PostgreSQL (production).

Production uses Postgres. SQLite stays only for the zero-infrastructure paths: the unit tests and
`qudisclose demo`. Both share the same SQL (written with `?` placeholders, `RETURNING`, and
`ON CONFLICT ... DO UPDATE`, all supported by SQLite >= 3.35 and Postgres); the only dialect
differences are the placeholder character and the auto-increment column type, handled here.

A DSN selects the backend:
    sqlite://:memory:            in-memory (tests)
    sqlite:///path/to/file.db    file
    postgresql://user:pw@host/db (or postgres://...)   Postgres

One connection is shared by the MCP event loop and the pipeline threads and serialized by a lock, so
the audit log can hold the lock across its read-prev-hash-then-insert and never fork the chain. That
is enough for a maintainer-scale deployment; swap in a pool here if you outgrow a single connection.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SERIAL = "%SERIAL%"  # placeholder in DDL for the backend's auto-increment primary-key type


class _Cursor:
    """Thin wrapper translating `?` placeholders to the backend's style."""

    def __init__(self, cur: Any, backend: Backend) -> None:
        self._cur = cur
        self._b = backend

    def execute(self, sql: str, params: Sequence[Any] = ()) -> _Cursor:
        self._cur.execute(self._b._q(sql), tuple(params))
        return self

    def fetchone(self) -> Any:
        return self._cur.fetchone()

    def fetchall(self) -> list[Any]:
        return self._cur.fetchall()


class Backend:
    placeholder = "?"
    serial_ddl = "INTEGER PRIMARY KEY AUTOINCREMENT"

    def __init__(self, conn: Any) -> None:
        self.conn = conn
        self.lock = threading.RLock()

    # -- dialect

    def _q(self, sql: str) -> str:
        return sql if self.placeholder == "?" else sql.replace("?", self.placeholder)

    def ddl(self, statements: Sequence[str]) -> None:
        with self.lock:
            cur = self.conn.cursor()
            for s in statements:
                cur.execute(s.replace(SERIAL, self.serial_ddl))
            self.conn.commit()

    # -- transactions (the lock is held for the whole block; commit on clean exit)

    @contextmanager
    def tx(self) -> Iterator[_Cursor]:
        with self.lock:
            cur = self.conn.cursor()
            try:
                yield _Cursor(cur, self)
                self.conn.commit()
            except BaseException:
                self.conn.rollback()
                raise
            finally:
                cur.close()

    # -- convenience helpers (each is its own transaction)

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        with self.tx() as cur:
            cur.execute(sql, params)

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[Any]:
        with self.tx() as cur:
            return cur.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Any:
        with self.tx() as cur:
            return cur.execute(sql, params).fetchone()

    def close(self) -> None:
        with self.lock:
            self.conn.close()


class SqliteBackend(Backend):
    placeholder = "?"
    serial_ddl = "INTEGER PRIMARY KEY AUTOINCREMENT"

    def __init__(self, path: str) -> None:
        import sqlite3

        conn = sqlite3.connect(path, check_same_thread=False)
        if path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
        super().__init__(conn)


class PostgresBackend(Backend):
    placeholder = "%s"
    serial_ddl = "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY"

    def __init__(self, dsn: str) -> None:
        import psycopg

        super().__init__(psycopg.connect(dsn))


def connect(dsn: str) -> Backend:
    if dsn in (":memory:", "sqlite://:memory:", "sqlite://"):
        return SqliteBackend(":memory:")
    if dsn.startswith("sqlite:///"):
        return SqliteBackend(dsn[len("sqlite:///"):])
    if dsn.startswith("sqlite://"):
        return SqliteBackend(dsn[len("sqlite://"):])
    if dsn.startswith(("postgresql://", "postgres://")):
        return PostgresBackend(dsn)
    # bare path -> sqlite file (back-compat with the old db_path config)
    return SqliteBackend(dsn)


def ensure_database(dsn: str) -> None:
    """Create the Postgres database named in the DSN if it does not exist. No-op for SQLite."""
    if not dsn.startswith(("postgresql://", "postgres://")):
        return
    import psycopg
    from psycopg import sql as pgsql

    # Split the target database off the DSN and connect to the maintenance db instead.
    head, _, dbname = dsn.rpartition("/")
    dbname = dbname.split("?")[0]
    if not dbname:
        return
    admin = f"{head}/postgres"
    try:
        with psycopg.connect(admin, autocommit=True) as c:
            exists = c.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,)).fetchone()
            if not exists:
                c.execute(pgsql.SQL("CREATE DATABASE {}").format(pgsql.Identifier(dbname)))
    except Exception:
        # If we cannot reach the maintenance db (permissions, managed PG), assume the target already
        # exists or will be created out of band; the first real connection will surface a clear error.
        pass
