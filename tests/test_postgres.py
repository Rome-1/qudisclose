"""Postgres parity: the full pipeline, audit chain and coverage map run identically on Postgres.

Skipped unless a local Postgres is reachable (CI sets QUDISCLOSE_TEST_PG, or a default local socket
works). Uses a throwaway database that is dropped afterwards.
"""

from __future__ import annotations

import os

import pytest

from qudisclose.db import connect, ensure_database
from qudisclose.security import AuditLog, Identity
from qudisclose.store import Store
from tests.conftest import new_report

ADMIN = os.environ.get("QUDISCLOSE_TEST_PG", "postgresql:///postgres")
TEST_DB = "qudisclose_partest"
TEST_DSN = ADMIN.rsplit("/", 1)[0] + "/" + TEST_DB


def _pg_available() -> bool:
    try:
        import psycopg

        with psycopg.connect(ADMIN, connect_timeout=2):
            return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _pg_available(), reason="no local Postgres reachable")


@pytest.fixture
def pg_store():
    import psycopg

    ensure_database(TEST_DSN)
    with psycopg.connect(TEST_DSN, autocommit=True) as c:
        for t in ("audit", "events", "artifacts", "reports", "hunt_coverage", "vsla_ledger", "vsla_ledger_seen"):
            c.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
    store = Store(TEST_DSN)
    yield store
    store.close()


def test_pipeline_on_postgres(pg_store, tmp_path, repo):
    from qudisclose.config import Config, RepoConfig
    from qudisclose.demo import demo_provider
    from qudisclose.orchestrator import Orchestrator
    from qudisclose.publisher import LocalPublisher

    cfg = Config(db_dsn=TEST_DSN, out_dir=str(tmp_path / "out"), provider="scripted",
                 repos={"example/vulnpkg": RepoConfig(path=str(repo), test_command="python -m pytest -q")})
    cfg.vsla.allow_ephemeral_platform_key = True   # test: no keys/ directory (a real deployment refuses an ephemeral platform key)
    audit = AuditLog(pg_store.db, Identity.generate("audit"))
    orch = Orchestrator(store=pg_store, audit=audit, config=cfg, provider=demo_provider(), publisher=LocalPublisher(cfg.out_dir))
    rep, is_new = orch.intake(new_report(), actor="agent:researcher-1")
    assert is_new
    r = orch.run_case(rep.id)
    assert r.status == "closed", [e.kind for e in pg_store.events(rep.id)]
    assert set(pg_store.artifacts(rep.id)) >= {"triage", "patch", "review", "release_plan", "postmortem"}
    ok, msg = audit.verify_chain()
    assert ok, msg
    # duplicate detection and the coverage upsert both exercise Postgres-specific SQL paths
    _, again = orch.intake(new_report(), actor="x")
    assert not again
    pg_store.record_visit("example/vulnpkg", "vulnpkg/files.py", found=True, outcome="escalated")
    pg_store.record_visit("example/vulnpkg", "vulnpkg/files.py", found=False, outcome="revisit")
    cov = pg_store.coverage("example/vulnpkg")
    assert cov["vulnpkg/files.py"]["visits"] == 2 and cov["vulnpkg/files.py"]["findings"] == 1
