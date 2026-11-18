import shutil
import subprocess
from pathlib import Path

import pytest

from qudisclose.config import Config, RepoConfig
from qudisclose.demo import FIXTURE, demo_provider, demo_reporter, demo_submission
from qudisclose.models import Report, Source
from qudisclose.orchestrator import Orchestrator
from qudisclose.publisher import LocalPublisher
from qudisclose.security import AuditLog, Identity
from qudisclose.store import Store


@pytest.fixture
def repo(tmp_path) -> Path:
    """A git checkout of the fixture: sandboxes are worktrees of it, so the subject revision (VSLA-F-2) is the fixture's
    commit and a second sandbox can check it out again (VSLA-P-4 re-execution at the subject revision)."""
    dst = tmp_path / "vulnpkg"
    shutil.copytree(FIXTURE, dst)
    git = ["git", "-c", "user.name=qudisclose", "-c", "user.email=qudisclose@localhost", "-C", str(dst)]
    subprocess.run([*git, "init", "-q"], check=True, capture_output=True)
    subprocess.run([*git, "add", "-A"], check=True, capture_output=True)
    subprocess.run([*git, "commit", "-q", "-m", "fixture", "--no-gpg-sign"], check=True, capture_output=True)
    return dst


@pytest.fixture
def env(tmp_path, repo):
    cfg = Config(db_dsn=":memory:", out_dir=str(tmp_path / "out"), provider="scripted",
                 repos={"example/vulnpkg": RepoConfig(path=str(repo), test_command="python -m pytest -q")})
    cfg.vsla.allow_ephemeral_platform_key = True   # tests: no keys/ directory
    store = Store(":memory:")
    audit = AuditLog(store.db, Identity.generate("audit"))
    provider = demo_provider()
    orch = Orchestrator(store=store, audit=audit, config=cfg, provider=provider, publisher=LocalPublisher(cfg.out_dir))
    return cfg, store, audit, provider, orch


def new_report() -> Report:
    return Report.from_submission(demo_submission(), source=Source.MCP, reporter=demo_reporter())
