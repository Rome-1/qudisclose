"""The hunter finds a reproducible bug, escalates it, and the normal pipeline patches it — all offline."""

from __future__ import annotations

from pathlib import Path

from qudisclose.demo import demo_provider_with_hunter
from qudisclose.hunter import Hunter, LocalEscalator, TargetSelector, candidate_files
from qudisclose.models import Status


class _FixedSelector:
    def __init__(self, path: str) -> None:
        self.path = path

    def pick(self) -> str:
        return self.path


def _hunter(env, repo, target="vulnpkg/files.py", provider=None):
    cfg, store, audit, _prov, orch = env
    h = Hunter(provider=provider or demo_provider_with_hunter(), store=store, repo_slug="example/vulnpkg",
               repo_path=Path(repo), escalator=LocalEscalator(orch), authorized_targets=["example/vulnpkg"])
    h.selector = _FixedSelector(target)
    return h, orch, store


def test_hunter_escalates_and_pipeline_patches(env, repo):
    h, orch, store = _hunter(env, repo)
    outcome = h.cycle()
    assert outcome.escalated and outcome.report_id, outcome
    # the escalated finding is a normal case; the (scripted) pipeline closes it
    orch.wait_all()
    r = store.get_report(outcome.report_id)
    assert r.status == Status.CLOSED, [e.kind for e in store.events(r.id)]
    assert r.submission.cwe == "CWE-22" and r.reporter.identity == "agent:hunter"
    # coverage recorded a finding on that file
    cov = store.coverage("example/vulnpkg")
    assert cov["vulnpkg/files.py"]["findings"] == 1


def test_hunter_skips_file_with_no_hypotheses(env, repo):
    h, orch, store = _hunter(env, repo, target="vulnpkg/__init__.py")
    outcome = h.cycle()
    assert not outcome.escalated and outcome.reason == "no hypotheses"
    assert store.coverage("example/vulnpkg")["vulnpkg/__init__.py"]["visits"] == 1


def test_hunter_does_not_escalate_unprovable_hypothesis(env, repo):
    provider = demo_provider_with_hunter()
    # the model claims a bug but the reproduction test does not actually fail on the current tree
    provider.scripts["hunt_reproduce"] = lambda u, t: dict(
        test_path="tests/test_x.py", test_source="def test_x():\n    assert True\n",
        fails_on_vulnerable=False, command="python -m pytest -q tests/test_x.py", output_excerpt="")
    h, orch, store = _hunter(env, repo, provider=provider)
    outcome = h.cycle()
    assert not outcome.escalated and outcome.reason == "hypothesis not reproducible"
    assert store.list_reports() == []


def test_hunter_loop_stops_at_max_findings(env, repo):
    h, orch, store = _hunter(env, repo)
    outcomes = h.run(iterations=3, interval=0, max_findings=1)
    # first cycle escalates (dedup makes later ones non-new, but the loop stops at the first finding)
    assert outcomes[0].escalated and len([o for o in outcomes if o.escalated]) == 1
    orch.wait_all()


def test_target_selector_prefers_entry_points_over_inert_files(env, repo):
    cfg, store, audit, prov, orch = env
    sel = TargetSelector(store, "example/vulnpkg", Path(repo))
    files = candidate_files(Path(repo))
    assert "vulnpkg/files.py" in files
    cov = store.coverage("example/vulnpkg")
    churn_max = 1
    assert sel.score("vulnpkg/files.py", cov, churn_max) > sel.score("vulnpkg/__init__.py", cov, churn_max)
    # fatigue: a file visited repeatedly without findings loses ground
    before = sel.score("vulnpkg/files.py", cov, churn_max)
    for _ in range(5):
        store.record_visit("example/vulnpkg", "vulnpkg/files.py", found=False, outcome="revisit")
    after = sel.score("vulnpkg/files.py", store.coverage("example/vulnpkg"), churn_max)
    assert after < before


def test_hunter_rejects_broken_test_that_fails_for_wrong_reason(env, repo):
    """A test that fails with NameError/ImportError (exit 1) is broken, not a reproduction. The code-side
    check must reject it even though the model claims fails_on_vulnerable=True."""
    provider = demo_provider_with_hunter()
    broken = ("def test_traversal():\n"
              "    undefined_symbol(1, 2)  # NameError at runtime -> exit 1 but not a security failure\n")
    provider.scripts["hunt_reproduce"] = lambda u, t: (
        t["write_file"]("tests/test_broken_repro.py", broken),
        t["run_command"]("python -m pytest -q tests/test_broken_repro.py"),
        dict(test_path="tests/test_broken_repro.py", test_source=broken, fails_on_vulnerable=True,
             command="python -m pytest -q tests/test_broken_repro.py", output_excerpt="NameError"))[-1]
    h, orch, store = _hunter(env, repo, provider=provider)
    outcome = h.cycle()
    assert not outcome.escalated and outcome.reason == "hypothesis not reproducible"
    assert store.list_reports() == []



def test_hunter_refuses_without_allowlist(env, repo):
    """VSLA-F-19 / threats T24: the hunter records authorization and cannot enforce it; the operator's allowlist is the
    one-line guard, so a target outside it (or an empty allowlist) refuses to start with a clear error."""
    import pytest

    cfg, store, audit, _prov, orch = env
    with pytest.raises(PermissionError, match="authorized_targets"):
        Hunter(provider=demo_provider_with_hunter(), store=store, repo_slug="example/vulnpkg", repo_path=Path(repo), escalator=LocalEscalator(orch))
    with pytest.raises(PermissionError, match="not in hunter.authorized_targets"):
        Hunter(provider=demo_provider_with_hunter(), store=store, repo_slug="example/vulnpkg", repo_path=Path(repo), escalator=LocalEscalator(orch),
               authorized_targets=["someone-else/other"])
    # a URL or the checkout path also authorizes
    for ok in (["https://github.com/example/vulnpkg.git"], [str(repo)]):
        Hunter(provider=demo_provider_with_hunter(), store=store, repo_slug="example/vulnpkg", repo_path=Path(repo), escalator=LocalEscalator(orch),
               authorized_targets=ok)
