"""The read-only dashboard's data layer: `report_rows` / `report_detail` shape the store into exactly
what the page renders, without opening a socket. We run a real case through the orchestrator so the
timeline and artifacts are genuine, then assert the view reflects them."""

from __future__ import annotations

from qudisclose.config import Config
from qudisclose.dashboard import available_models, report_detail, report_rows
from qudisclose.models import Status

from .conftest import new_report


def test_report_rows_lists_cases_newest_first(env):
    _, store, _, _, orch = env
    rep = new_report()
    store.insert_report(rep)
    rows = report_rows(store)
    assert [r["id"] for r in rows] == [rep.id]
    row = rows[0]
    assert row["title"] == rep.submission.title
    assert row["status"] == str(Status.RECEIVED)
    assert set(row) >= {"id", "status", "severity", "lane", "source", "repo", "cwe", "title", "received_at"}
    assert row["repo"] == rep.submission.repo  # repo is carried so the UI can filter/search/link on it


def test_report_detail_has_report_timeline_and_decoded_artifacts(env):
    _, store, _, _, orch = env
    rep, _ = orch.intake(new_report(), actor="agent:test")
    orch.run_case(rep.id)

    d = report_detail(store, rep.id)
    assert d is not None
    assert d["report"]["id"] == rep.id
    # timeline is the ordered event stream
    kinds = [e["kind"] for e in d["events"]]
    assert "triage_done" in kinds and "reproduction_done" in kinds
    # artifacts are decoded dicts, ordered with the known pipeline stages first
    by_kind = {a["kind"]: a["body"] for a in d["artifacts"]}
    assert "triage" in by_kind
    assert isinstance(by_kind["triage"], dict)
    order = [a["kind"] for a in d["artifacts"] if a["kind"] in ("triage", "reproduction", "patch")]
    assert order == sorted(order, key=["triage", "reproduction", "patch"].index)


def test_report_detail_unknown_id_is_none(env):
    _, store, _, _, _ = env
    assert report_detail(store, "rpt_does_not_exist") is None


def test_available_models_gates_claude_on_cli(monkeypatch):
    """Claude is offered in the run picker only when the local `claude` CLI is installed; shape is always well-formed."""
    import qudisclose.dashboard as dash

    cfg = Config()
    monkeypatch.setattr(dash.shutil, "which", lambda name: None)
    m = available_models(cfg)
    assert m["claude"] == []
    assert isinstance(m["local"], list) and "default" in m
    monkeypatch.setattr(dash.shutil, "which", lambda name: "/usr/local/bin/claude")
    assert available_models(cfg)["claude"]  # now offered
