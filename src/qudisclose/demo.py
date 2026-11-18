"""Offline demo: a scripted provider that plays all six roles against the `fixtures/vulnpkg` path-traversal bug.

It exercises the same sandbox tools a real model would (list/read/write/run), so the end-to-end pipeline,
verification, publishing and postmortem paths are all real; only the reasoning is canned."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from qudisclose.agents.provider import ScriptedProvider
from qudisclose.models import Lane, Reporter, ReportSubmission, Severity

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "vulnpkg"

REPRO_TEST = '''import pytest

from vulnpkg import resolve_path


def test_path_traversal_is_rejected(tmp_path):
    root = tmp_path / "storage"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("top secret")
    with pytest.raises(ValueError):
        resolve_path(root, "../secret.txt")
    with pytest.raises(ValueError):
        resolve_path(root, "/etc/passwd")
'''

FIXED_FILES = '''"""Serve files from a per-user storage directory."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_path(storage_root: str | os.PathLike[str], user_path: str) -> Path:
    """Map a user-supplied relative path to a location under storage_root.

    Rejects absolute paths and any path that escapes storage_root after resolution.
    """
    root = Path(storage_root).resolve()
    candidate = (root / user_path).resolve()
    if Path(user_path).is_absolute() or not candidate.is_relative_to(root):
        raise ValueError("path escapes storage root")
    return candidate


def read_user_file(storage_root: str | os.PathLike[str], user_path: str) -> bytes:
    return resolve_path(storage_root, user_path).read_bytes()
'''


def demo_submission() -> ReportSubmission:
    return ReportSubmission(
        title="Path traversal in vulnpkg.files.resolve_path allows reading arbitrary files",
        description=("resolve_path joins the caller-controlled `user_path` onto storage_root with no normalization. "
                     "A request for `../secret.txt` or an absolute path escapes the per-user storage directory and "
                     "read_user_file returns arbitrary files readable by the service account."),
        repo="example/vulnpkg", package="vulnpkg", affected_versions=["<1.4.3"],
        proof_of_concept="read_user_file('/srv/storage/alice', '../../etc/passwd')",
        cwe="CWE-22", cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        reporter_contact="researcher@example.org", wants_credit=True,
    )


def demo_reporter() -> Reporter:
    return Reporter(identity="agent:researcher-1", contact="researcher@example.org")


def _triage(user: str, tools: dict) -> dict[str, Any]:
    flagged = "scanner_flags=" in user
    return dict(is_vulnerability=True, severity=Severity.HIGH,
                cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", cvss_score=7.1, cwe="CWE-22",
                exploitability="Any authenticated caller controlling user_path reads arbitrary files; no special conditions.",
                affected_components=["vulnpkg/files.py:resolve_path", "vulnpkg/files.py:read_user_file"], lane=Lane.HOTFIX,
                duplicate_of=None, rationale="Classic CWE-22; direct Path join with user input and no containment check.",
                injection_suspected=flagged)


def _reproducer(user: str, tools: dict) -> dict[str, Any]:
    tools["list_files"]("")
    tools["read_file"]("vulnpkg/files.py")
    tools["write_file"]("tests/test_qud_path_traversal.py", REPRO_TEST)
    out = tools["run_command"]("python -m pytest -q tests/test_qud_path_traversal.py")
    return dict(test_path="tests/test_qud_path_traversal.py", test_source=REPRO_TEST, fails_on_vulnerable="exit=1" in out,
                command="python -m pytest -q tests/test_qud_path_traversal.py", output_excerpt=out[-1500:])


def _patcher(user: str, tools: dict) -> dict[str, Any]:
    tools["read_file"]("vulnpkg/files.py")
    tools["write_file"]("vulnpkg/files.py", FIXED_FILES)
    tools["run_command"]("python -m pytest -q")
    diff = tools["current_diff"]()
    return dict(summary="Resolve and contain user_path under storage_root; reject absolute paths and escapes with ValueError.",
                diff=diff, files_touched=["vulnpkg/files.py"],
                risk_notes="Callers passing absolute paths intentionally will now get ValueError; this was never a supported contract.")


def _reviewer(user: str, tools: dict) -> dict[str, Any]:
    m = re.search(r"reproduction_passes=(\w+) suite_passes=(\w+)", user)
    ok = bool(m and m.group(1) == "True" and m.group(2) == "True") and "is_relative_to" in user
    return dict(approved=ok, completeness="Both resolve_path and read_user_file go through the containment check.",
                regressions=[], scope_creep=[], suspicious=[],
                required_changes=[] if ok else ["Patch must make the reproduction test and the suite pass"],
                rationale="Minimal, root-cause fix using resolve()+is_relative_to; symlink escapes are covered by resolve().")


def _release(user: str, tools: dict) -> dict[str, Any]:
    ver = re.search(r"Current version: (\S+)", user).group(1)  # type: ignore[union-attr]
    adv_id = re.search(r"Advisory id to use: (\S+)", user).group(1)  # type: ignore[union-attr]
    major, minor, patch = (int(x) for x in ver.split(".")[:3])
    new = f"{major}.{minor}.{patch + 1}"
    return dict(new_version=new,
                changelog_entry=f"## {new}\n- Security: resolve_path now rejects paths that escape the storage root ({adv_id}, CWE-22).",
                pr_title=f"security: contain user paths under storage root ({adv_id})",
                pr_body=(f"Fixes a path traversal in `vulnpkg.files.resolve_path` ({adv_id}).\n\n* Adds containment check with "
                         f"`Path.resolve()` + `is_relative_to`\n* Adds regression test `tests/test_qud_path_traversal.py`\n\n"
                         "Verified by qudisclose: reproduction test fails before / passes after; full suite green; independent review approved."),
                advisory=dict(id=adv_id, summary="Path traversal in vulnpkg.files.resolve_path",
                              details="resolve_path joined user input onto the storage root without containment, allowing arbitrary file reads.",
                              severity=Severity.HIGH, cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", cwe="CWE-22",
                              affected=[{"package": {"name": "vulnpkg", "ecosystem": "PyPI"},
                                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": new}]}]}],
                              fixed_version=new, references=["https://github.com/example/vulnpkg/security/advisories"],
                              credits=["agent:researcher-1"],
                              cve_request=f"Requesting a CVE for {adv_id}: CWE-22 path traversal in vulnpkg < {new}. Fixed in {new}.",
                              published=False))


def _postmortem(user: str, tools: dict) -> dict[str, Any]:
    rid = re.search(r"Case (rpt_\w+) outcome: (\S+)", user)
    missed = re.findall(r'"name":\s*"([^"]+)",\s*"target_minutes":\s*\d+,\s*"actual_minutes":\s*[\d.]+,\s*"met":\s*false', user)
    retries = len(re.findall(r"patch_attempt", user)) - 1
    went_badly = [f"SLO missed: {m}" for m in missed] + ([f"{retries} failed patch attempt(s) before verification"] if retries > 0 else [])
    if "reproduction_unverified" in user:
        went_badly.append("Reproducer's claim did not survive independent re-run")
    if "scanner_flags" in user and "scanner_flags': []" not in user and '"scanner_flags": []' not in user:
        went_badly.append("Report text triggered the injection scanner; agents ran with hardened prompts")
    return dict(report_id=rid.group(1) if rid else "unknown", outcome=rid.group(2) if rid else "unknown",
                timeline=[line.strip() for line in user.split("TIMELINE:")[1].split("SLO CHECKS:")[0].strip().splitlines()][:40],
                slo_checks=[], went_well=["Acknowledged instantly at intake", "Reproduction and triage ran in parallel",
                                          "Fix verified by code in a clean worktree, not by the model's say-so", "Independent review approved on first pass"]
                if "review_done" in user else ["Acknowledged instantly at intake"],
                went_badly=went_badly or ["Nothing notable"],
                action_items=["Add a fuzz target for resolve_path to CI", "Document the storage-root contract in the README",
                              "Consider enabling require_human_for_publish until trust in automation is established"],
                summary="Hotfix shipped through the fully automated path." if "published" in user else "Case did not reach publication; see went_badly.")


def demo_provider() -> ScriptedProvider:
    return ScriptedProvider({"triage": _triage, "reproducer": _reproducer, "patcher": _patcher, "reviewer": _reviewer,
                             "release": _release, "postmortem": _postmortem})


# ----------------------------------------------------------------------------- scripted hunter (offline)

def _hunt_threat_model(user: str, tools: dict) -> dict[str, Any]:
    path = re.search(r"File: (\S+)", user)
    path = path.group(1) if path else "unknown"
    return dict(component=path,
                entry_points=["resolve_path(storage_root, user_path)", "read_user_file(...)"] if "files.py" in path else [],
                assets=["arbitrary files readable by the service account"] if "files.py" in path else ["none obvious"],
                trust_boundaries=["user_path is attacker-controlled"] if "files.py" in path else [],
                notes=("resolve_path joins user input onto a root with no normalization" if "files.py" in path
                       else "no security-relevant external input found in this file"))


def _hunt_hypothesize(user: str, tools: dict) -> dict[str, Any]:
    if "files.py" not in user or "resolve_path" not in user:
        return dict(hypotheses=[])
    return dict(hypotheses=[dict(
        title="Path traversal in vulnpkg.files.resolve_path allows reading arbitrary files",
        cwe="CWE-22", location="vulnpkg/files.py:resolve_path",
        attack="pass '../' sequences or an absolute path as user_path to escape storage_root",
        test_idea="assert resolve_path(root, '../secret') raises ValueError", confidence=0.86,
        severity_guess=Severity.HIGH)])


def _hunt_reproduce(user: str, tools: dict) -> dict[str, Any]:
    tools["list_files"]("")
    tools["read_file"]("vulnpkg/files.py")
    tools["write_file"]("tests/test_qud_hunter_path_traversal.py", REPRO_TEST.replace("resolve_path", "resolve_path"))
    out = tools["run_command"]("python -m pytest -q tests/test_qud_hunter_path_traversal.py")
    return dict(test_path="tests/test_qud_hunter_path_traversal.py", test_source=REPRO_TEST,
                fails_on_vulnerable="exit=1" in out,
                command="python -m pytest -q tests/test_qud_hunter_path_traversal.py", output_excerpt=out[-1500:])


def demo_hunter_scripts() -> dict:
    return {"hunt_threat_model": _hunt_threat_model, "hunt_hypothesize": _hunt_hypothesize, "hunt_reproduce": _hunt_reproduce}


def demo_provider_with_hunter() -> ScriptedProvider:
    """One scripted provider that plays both the pipeline agents and the hunter (offline demo and tests)."""
    p = demo_provider()
    p.scripts.update(demo_hunter_scripts())
    return p
