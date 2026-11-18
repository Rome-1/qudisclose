from __future__ import annotations

import json
from typing import Any

from qudisclose.agents import prompts
from qudisclose.agents.provider import Provider
from qudisclose.agents.tools import sandbox_tools
from qudisclose.models import (
    Event, PatchProposal, PatchResult, Postmortem, ReleasePlan, Report, ReproductionResult, ReviewVerdict,
    SLOCheck, TriageResult,
)
from qudisclose.security.sandbox import SandboxBackend
from qudisclose.security.scanner import Redactor, wrap_untrusted

_redactor = Redactor(keep_emails=True)


def report_block(report: Report) -> str:
    s = report.submission
    body = {
        "title": s.title, "description": s.description, "repo": s.repo, "package": s.package,
        "affected_versions": s.affected_versions, "proof_of_concept": s.proof_of_concept, "cwe": s.cwe,
        "cvss_vector": s.cvss_vector, "suggested_fix": s.suggested_fix, "source": report.source,
        "reporter": report.reporter.identity,
    }
    return wrap_untrusted("vulnerability_report", _redactor.redact(json.dumps(body, indent=2, default=str)))


class TriageAgent:
    role = "triage"

    def __init__(self, provider: Provider, effort: str = "high") -> None:
        self.provider, self.effort = provider, effort

    def run(self, report: Report, known_reports: list[str] | None = None) -> TriageResult:
        user = (f"Project policy: hotfix lane for critical/high.\nKnown open report ids and titles for duplicate "
                f"detection:\n{json.dumps(known_reports or [], indent=1)}\n\n{report_block(report)}")
        return self.provider.run(role=self.role, system=prompts.TRIAGE, user=user, schema=TriageResult, effort=self.effort)


class ReproducerAgent:
    role = "reproducer"

    def __init__(self, provider: Provider, effort: str = "high") -> None:
        self.provider, self.effort = provider, effort

    def run(self, report: Report, sandbox: SandboxBackend) -> ReproductionResult:
        tools = sandbox_tools(sandbox, allow_write=True)
        user = f"Repository tree:\n" + "\n".join(sandbox.tree()[:200]) + "\n\n" + report_block(report)
        return self.provider.run(role=self.role, system=prompts.REPRODUCER, user=user, schema=ReproductionResult,
                                 tools=tools, effort=self.effort)


class PatcherAgent:
    role = "patcher"

    def __init__(self, provider: Provider, effort: str = "xhigh") -> None:
        self.provider, self.effort = provider, effort

    def run(self, report: Report, sandbox: SandboxBackend, reproduction: ReproductionResult,
            feedback: list[str] | None = None) -> PatchProposal:
        tools = sandbox_tools(sandbox, allow_write=True)
        user = (f"Reproduction test at {reproduction.test_path} (run with: {reproduction.command}):\n"
                f"{wrap_untrusted('reproduction_test', reproduction.test_source)}\n\n"
                + (f"Feedback from the previous attempt / reviewer, address every item:\n- " + "\n- ".join(feedback) + "\n\n" if feedback else "")
                + report_block(report))
        return self.provider.run(role=self.role, system=prompts.PATCHER, user=user, schema=PatchProposal,
                                 tools=tools, effort=self.effort)


class ReviewerAgent:
    role = "reviewer"

    def __init__(self, provider: Provider, effort: str = "xhigh") -> None:
        self.provider, self.effort = provider, effort

    def run(self, report: Report, patch: PatchResult) -> ReviewVerdict:
        user = (f"{report_block(report)}\n\nDIFF:\n{wrap_untrusted('patch_diff', patch.proposal.diff)}\n\n"
                f"Test results: reproduction_passes={patch.reproduction_passes} suite_passes={patch.suite_passes} "
                f"attempts={patch.attempts}\n{wrap_untrusted('test_output', patch.output_excerpt)}")
        return self.provider.run(role=self.role, system=prompts.REVIEWER, user=user, schema=ReviewVerdict, effort=self.effort)


class ReleaseAgent:
    role = "release"

    def __init__(self, provider: Provider, effort: str = "medium") -> None:
        self.provider, self.effort = provider, effort

    def run(self, report: Report, triage: TriageResult, patch: PatchResult, current_version: str, advisory_id: str) -> ReleasePlan:
        user = (f"Current version: {current_version}\nAdvisory id to use: {advisory_id}\n"
                f"Reporter wants credit: {report.submission.wants_credit} (identity: {report.reporter.identity})\n"
                f"Triage: {triage.model_dump_json()}\n\nDIFF:\n{wrap_untrusted('patch_diff', patch.proposal.diff)}\n\n{report_block(report)}")
        return self.provider.run(role=self.role, system=prompts.RELEASE, user=user, schema=ReleasePlan, effort=self.effort)


class PostmortemAgent:
    role = "postmortem"

    def __init__(self, provider: Provider, effort: str = "medium") -> None:
        self.provider, self.effort = provider, effort

    def run(self, report: Report, events: list[Event], slo_checks: list[SLOCheck], artifacts: dict[str, Any],
            outcome: str) -> Postmortem:
        timeline = "\n".join(f"{e.at.isoformat()} [{e.actor}] {e.kind} {json.dumps(e.data, default=str)[:300]}" for e in events)
        user = (f"Case {report.id} outcome: {outcome}\n\nTIMELINE:\n{timeline}\n\nSLO CHECKS:\n"
                f"{json.dumps([s.model_dump() for s in slo_checks], indent=1)}\n\nARTIFACTS (truncated):\n"
                f"{_redactor.redact(json.dumps(artifacts, default=str)[:30_000])}")
        return self.provider.run(role=self.role, system=prompts.POSTMORTEM, user=user, schema=Postmortem, effort=self.effort)
