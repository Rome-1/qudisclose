"""Disclosure policy: SLO targets, embargo rules and the lanes. Published as the `qudisclose://policy` resource."""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, Field

from qudisclose.models import Severity


class SLOTargets(BaseModel):
    """Minutes. Deliberately aggressive: the point is to not wait."""

    acknowledge: int = 15
    triage: int = 60
    patch_critical: int = 240
    patch_high: int = 480
    patch_medium: int = 24 * 60
    patch_low: int = 7 * 24 * 60
    review: int = 60
    publish_after_fix: int = 60

    def patch_target(self, severity: Severity | None) -> int:
        return {
            Severity.CRITICAL: self.patch_critical, Severity.HIGH: self.patch_high,
            Severity.MEDIUM: self.patch_medium, Severity.LOW: self.patch_low,
        }.get(severity or Severity.MEDIUM, self.patch_medium)


class Policy(BaseModel):
    name: str = "qudisclose default disclosure policy"
    version: str = "1"
    embargo_days_max: int = Field(default=7, description="Hard cap. Traditional CVD uses 90; we publish when the fix ships.")
    publish_on_fix: bool = True
    speculative_patching: bool = Field(default=True, description="Start reproduce+patch at acknowledgement, in parallel with triage.")
    require_human_for_merge: bool = False  # qudisclose opens the PR automatically; a human reviews it and merges it on GitHub (qudisclose never merges). Set True to also require human approval (control approve) before the PR is opened.
    require_human_for_publish: bool = False
    max_patch_attempts: int = 3
    credit_reporters: bool = True
    slo: SLOTargets = Field(default_factory=SLOTargets)
    accepted_sources: list[str] = Field(default_factory=lambda: ["mcp", "github_advisory", "dependabot", "osv", "webhook"])
    out_of_scope: list[str] = Field(default_factory=lambda: [
        "Reports without a concrete affected component",
        "Denial of service by resource exhaustion without amplification",
        "Issues in third-party dependencies with no reachable path (report to OSV / upstream)",
    ])

    def embargo_deadline(self, received_at: datetime) -> datetime:
        return received_at + timedelta(days=self.embargo_days_max)
