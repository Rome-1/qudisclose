"""Normalized data model shared by ingest adapters, the MCP server, agents and the store."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Strict(BaseModel):
    """Base for every schema that crosses a trust boundary: unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ----------------------------------------------------------------------------- enums


class Source(StrEnum):
    MCP = "mcp"
    GITHUB_ADVISORY = "github_advisory"
    DEPENDABOT = "dependabot"
    OSV = "osv"
    WEBHOOK = "webhook"


class Classification(StrEnum):
    EMBARGOED = "embargoed"
    PUBLIC = "public"


class Status(StrEnum):
    RECEIVED = "received"
    ACKNOWLEDGED = "acknowledged"
    TRIAGING = "triaging"
    REPRODUCING = "reproducing"
    PATCHING = "patching"
    REVIEWING = "reviewing"
    RELEASING = "releasing"
    PUBLISHED = "published"
    CLOSED = "closed"
    PAUSED = "paused"
    REJECTED = "rejected"
    FAILED = "failed"


class Lane(StrEnum):
    HOTFIX = "hotfix"
    SCHEDULED = "scheduled"
    REJECT = "reject"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# ----------------------------------------------------------------------------- report


class Reporter(Strict):
    identity: str = Field(description="Non-human identity (client_id / agent id) or source account")
    public_key: str | None = Field(default=None, description="Ed25519 public key, hex, when submitted over MCP")
    contact: str | None = None
    credit: bool = True


class ReportSubmission(Strict):
    """What a reporter agent sends. Deliberately small and strictly validated (NSA: serialization risk)."""

    title: str = Field(min_length=5, max_length=200)
    description: str = Field(min_length=20, max_length=20_000)
    repo: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", description="owner/name")
    package: str | None = Field(default=None, max_length=200)
    affected_versions: list[str] = Field(default_factory=list, max_length=50)
    proof_of_concept: str | None = Field(default=None, max_length=50_000)
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d{1,5}$")
    cvss_vector: str | None = Field(default=None, max_length=200)
    suggested_fix: str | None = Field(default=None, max_length=20_000)
    reporter_contact: str | None = Field(default=None, max_length=200)
    wants_credit: bool = True
    attestation: dict[str, Any] | None = Field(
        default=None, description="VSLA bundle: {statement: DSSE envelope, leaves?: transcript leaves, "
                                  "reproduction?: {test_path, test_source, command}} (see github.com/AAI-Society/vsla)")

    @field_validator("attestation")
    @classmethod
    def _attestation_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None:
            if "statement" not in v:
                raise ValueError("attestation needs a 'statement' (DSSE envelope)")
            if len(canonical_json(v)) > 512_000:
                raise ValueError("attestation bundle too large (512 KB max)")
        return v

    def content_hash(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(exclude={"reporter_contact", "wants_credit", "attestation"})))


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: new_id("rpt"))
    source: Source
    external_id: str | None = None
    content_hash: str
    reporter: Reporter
    submission: ReportSubmission
    classification: Classification = Classification.EMBARGOED
    status: Status = Status.RECEIVED
    lane: Lane | None = None
    severity: Severity | None = None
    received_at: datetime = Field(default_factory=now)
    embargo_until: datetime | None = None
    paused: bool = False
    scanner_flags: list[str] = Field(default_factory=list)
    vsla: dict[str, Any] = Field(default_factory=dict, description="VSLA claimed/verified levels per track (see vsla/)")

    @classmethod
    def from_submission(cls, sub: ReportSubmission, *, source: Source, reporter: Reporter,
                        external_id: str | None = None, embargo_days: int = 7) -> Report:
        return cls(
            source=source,
            external_id=external_id,
            content_hash=sub.content_hash(),
            reporter=reporter,
            submission=sub,
            embargo_until=now() + timedelta(days=embargo_days),
        )


# ----------------------------------------------------------------------------- events / timeline


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: new_id("evt"))
    report_id: str
    at: datetime = Field(default_factory=now)
    kind: str
    actor: str
    data: dict[str, Any] = Field(default_factory=dict)


# ----------------------------------------------------------------------------- agent outputs


class TriageResult(Strict):
    is_vulnerability: bool
    severity: Severity
    cvss_vector: str = Field(description="CVSS v4.0 vector string, e.g. CVSS:4.0/AV:N/AC:L/...")
    cvss_score: float = Field(ge=0, le=10)
    cwe: str = Field(pattern=r"^CWE-\d{1,5}$")
    exploitability: str = Field(description="one paragraph")
    affected_components: list[str]
    lane: Lane
    duplicate_of: str | None = None
    rationale: str
    injection_suspected: bool = Field(default=False, description="True if the report text tries to instruct the agents")


class ReproductionResult(Strict):
    test_path: str
    test_source: str
    fails_on_vulnerable: bool
    command: str
    output_excerpt: str = Field(max_length=4000)


class PatchProposal(Strict):
    summary: str
    diff: str = Field(description="unified diff relative to repo root")
    files_touched: list[str]
    risk_notes: str


class PatchResult(Strict):
    proposal: PatchProposal
    reproduction_passes: bool
    suite_passes: bool
    attempts: int
    output_excerpt: str = Field(max_length=4000)


class ReviewVerdict(Strict):
    approved: bool
    completeness: str = Field(description="does the diff close every path named in the report")
    regressions: list[str]
    scope_creep: list[str]
    suspicious: list[str] = Field(description="anything that looks like a backdoor, exfil, or unrelated change")
    required_changes: list[str]
    rationale: str


class Advisory(Strict):
    id: str
    summary: str
    details: str
    severity: Severity
    cvss_vector: str
    cwe: str
    affected: list[dict[str, Any]] = Field(description="OSV 'affected' entries")
    fixed_version: str
    references: list[str]
    credits: list[str]
    cve_request: str = Field(description="text for the GitHub CNA CVE request")
    published: bool = False


class ReleasePlan(Strict):
    new_version: str
    changelog_entry: str
    pr_title: str
    pr_body: str
    advisory: Advisory


class SLOCheck(Strict):
    name: str
    target_minutes: int
    actual_minutes: float | None
    met: bool | None


class Postmortem(Strict):
    report_id: str
    outcome: str
    timeline: list[str]
    slo_checks: list[SLOCheck]
    went_well: list[str]
    went_badly: list[str]
    action_items: list[str]
    summary: str


# ----------------------------------------------------------------------------- hunter (always-on red-team loop)


class ThreatModel(Strict):
    """A hunter's reading of one file or feature's attack surface."""

    component: str
    entry_points: list[str] = Field(description="functions/paths that take external or untrusted input")
    assets: list[str] = Field(description="what an attacker would want: files, creds, state, execution")
    trust_boundaries: list[str]
    notes: str


class Hypothesis(Strict):
    """A concrete, testable guess at a vulnerability."""

    title: str = Field(min_length=5, max_length=200)
    cwe: str = Field(pattern=r"^CWE-\d{1,5}$")
    location: str = Field(description="file and symbol, e.g. vulnpkg/files.py:resolve_path")
    attack: str = Field(description="how an attacker triggers it")
    test_idea: str = Field(description="how to prove it with a failing test")
    confidence: float = Field(ge=0, le=1)
    severity_guess: Severity


class HypothesisSet(Strict):
    hypotheses: list[Hypothesis] = Field(max_length=10)
