"""The always-on red-team hunter.

A loop that keeps looking at an authorized codebase, feature by feature, and turns reproducible findings into
signed vulnerability reports that flow through the normal qudisclose pipeline (triage -> reproduce -> patch ->
review -> publish). Designed to run on a self-hosted model (GLM/Qwen via Ollama or vLLM) so source never
leaves your hardware, with Claude doing the patching once a report lands.

Three principles keep the volume useful instead of noisy:
  1. It never escalates a guess. Every lead is proven with a failing test in a sandbox first, and the test is
     re-run by code (not trusted from the model) before anything is submitted.
  2. It does not look at files at random. Targets are weighted by entry-point heuristics, git churn, proximity
     to past findings, and staleness, and the coverage map in the store stops it re-walking the same code.
  3. Its output is untrusted input. Reports enter through the same intake as any reporter and are re-reproduced
     and reviewed downstream; the hunter's say-so is only a lead.

Authorization. The hunter refuses to start unless the target repository is in `HunterConfig.authorized_targets`
(owner/name slugs, repository URLs or local checkout paths), and every statement qudisclose signs for a hunter finding
names the authorization basis (`ownership`, `program`, `engagement`, `safe-harbour`; VSLA-F-19). Be clear about what
that buys: VSLA *records* authorization and cannot enforce it, and nothing in the framework constrains a hunter that
never discloses (spec threats.md, T24). The allowlist is the operator's own guard against pointing this loop at code
they are not entitled to test; it is not a security boundary against an operator who edits the config.
"""

from __future__ import annotations

import logging
import random
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from qudisclose.agents import hunter_prompts
from qudisclose.agents.provider import Provider
from qudisclose.agents.tools import sandbox_tools
from qudisclose.models import (
    HypothesisSet, Report, Reporter, ReportSubmission, ReproductionResult, Source, ThreatModel,
)
from qudisclose.config import SandboxConfig
from qudisclose.security.sandbox import make_sandbox, run_classified
from qudisclose.security.scanner import wrap_untrusted
from qudisclose.store import Store

log = logging.getLogger("qudisclose.hunter")

CODE_EXTENSIONS = {".py", ".js", ".ts", ".go", ".rb", ".java", ".php", ".rs", ".c", ".cc", ".cpp", ".h"}
# Kept in sync with quome_sandbox._SEED_EXCLUDE: the hunter must not target a file that the sandbox
# backend won't seed (e.g. docs/), or its reproduction would reference a path that isn't there.
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", "target",
             ".qudisclose-sandboxes", "vendor", "docs", "doc", "site",
             ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vscode"}

# Weighting hints: a path or its contents matching these suggests reachable, security-relevant surface.
ENTRY_POINT_PATTERNS = [
    r"\b(route|handler|view|endpoint|controller|api)\b", r"\b(request|response|http|url|param|query|header|cookie)\b",
    r"\b(open|read_file|read_bytes|send_file|path|join|resolve)\b", r"\b(pickle|marshal|yaml\.load|eval|exec|__import__)\b",
    r"\b(subprocess|os\.system|popen|shell|command)\b", r"\b(sql|query|execute|cursor|format|f\")\b",
    r"\b(auth|login|token|session|password|secret|verify|hmac|jwt)\b", r"\b(upload|download|deserialize|unmarshal|parse)\b",
    r"\b(redirect|ssrf|fetch|requests\.get|urlopen)\b",
]
_ENTRY_RE = [re.compile(p, re.I) for p in ENTRY_POINT_PATTERNS]


@dataclass
class HuntOutcome:
    path: str
    escalated: bool
    report_id: str | None = None
    reason: str = ""
    hypotheses: int = 0


# ----------------------------------------------------------------------------- authorization


def is_authorized(repo_slug: str, repo_path: Path | str, allowlist: list[str]) -> bool:
    """True iff the slug, a URL ending in the slug, or the resolved checkout path is in the operator's allowlist."""
    if not allowlist:
        return False
    slug = repo_slug.strip().lower().removesuffix(".git")
    try:
        resolved = Path(repo_path).resolve()
    except Exception:
        resolved = Path(repo_path)
    for entry in allowlist:
        e = str(entry).strip()
        el = e.lower().rstrip("/").removesuffix(".git")
        if el == slug or el.endswith("/" + slug) or el.endswith(":" + slug):
            return True
        try:
            if Path(e).expanduser().resolve() == resolved:
                return True
        except Exception:
            continue
    return False


# ----------------------------------------------------------------------------- target selection


def candidate_files(repo_path: Path) -> list[str]:
    out: list[str] = []
    for p in sorted(repo_path.rglob("*")):
        rel = p.relative_to(repo_path)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if p.is_file() and p.suffix in CODE_EXTENSIONS and "test" not in p.name.lower():
            out.append(str(rel))
    return out


def _git_churn(repo_path: Path, rel: str, commits: int = 200) -> int:
    try:
        r = subprocess.run(["git", "-C", str(repo_path), "log", f"-{commits}", "--oneline", "--", rel],
                           capture_output=True, text=True, timeout=10)
        return len(r.stdout.splitlines())
    except Exception:
        return 0


def _entry_point_score(repo_path: Path, rel: str) -> float:
    try:
        text = (repo_path / rel).read_text(errors="ignore")[:40_000]
    except Exception:
        return 0.0
    hits = sum(1 for rx in _ENTRY_RE if rx.search(rel) or rx.search(text))
    return min(hits / len(_ENTRY_RE), 1.0)


class TargetSelector:
    """Scores candidate files and samples one, weighted toward reachable surface and away from stale repeats."""

    def __init__(self, store: Store, repo_slug: str, repo_path: Path, *, rng: random.Random | None = None,
                 top_k: int = 6) -> None:
        self.store, self.repo_slug, self.repo_path = store, repo_slug, repo_path
        self.rng = rng or random.Random()
        self.top_k = top_k

    def score(self, rel: str, coverage: dict[str, dict[str, Any]], churn_max: int) -> float:
        cov = coverage.get(rel, {})
        visits = cov.get("visits", 0)
        found = cov.get("findings", 0)
        entry = _entry_point_score(self.repo_path, rel)
        churn = (_git_churn(self.repo_path, rel) / churn_max) if churn_max else 0.0
        # proximity: a sibling file in a directory that already produced a finding is more interesting
        proximity = 0.3 if any(c.get("findings", 0) and Path(p).parent == Path(rel).parent
                               for p, c in coverage.items() if p != rel) else 0.0
        staleness = 1.0 / (1 + visits)                 # unseen first, then least-recently/least-often seen
        fatigue = 0.4 * max(visits - found, 0)         # stop re-walking files that never pay off
        return 1.6 * entry + 0.8 * churn + proximity + 0.6 * staleness - fatigue

    def pick(self) -> str | None:
        files = candidate_files(self.repo_path)
        if not files:
            return None
        coverage = self.store.coverage(self.repo_slug)
        churn_max = max((_git_churn(self.repo_path, f) for f in files), default=0) or 1
        scored = sorted(((self.score(f, coverage, churn_max), f) for f in files), reverse=True)
        pool = [f for _, f in scored[: self.top_k]]
        weights = [max(s, 0.01) for s, _ in scored[: self.top_k]]
        return self.rng.choices(pool, weights=weights, k=1)[0]


# ----------------------------------------------------------------------------- escalation


class Escalator(Protocol):
    def submit(self, submission: ReportSubmission) -> str: ...


class LocalEscalator:
    """Hand the finding straight to an in-process orchestrator (single-box deployment)."""

    def __init__(self, orchestrator: Any, identity: str = "agent:hunter") -> None:
        self.orchestrator = orchestrator
        self.identity = identity

    def submit(self, submission: ReportSubmission) -> str:
        rep = Report.from_submission(submission, source=Source.MCP, reporter=Reporter(identity=self.identity, credit=False),
                                     embargo_days=self.orchestrator.policy.embargo_days_max)
        rep, is_new = self.orchestrator.intake(rep, actor=self.identity)
        if is_new:
            self.orchestrator.schedule(rep.id)
        return rep.id


class McpEscalator:
    """Submit over MCP as a scoped, signed reporter (distributed deployment: hunter and qudisclose on
    different hosts). Requires the openai/anthropic-free ReporterClient."""

    def __init__(self, url: str, token: str, key_path: str, *, pinned_server_key: str | None = None,
                 pinned_fingerprint: str | None = None) -> None:
        self.url, self.token, self.key_path = url, token, key_path
        self.pins = (pinned_server_key, pinned_fingerprint)

    def submit(self, submission: ReportSubmission) -> str:
        import asyncio

        from qudisclose.client import ReporterClient
        from qudisclose.security import Identity

        async def go() -> str:
            async with ReporterClient(self.url, self.token, Identity.load(Path(self.key_path)),
                                      pinned_server_key=self.pins[0], pinned_fingerprint=self.pins[1]) as c:
                res = await c.submit(submission)
                return res["report_id"]

        return asyncio.run(go())


# ----------------------------------------------------------------------------- the hunter


@dataclass
class Hunter:
    provider: Provider
    store: Store
    repo_slug: str
    repo_path: Path
    escalator: Escalator
    selector: TargetSelector | None = None
    sandbox_config: SandboxConfig | None = None
    effort: str = "high"
    on_outcome: Callable[[HuntOutcome], None] | None = None
    authorized_targets: list[str] = field(default_factory=list)
    authorization_basis: str = "ownership"

    def __post_init__(self) -> None:
        self.repo_path = Path(self.repo_path)
        if not is_authorized(self.repo_slug, self.repo_path, self.authorized_targets):
            raise PermissionError(
                f"hunter refuses to start: {self.repo_slug!r} ({self.repo_path}) is not in hunter.authorized_targets "
                f"({self.authorized_targets or 'empty'}). Add the owner/name slug, repository URL or checkout path of a codebase you are "
                f"entitled to test (basis: ownership, a published program scope, a written engagement, or a safe-harbour policy; VSLA-F-19).")
        self.selector = self.selector or TargetSelector(self.store, self.repo_slug, self.repo_path)

    # -- one cycle: pick -> threat model -> hypothesize -> prove -> escalate

    def cycle(self) -> HuntOutcome:
        target = self.selector.pick()
        if target is None:
            return HuntOutcome(path="", escalated=False, reason="no candidate files")
        try:
            source = (self.repo_path / target).read_text(errors="ignore")[:40_000]
        except Exception as e:
            return self._record(target, HuntOutcome(path=target, escalated=False, reason=f"unreadable: {e}"))

        file_block = wrap_untrusted(f"source:{target}", source)
        tm = self.provider.run(role="hunt_threat_model", system=hunter_prompts.THREAT_MODEL,
                               user=f"File: {target}\n\n{file_block}", schema=ThreatModel, effort=self.effort)
        hs = self.provider.run(role="hunt_hypothesize", system=hunter_prompts.HYPOTHESIZE,
                               user=f"File: {target}\nThreat model: {tm.model_dump_json()}\n\n{file_block}",
                               schema=HypothesisSet, effort=self.effort)
        if not hs.hypotheses:
            return self._record(target, HuntOutcome(path=target, escalated=False, reason="no hypotheses", hypotheses=0))

        # try the most confident hypothesis; prove it in a sandbox before escalating
        hyp = max(hs.hypotheses, key=lambda h: h.confidence)
        sandbox = make_sandbox(f"hunt-{abs(hash(target)) % 10**8}", repo_path=self.repo_path, config=self.sandbox_config)
        try:
            sandbox.create()
            tools = sandbox_tools(sandbox, allow_write=True)
            repro = self.provider.run(
                role="hunt_reproduce", system=hunter_prompts.REPRODUCE,
                user=(f"Hypothesis: {hyp.model_dump_json()}\nRepository tree:\n" + "\n".join(sandbox.tree()[:200])),
                schema=ReproductionResult, tools=tools, effort=self.effort)
            proven = repro.fails_on_vulnerable and self._test_genuinely_fails(sandbox, repro)
        finally:
            sandbox.destroy()

        if not proven:
            return self._record(target, HuntOutcome(path=target, escalated=False, hypotheses=len(hs.hypotheses),
                                                     reason="hypothesis not reproducible"))

        submission = ReportSubmission(
            title=hyp.title,
            description=(f"{tm.notes}\n\nAttack: {hyp.attack}\n\nFound by the qudisclose hunter and reproduced with a "
                         f"failing test ({repro.test_path}). Reproduction output:\n{repro.output_excerpt[:1500]}"),
            repo=self.repo_slug, package=None, affected_versions=[],
            proof_of_concept=repro.test_source[:50_000], cwe=hyp.cwe,
            suggested_fix=None, wants_credit=False)
        report_id = self.escalator.submit(submission)
        return self._record(target, HuntOutcome(path=target, escalated=True, report_id=report_id,
                                                 hypotheses=len(hs.hypotheses), reason="escalated"))

    def _test_genuinely_fails(self, sandbox: Any, repro: ReproductionResult) -> bool:
        """The normative VSLA-F-5 classifier (security/sandbox.py), the same one the platform applies on receipt."""
        sandbox.write(repro.test_path, repro.test_source)
        r, c = run_classified(sandbox, repro.command)
        return r.returncode == 1 and not r.timed_out and c.security_failure

    def _record(self, target: str, outcome: HuntOutcome) -> HuntOutcome:
        self.store.record_visit(self.repo_slug, target, found=outcome.escalated, outcome=outcome.reason)
        if self.on_outcome:
            self.on_outcome(outcome)
        return outcome

    # -- the loop

    def run(self, *, iterations: int = 0, interval: float = 30.0, max_findings: int = 0) -> list[HuntOutcome]:
        """iterations=0 loops forever; max_findings=0 is unlimited. Returns outcomes (bounded runs only)."""
        outcomes: list[HuntOutcome] = []
        found = 0
        i = 0
        while iterations == 0 or i < iterations:
            i += 1
            try:
                o = self.cycle()
            except Exception as exc:  # one bad cycle must not kill an always-on loop
                log.exception("hunt cycle failed")
                o = HuntOutcome(path="", escalated=False, reason=f"cycle error: {type(exc).__name__}")
            outcomes.append(o)
            if o.escalated:
                found += 1
                if max_findings and found >= max_findings:
                    break
            if iterations == 0 or i < iterations:
                time.sleep(interval)
        return outcomes
