"""The qudisclose intake MCP server.

Streamable HTTP + bearer auth (EdDSA JWTs from our own issuer key). A single `GuardMiddleware` enforces, per
tool call: identity (token), rate limit, required scope, per-message signed envelope (anti-tamper/anti-replay)
and audit logging of inputs and outputs. Tool inputs are strict pydantic models."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import replace
from typing import Any

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.context import CallNext, HandlerResult, ServerMiddleware, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp_types import INTERNAL_ERROR, ToolAnnotations
from pydantic import Field

from qudisclose import __version__
from qudisclose.config import Config
from qudisclose.models import Report, Reporter, ReportSubmission, Source, Status, Strict
from qudisclose.orchestrator import Orchestrator
from qudisclose.security import (
    AuditLog, EnvelopeError, Identity, NonceCache, RateLimiter, ScopedTokenVerifier, SignedEnvelope,
    catalog_fingerprint,
)
from qudisclose.security.keys import KeyRing

INVALID_REQUEST = -32600
_caller: ContextVar[tuple[str, str | None, frozenset[str]]] = ContextVar("qudisclose_caller", default=("anonymous", None, frozenset()))
ADMIN_SCOPES = frozenset({"admin", "report:admin"})
META_SIG_KEY = "qudisclose/sig"

# Least privilege at the tool-call boundary: one required scope per tool. `None` = public.
TOOL_SCOPES: dict[str, str | None] = {
    "catalog_fingerprint": None,
    "submit_report": "report:submit",
    "get_report_status": "report:read",
    "list_reports": "report:read",
    "get_advisory": "report:read",
    "get_postmortem": "report:read",
    "get_audit_trail": "report:read",
    "get_attestation": "report:read",
    "get_ledger": "report:read",
    "acknowledge_report": "triage:write",
    "set_embargo": "triage:write",
    "pause_case": "admin",
    "resume_case": "admin",
    "approve_release": "admin",
}
# Tools that mutate state must carry a signed envelope from a pinned identity.
SIGNED_TOOLS = {"submit_report", "acknowledge_report", "set_embargo", "pause_case", "resume_case", "approve_release"}


class GuardMiddleware(ServerMiddleware[Any]):
    def __init__(self, *, keyring: KeyRing, audit: AuditLog, limiter: RateLimiter, nonces: NonceCache | None = None,
                 identity_resolver: Any = None) -> None:
        self.keyring, self.audit, self.limiter = keyring, audit, limiter
        self.nonces = nonces or NonceCache()
        self._resolve = identity_resolver or self._from_token

    @staticmethod
    def _from_token() -> tuple[str, set[str]]:
        tok = get_access_token()
        if tok is None:
            return "anonymous", set()
        return tok.client_id, set(tok.scopes)

    async def __call__(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        if ctx.method not in ("tools/call", "resources/read"):
            return await call_next(ctx)
        identity, scopes = self._resolve()
        params = dict(ctx.params or {})
        if not self.limiter.allow(identity):
            raise MCPError(INVALID_REQUEST, "rate limit exceeded")
        if ctx.method == "resources/read":
            if "report:read" not in scopes and not (scopes & ADMIN_SCOPES):
                raise MCPError(INVALID_REQUEST, "scope report:read required")
            token = _caller.set((identity, None, frozenset(scopes)))
            try:
                return await call_next(ctx)
            finally:
                _caller.reset(token)

        name = str(params.get("name"))
        args = dict(params.get("arguments") or {})
        meta = dict(params.get("_meta") or {})
        required = TOOL_SCOPES.get(name, "admin")
        if required and required not in scopes and not (scopes & ADMIN_SCOPES):
            self.audit.record(actor=identity, action="tool.denied", input={"tool": name}, output={"reason": f"missing scope {required}"})
            raise MCPError(INVALID_REQUEST, f"scope {required} required for {name}")
        signer = None
        if name in SIGNED_TOOLS:
            # The envelope travels in _meta (native clients) or as an `envelope` argument (generic MCP clients that
            # cannot set _meta). Either way it is verified against the remaining arguments and stripped before the tool runs.
            raw = meta.get(META_SIG_KEY) or args.pop("envelope", None)
            if not raw:
                raise MCPError(INVALID_REQUEST, f"{name} requires a signed envelope: _meta['{META_SIG_KEY}'] or an 'envelope' argument "
                                                "(make one with `qudisclose sign`)")
            try:
                env = SignedEnvelope.model_validate(raw)
                signer = env.verify(self.keyring, self.nonces, name, args)
            except (EnvelopeError, ValueError) as e:
                self.audit.record(actor=identity, action="tool.envelope_rejected", input={"tool": name}, output={"reason": str(e)})
                raise MCPError(INVALID_REQUEST, f"signed envelope rejected: {e}") from e
            if signer.name != identity:
                raise MCPError(INVALID_REQUEST, "envelope signer does not match bearer identity")
        # Hand the verified identity to the tool through a contextvar (never trust a caller-supplied value).
        token = _caller.set((identity, signer.public_hex if signer else None, frozenset(scopes)))
        if "envelope" in (params.get("arguments") or {}):
            params["arguments"] = args
            ctx = replace(ctx, params=params)
        try:
            result = await call_next(ctx)
        except MCPError as e:
            self.audit.record(actor=identity, action=f"tool.{name}.error", input=args, output={"error": e.message})
            raise
        finally:
            _caller.reset(token)
        out: Any = result.model_dump() if hasattr(result, "model_dump") else result
        self.audit.record(actor=identity, action=f"tool.{name}", input=args, output=out,
                          report_id=(out or {}).get("structuredContent", {}).get("report_id") if isinstance(out, dict) else None)
        return result


# ----------------------------------------------------------------------------- tool inputs


class EnvelopeArg(Strict):
    """A `SignedEnvelope` (see `qudisclose sign`). Accepted in place of `_meta['qudisclose/sig']`; verified and
    removed by the server before the tool runs."""
    sender: str
    tool: str
    args_hash: str
    nonce: str
    iat: int
    exp: int
    sig: str


class SubmitReportInput(ReportSubmission):
    pass


class ReportIdInput(Strict):
    report_id: str = Field(pattern=r"^rpt_[0-9a-f]{12}$")


class ListReportsInput(Strict):
    status: Status | None = None
    limit: int = Field(default=50, ge=1, le=200)


class LedgerInput(Strict):
    finder: str | None = Field(default=None, max_length=200)


class SetEmbargoInput(Strict):
    report_id: str = Field(pattern=r"^rpt_[0-9a-f]{12}$")
    days_from_now: int = Field(ge=0, le=90)


class PauseInput(Strict):
    report_id: str = Field(pattern=r"^rpt_[0-9a-f]{12}$")
    reason: str = Field(default="", max_length=500)


# ----------------------------------------------------------------------------- server factory


def build_server(*, config: Config, orchestrator: Orchestrator, audit: AuditLog, server_identity: Identity,
                 issuer_identity: Identity, keyring: KeyRing, identity_resolver: Any = None,
                 enable_http_auth: bool = True) -> MCPServer:
    store = orchestrator.store
    base = config.public_url.rsplit("/mcp", 1)[0]
    auth = AuthSettings(issuer_url=f"{base}/issuer", resource_server_url=config.public_url, validate_token_resource=True,
                        required_scopes=None) if enable_http_auth else None
    guard = GuardMiddleware(keyring=keyring, audit=audit, limiter=RateLimiter(config.rate_limit_per_minute), identity_resolver=identity_resolver)

    mcp = MCPServer(
        name=config.server_name, version=__version__,
        instructions=("Machine-to-machine coordinated vulnerability disclosure. Call catalog_fingerprint first and compare it with "
                      "your pinned value; submit reports with submit_report (requires scope report:submit and a signed envelope in "
                      f"_meta['{META_SIG_KEY}']). Read qudisclose://policy for SLOs and embargo rules."),
        token_verifier=ScopedTokenVerifier(issuer_identity, audience=config.public_url) if enable_http_auth else None,
        auth=auth, middleware=[guard],
    )

    def _identity() -> str:
        return _caller.get()[0]

    def _signer_key() -> str | None:
        return _caller.get()[1]

    def _is_admin() -> bool:
        return bool(_caller.get()[2] & ADMIN_SCOPES)

    def _may_see(r: Report) -> bool:
        """VSLA-P-13: until a case is public, its status, severity, lane, timestamps, timeline, test path, command and
        files touched are visible only to the reporter that submitted it and to an admin (the maintainer's operator)."""
        return r.classification == "public" or _is_admin() or r.reporter.identity == _identity()

    def _withheld(r: Report) -> dict[str, Any]:
        return {"report_id": r.id, "classification": r.classification, "embargoed": True,
                "note": "details are withheld until the case is public (VSLA-P-13)"}

    def _summary(r: Report) -> dict[str, Any]:
        if not _may_see(r):
            return _withheld(r)
        arts = store.artifacts(r.id)
        return {"report_id": r.id, "status": r.status, "lane": r.lane, "severity": r.severity, "source": r.source,
                "classification": r.classification, "received_at": r.received_at.isoformat(),
                "embargo_until": r.embargo_until.isoformat() if r.embargo_until else None, "paused": r.paused,
                "scanner_flags": r.scanner_flags, "artifacts": sorted(arts), "slo": [c.model_dump() for c in orchestrator.slo_checks(r)],
                "vsla": {k: v for k, v in r.vsla.items() if k != "submitted"} | ({"submitted": {kk: vv for kk, vv in r.vsla["submitted"].items() if kk != "pillars"}} if "submitted" in r.vsla else {}),
                "timeline": [{"at": e.at.isoformat(), "kind": e.kind, "actor": e.actor} for e in store.events(r.id)]}

    def catalog_fingerprint_tool() -> dict[str, str]:
        """SHA-256 fingerprint of this server's tool catalog, signed by the server identity. Pin it; refuse to operate if it changes."""
        fp = _fingerprint_sync(mcp)
        return {"fingerprint": fp, "server": server_identity.name, "server_public_key": server_identity.public_hex,
                "signature": server_identity.sign(fp.encode()).hex()}

    mcp.add_tool(catalog_fingerprint_tool, name="catalog_fingerprint", description=catalog_fingerprint_tool.__doc__,
                 annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False))

    @mcp.tool(name="submit_report", annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False),
              description="Submit a vulnerability report. Idempotent on content: resubmitting returns the existing case. Starts triage, reproduction and patching immediately. "
                          "Requires a signed envelope: in _meta['qudisclose/sig'] or as the `envelope` argument (make one with `qudisclose sign submit_report args.json`).")
    def submit_report(report: SubmitReportInput, envelope: EnvelopeArg | None = None) -> dict[str, Any]:
        identity = _identity()
        rep = Report.from_submission(report, source=Source.MCP, reporter=Reporter(
            identity=identity, public_key=_signer_key(), contact=report.reporter_contact, credit=report.wants_credit),
            embargo_days=config.policy.embargo_days_max)
        rep, is_new = orchestrator.intake(rep, actor=identity)
        if is_new:
            orchestrator.schedule(rep.id)
        return {"report_id": rep.id, "new": is_new, "status": rep.status, "embargo_until": rep.embargo_until.isoformat() if rep.embargo_until else None,
                "policy": "qudisclose://policy", "slo_acknowledge_minutes": config.policy.slo.acknowledge}

    @mcp.tool(name="get_report_status", annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def get_report_status(query: ReportIdInput) -> dict[str, Any]:
        """Status, timeline, SLO checks and available artifacts for one case."""
        r = store.get_report(query.report_id)
        if r is None:
            raise MCPError(INVALID_REQUEST, "unknown report")
        return _summary(r)

    @mcp.tool(name="list_reports", annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def list_reports(query: ListReportsInput) -> dict[str, Any]:
        """List cases (most recent first). For an embargoed case only its own reporter and an admin see status, severity,
        lane and timing; everyone else sees the id and that it is embargoed (VSLA-P-13)."""
        rows = store.list_reports(query.status, query.limit)
        out = []
        for r in rows:
            if _may_see(r):
                out.append({"report_id": r.id, "status": r.status, "severity": r.severity, "lane": r.lane, "source": r.source,
                            "received_at": r.received_at.isoformat(), "classification": r.classification,
                            "title": r.submission.title if r.classification == "public" else "[embargoed]"})
            else:
                out.append({"report_id": r.id, "classification": r.classification, "title": "[embargoed]"})
        return {"reports": out}

    @mcp.tool(name="get_advisory", annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def get_advisory(query: ReportIdInput) -> dict[str, Any]:
        """The OSV-format advisory and release plan once a fix is verified (embargoed until published)."""
        r = store.get_report(query.report_id)
        if r is None:
            raise MCPError(INVALID_REQUEST, "unknown report")
        if not _may_see(r):
            return _withheld(r)
        plan = store.get_artifact(r.id, "release_plan")
        if plan is None:
            return {"report_id": r.id, "available": False, "status": r.status}
        if r.classification != "public":
            return {"report_id": r.id, "available": True, "embargoed": True, "fixed_version": plan["new_version"], "embargo_until": r.embargo_until.isoformat() if r.embargo_until else None}
        return {"report_id": r.id, "available": True, "embargoed": False, "advisory": plan["advisory"], "new_version": plan["new_version"], "changelog": plan["changelog_entry"]}

    @mcp.tool(name="get_postmortem", annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def get_postmortem(query: ReportIdInput) -> dict[str, Any]:
        """The automated blameless postmortem for a finished case (withheld on an embargoed case, VSLA-P-13: it names the timeline)."""
        r = store.get_report(query.report_id)
        if r is None:
            raise MCPError(INVALID_REQUEST, "unknown report")
        if not _may_see(r):
            return _withheld(r)
        pm = store.get_artifact(query.report_id, "postmortem")
        return {"report_id": query.report_id, "available": pm is not None, "postmortem": pm}

    @mcp.tool(name="get_audit_trail", annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def get_audit_trail(query: ReportIdInput) -> dict[str, Any]:
        """Hash-chained, signed audit entries for a case plus the chain verification result. Audit entries carry every agent's
        output (the patcher's diff, triage severity); until the case is public they are visible only to its reporter and an
        admin (VSLA-P-13). The chain verification result is public."""
        r = store.get_report(query.report_id)
        if r is None:
            raise MCPError(INVALID_REQUEST, "unknown report")
        ok, msg = audit.verify_chain()
        if not _may_see(r):
            return {**_withheld(r), "chain_ok": ok, "chain_message": msg}
        return {"report_id": query.report_id, "chain_ok": ok, "chain_message": msg,
                "entries": [{k: v for k, v in e.items() if k != "input"} for e in audit.entries(query.report_id)]}

    @mcp.tool(name="get_attestation", annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def get_attestation(query: ReportIdInput) -> dict[str, Any]:
        """VSLA statements for a case: the Finding and Patch statements qudisclose signed (DSSE envelopes), the transcript
        leaves behind their Merkle roots, and, for a submitted statement, the platform receipt and the verification
        (claimed vs verified level, every check). Spec: https://github.com/AAI-Society/vsla."""
        r = store.get_report(query.report_id)
        if r is None:
            raise MCPError(INVALID_REQUEST, "unknown report")
        arts = store.artifacts(r.id)
        public = r.classification == "public"
        # Until the case is public only the embargoed profile leaves the platform (digests for test path, command and files
        # touched); the published profile, the leaves (which name the command) and the receipt (which may carry the command)
        # follow once it is public (VSLA-P-13). The reporter and an admin see the receipt and verification at any time.
        out: dict[str, Any] = {"report_id": r.id, "classification": r.classification, "profile": "published" if public else "embargoed",
                               "finding": arts.get("vsla_finding_published") if public else arts.get("vsla_finding"),
                               "patch": arts.get("vsla_patch_published") if public else arts.get("vsla_patch"),
                               "finding_embargoed": arts.get("vsla_finding") if public else None,
                               "patch_embargoed": arts.get("vsla_patch") if public else None,
                               "finder_key": orchestrator.attestation_identity.public_hex, "platform_key": orchestrator.platform_identity.public_hex}
        if _may_see(r):
            out["vsla"] = r.vsla
            out["receipt"] = arts.get("vsla_receipt")
            out["verification"] = arts.get("vsla_verification")
        else:
            out["vsla"] = {k: {"claimed": v.get("claimed"), "statement": v.get("statement")} for k, v in r.vsla.items() if k in ("finding", "patch") and isinstance(v, dict)}
        out["leaves"] = arts.get("vsla_leaves") if public else None
        return out

    @mcp.tool(name="get_ledger", annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
    def get_ledger(query: LedgerInput) -> dict[str, Any]:
        """The caller's countersigned VSLA trust ledger on this platform (DSSE entries, root, rubric score). Another
        finder's ledger is visible only to an admin: ledger entries for open cases name a submission and its timing (VSLA-P-13)."""
        finder = query.finder or _identity()
        if finder != _identity() and not _is_admin():
            raise MCPError(INVALID_REQUEST, "get_ledger: another finder's ledger requires report:admin")
        fid = orchestrator.finder_id(finder, _signer_key() if finder == _identity() else None)
        led = orchestrator.ledger
        # one ledger per track (VSLA-F-11); each list is directly importable by another qudisclose (`Ledger.import_entry`)
        return {"finder": finder, "finder_key": fid, "platform": orchestrator.platform_name, "countersigner": led.keyid,
                "ledgers": {t: {"root": led.root(fid, t), "entries": led.entries(fid, t), "score": led.score(fid, t)} for t in ("finding", "patch")},
                "floor": {"score": config.vsla.floor, "min_entries": config.vsla.min_entries, "min_countersigners": config.vsla.min_countersigners,
                          "min_age_days": config.vsla.min_age_days}}

    @mcp.tool(name="acknowledge_report", annotations=ToolAnnotations(idempotent_hint=True, open_world_hint=False))
    def acknowledge_report(query: ReportIdInput, envelope: EnvelopeArg | None = None) -> dict[str, Any]:
        """Manually (re)acknowledge and (re)schedule a case. Normally unnecessary: intake acknowledges automatically."""
        r = store.get_report(query.report_id)
        if r is None:
            raise MCPError(INVALID_REQUEST, "unknown report")
        store.add_event(r.id, "acknowledged", _identity(), manual=True)
        if r.status in (Status.ACKNOWLEDGED, Status.FAILED):
            r.status = Status.ACKNOWLEDGED
            store.save_report(r)
            orchestrator.schedule(r.id)
        return {"report_id": r.id, "status": r.status}

    @mcp.tool(name="set_embargo", annotations=ToolAnnotations(open_world_hint=False))
    def set_embargo(query: SetEmbargoInput, envelope: EnvelopeArg | None = None) -> dict[str, Any]:
        """Shorten or extend the embargo (capped by policy.embargo_days_max)."""
        from datetime import timedelta
        r = store.get_report(query.report_id)
        if r is None:
            raise MCPError(INVALID_REQUEST, "unknown report")
        days = min(query.days_from_now, config.policy.embargo_days_max)
        r.embargo_until = orchestrator.clock() + timedelta(days=days)
        store.save_report(r)
        store.add_event(r.id, "embargo_changed", _identity(), embargo_until=r.embargo_until)
        return {"report_id": r.id, "embargo_until": r.embargo_until.isoformat(), "capped": days != query.days_from_now}

    @mcp.tool(name="pause_case", annotations=ToolAnnotations(open_world_hint=False))
    def pause_case(query: PauseInput, envelope: EnvelopeArg | None = None) -> dict[str, Any]:
        """Human veto: halt the pipeline at the next stage boundary."""
        r = orchestrator.pause(query.report_id, _identity(), query.reason)
        return {"report_id": r.id, "paused": True, "status": r.status}

    @mcp.tool(name="resume_case", annotations=ToolAnnotations(open_world_hint=False))
    def resume_case(query: ReportIdInput, envelope: EnvelopeArg | None = None) -> dict[str, Any]:
        """Resume a paused case."""
        r = orchestrator.resume(query.report_id, _identity())
        return {"report_id": r.id, "paused": False, "status": r.status}

    @mcp.tool(name="approve_release", annotations=ToolAnnotations(open_world_hint=False))
    def approve_release(query: ReportIdInput, envelope: EnvelopeArg | None = None) -> dict[str, Any]:
        """Grant the human approval required (if policy demands it) for opening the PR and publishing the advisory."""
        r = orchestrator.approve_release(query.report_id, _identity())
        return {"report_id": r.id, "status": r.status}

    # ------------------------------------------------------------------ resources

    @mcp.resource("qudisclose://policy", mime_type="application/json", description="Disclosure policy, SLO targets and embargo rules")
    def policy_resource() -> str:
        import json
        body = json.loads(config.policy.model_dump_json())
        from qudisclose.security.sandbox import LocalSandbox
        from qudisclose.vsla.attest import sandbox_isolation
        v = config.vsla
        # VSLA-P-5: key, floors, isolation class used for re-execution, admission limits, the countersigners this platform pins
        body["vsla"] = {"spec": "https://github.com/AAI-Society/vsla", "spec_version": "1.0", "accepts_statements": v.enabled,
                        "platform_key": f"ed25519:{orchestrator.platform_identity.public_hex}", "platform_keyid": orchestrator.ledger.keyid,
                        "finder_key": f"ed25519:{orchestrator.attestation_identity.public_hex}", "finder_keyid": f"finder:{orchestrator.attestation_identity.name}",
                        "ledger": "get_ledger (own entries; report:admin for others)",
                        "floors": {"l2_floor": v.floor, "l2_min_entries": v.min_entries, "l2_min_countersigners": v.min_countersigners, "l2_min_age_days": v.min_age_days},
                        "reexecution": {"backend": config.sandbox.backend, "isolation": sandbox_isolation(config.sandbox.backend),
                                        "production_grade": sandbox_isolation(config.sandbox.backend) == "vm",
                                        "isolation_detail": LocalSandbox(".", case_id="policy").isolation_detail() if config.sandbox.backend == "local" else None,
                                        "classifier": "pytest-junit cross-checked against the runner summary and exit code (security/sandbox.py, VSLA-F-5); "
                                                      "defends against honest non-security failures, not against a hostile test inside the runner",
                                        "touched_subject": "coverage | importtime", "touched_subject_means": "imported (importtime) or covered (coverage) a module of the package the platform's repo config names",
                                        "admission": {"per_identity_per_hour": v.reexec_per_identity_per_hour, "concurrent": v.reexec_concurrent,
                                                      "unknown_identities": v.reexec_unknown_identities,
                                                      "unknown_means": "the submission presents no ledger entry verifiable under a countersigner this platform pins; deferred to the slow lane with a not-attempted receipt unless unknown_identities is true"}},
                        "accepts": {"require_anchor": v.require_anchor, "accept_timestamp_anchor": v.accept_timestamp_anchor, "anchor_forms": ["log-inclusion"] + (["signed-timestamp"] if v.accept_timestamp_anchor else []), "require_isolation": v.require_isolation, "pinned_logs": orchestrator.keyring.role("log")},
                        "pinned_countersigners": {k: val for k, val in orchestrator.keyring.to_dict().items() if k.split(":", 1)[0] in ("platform", "maintainer")},
                        "pinned_providers": orchestrator.keyring.role("provider"), "pinned_roots": orchestrator.keyring.role("root"),
                        "expectations": {"harness": orchestrator.expectations.get("harness", {}), "measurements": len(orchestrator.expectations.get("measurements", []))},
                        "profiles": {"embargoed_until_public": True},
                        "require_leaves": v.require_leaves, "l3_environment": bool(v.environment_evidence_path),
                        "retention": "statements, leaves, receipts and ledger entries are kept with the case"}
        return json.dumps(body, indent=2)

    @mcp.resource("qudisclose://reports/{report_id}", mime_type="application/json")
    def report_resource(report_id: str) -> str:
        r = store.get_report(report_id)
        if r is None:
            raise MCPError(INVALID_REQUEST, "unknown report")
        if r.classification == "public":
            return Report.model_validate(r).model_dump_json(indent=2)
        if _may_see(r):
            return Report.model_validate(r).model_dump_json(indent=2, exclude={"submission": {"proof_of_concept"}})
        import json
        return json.dumps({"id": r.id, "classification": r.classification, "embargoed": True, "note": "withheld until public (VSLA-P-13)"}, indent=2)

    @mcp.resource("qudisclose://advisories/{report_id}", mime_type="application/json")
    def advisory_resource(report_id: str) -> str:
        import json
        return json.dumps(get_advisory(ReportIdInput(report_id=report_id)), indent=2, default=str)

    @mcp.resource("qudisclose://attestations/{report_id}", mime_type="application/json")
    def attestation_resource(report_id: str) -> str:
        import json
        return json.dumps(get_attestation(ReportIdInput(report_id=report_id)), indent=2, default=str)

    @mcp.resource("qudisclose://postmortems/{report_id}", mime_type="application/json")
    def postmortem_resource(report_id: str) -> str:
        import json
        return json.dumps(store.get_artifact(report_id, "postmortem") or {"available": False}, indent=2, default=str)

    return mcp


def _fingerprint_sync(mcp: MCPServer) -> str:
    tools = mcp._tool_manager.list_tools()  # type: ignore[attr-defined]
    rows = [{"name": t.name, "description": t.description, "inputSchema": t.parameters} for t in tools]
    return catalog_fingerprint(rows)


def handle_webhook(orchestrator: Orchestrator, source: Any, *, sender: str, body: bytes, headers: Any) -> tuple[int, dict[str, Any]]:
    """Signed webhook intake (huntr, HackerOne, fuzzers, a peer team's qudisclose). Returns (status, json)."""
    from qudisclose.ingest.webhook import WebhookSignatureError

    try:
        report = source.receive(sender=sender, body=body, signature=headers.get("x-qud-signature", ""),
                                timestamp=headers.get("x-qud-timestamp", ""))
    except WebhookSignatureError as e:
        orchestrator.audit.record(actor=f"webhook:{sender}", action="webhook.rejected", input={}, output={"reason": str(e)})
        return 401, {"error": str(e)}
    except Exception as e:  # strict schema violations etc.
        return 400, {"error": f"invalid payload: {type(e).__name__}"}
    source.poll()  # drain: we hand the report to the orchestrator directly
    rep, is_new = orchestrator.intake(report, actor=f"webhook:{sender}")
    if is_new:
        orchestrator.schedule(rep.id)
    return 202, {"report_id": rep.id, "new": is_new, "status": rep.status}


def http_app(mcp: MCPServer, config: Config, orchestrator: Orchestrator | None = None):
    from urllib.parse import urlparse

    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    host = urlparse(config.public_url).netloc
    security = TransportSecuritySettings(allowed_hosts=[host, f"{host.split(':')[0]}:*", "127.0.0.1:*", "localhost:*"], allowed_origins=[])
    app = mcp.streamable_http_app(transport_security=security, stateless_http=True, json_response=True)
    if orchestrator is not None and config.webhook_secrets:
        from qudisclose.ingest.webhook import SignedWebhookSource

        source = SignedWebhookSource(config.webhook_secrets)

        async def webhook(request: Request) -> JSONResponse:
            body = await request.body()
            if len(body) > 512 * 1024:
                return JSONResponse({"error": "payload too large"}, status_code=413)
            status, payload = handle_webhook(orchestrator, source, sender=request.path_params["sender"], body=body, headers=request.headers)
            return JSONResponse(payload, status_code=status)

        app.router.routes.insert(0, Route("/webhooks/{sender}", webhook, methods=["POST"]))
    return app
