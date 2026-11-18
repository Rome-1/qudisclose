"""The verification procedure (spec: verification.md): claimed level -> verified level, per pillar, with every check
recorded and marked external (vs a pinned key, an expectation or the receiver's own execution) or structural
(self-consistency). Mirrors the reference verifier in the vsla repository check for check; the same inputs give the
same level. A missing or malformed input fails the checks that need it (VSLA-V-3); nothing self-reported stands in
for it. A receipt is read by E7/E8 only after I3 verified it under the pinned platform key the statement names. Every key
window, `revoke` entry and the rubric's decay are evaluated at one instant, `t_eval` (the anchor's integratedTime, else
the receipt's receivedAt, else the verifier's clock), and the time chain startedAt <= finishedAt <= receivedAt <=
integratedTime <= now is enforced (revision 4)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

import jsonschema

from qudisclose.models import ReportSubmission
from qudisclose.security.keys import Identity
from qudisclose.vsla.attest import report_digest
from qudisclose.vsla.canonical import sha256_hex
from qudisclose.vsla.dsse import (
    CLOCK_SKEW_S, PAYLOAD_TYPE, PREDICATE_TYPE, STATEMENT_TYPE, WEIGHTS_PAYLOAD_TYPE, _ts, canonical_payload, signer_keyids,
    statement_digest, verify_anchor, verify_receipt, verify_signature,
)
from qudisclose.vsla.environment import REQUIRED_MEASURES, EnvironmentAttestor, NoEnvironment
from qudisclose.vsla.keyring import Keyring
from qudisclose.vsla.ledger import ledger_consistent, ledger_root, ledger_well_formed, missing_entries, revocations, successor_chain, verified_ledger
from qudisclose.vsla.merkle import leaf_bytes, merkle_root
from qudisclose.vsla.rubric import meets_floor, trust_score

SCHEMA_PATH = Path(__file__).resolve().parent / "vsla-provenance-v1.schema.json"
_SCHEMA: dict[str, Any] | None = None
ISOLATION_RANK = {"process": 0, "container": 1, "vm": 2}


def _try(fn: Callable[[], Any], default: Any = None) -> Any:
    """A canonicalisation/parsing step: a malformed input is a failed check, never an exception out of `verify()` (VSLA-V-3)."""
    try:
        return fn()
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        return default


def _schema_ok(predicate: dict[str, Any]) -> tuple[bool, str]:
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = json.loads(SCHEMA_PATH.read_text())
    try:
        jsonschema.validate(predicate, _SCHEMA, format_checker=jsonschema.FormatChecker())
        return True, "schema valid"
    except jsonschema.ValidationError as e:
        return False, f"schema: {e.message[:160]} at {'/'.join(str(p) for p in e.absolute_path)}"


def _models_with_weights(models: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [m for m in models if m.get("serving") in ("self-hosted", "tee")]


def _isolation_ok(rx: dict[str, Any], required: str | None) -> bool:
    if required is None:
        return True
    have = (rx.get("sandbox") or {}).get("isolation")
    return have in ISOLATION_RANK and required in ISOLATION_RANK and ISOLATION_RANK[have] >= ISOLATION_RANK[required]


def verify_weights_attestation(att: dict[str, Any], keyring: Keyring, expected_sha256: str | None) -> bool:
    try:
        kid = signer_keyids(att)[0]
        pub = keyring.get(kid)
        body = canonical_payload(att)
    except Exception:
        return False
    return (pub is not None and kid.startswith("provider:") and verify_signature(att, kid, pub, WEIGHTS_PAYLOAD_TYPE)
            and body.get("weights", {}).get("sha256") == expected_sha256)


@dataclass
class Check:
    id: str
    level: int
    ok: bool
    detail: str = ""
    kind: str = "external"   # "external" or "structural"


@dataclass
class Pillar:
    name: str
    level: int = 0
    failed: str | None = None
    checks: list[Check] = field(default_factory=list)

    def run(self, cid: str, level: int, cond: bool, detail: str = "", kind: str = "external") -> bool:
        self.checks.append(Check(cid, level, bool(cond), detail, kind))
        return bool(cond)

    def finalize(self) -> None:
        """Level = highest n such that every check at level <= n passed; `failed` = the first failing check in order (VSLA-V-2)."""
        self.level = 0
        for n in (1, 2, 3):
            if all(c.ok for c in self.checks if c.level <= n):
                self.level = n
            else:
                break
        self.failed = next((c.id for c in self.checks if not c.ok and c.level <= self.level + 1), None)

    def check(self, cid: str) -> Check | None:
        return next((c for c in self.checks if c.id == cid), None)


@dataclass
class VerificationResult:
    claimed: int
    verified: int
    track: str
    pillars: dict[str, Pillar]

    def to_dict(self) -> dict[str, Any]:
        return {"claimed": self.claimed, "verified": self.verified, "track": self.track,
                "pillars": {k: {"level": p.level, "failed": p.failed, "checks": [c.__dict__ for c in p.checks]} for k, p in self.pillars.items()},
                "checks": [c.__dict__ for p in self.pillars.values() for c in p.checks]}

    def detail(self, cid: str) -> str:
        for p in self.pillars.values():
            c = p.check(cid)
            if c is not None:
                return c.detail
        return ""

    def ok(self, cid: str) -> bool:
        for p in self.pillars.values():
            c = p.check(cid)
            if c is not None:
                return c.ok
        return False


class Verifier:
    """`keyring` holds pinned keys by VSLA keyid (finder:, platform:, maintainer:, provider:, root:, operator:, log:). `expectations`
    are the receiver's independently obtained reference values (VSLA-V-6): {"harness": {name: {version: sha256}},
    "measurements": [{"type", "value", "harness", "coSigners"?}]}; without them the Environment pillar cannot pass N2.
    `require_anchor` makes I3 (and E7, which reads the receipt) demand a verified `log-inclusion` anchor (VSLA-P-16);
    `accept_timestamp_anchor` lets the `signed-timestamp` form satisfy it; `require_isolation` ("vm" | "container") makes E7
    accept only re-executions in at least that isolation class (VSLA-P-11). `required_entries` are ledger entries this
    verifier itself countersigned for the finder; each must be included in the presented ledger or I4 is a ledger-fork."""

    def __init__(self, keyring: Keyring, *, platform_keyid: str | None = None, environment: EnvironmentAttestor | None = None,
                 expectations: dict[str, Any] | None = None, floor: float = 0.6, min_entries: int = 5, min_countersigners: int = 2,
                 min_age_days: float = 30, require_leaves: bool = False, require_anchor: bool = False, require_isolation: str | None = None,
                 accept_timestamp_anchor: bool = False) -> None:
        self.keyring, self.platform_keyid = keyring, platform_keyid
        self.environment = environment or NoEnvironment()
        self.expectations = expectations or {}
        self.floor, self.min_entries, self.min_countersigners, self.min_age_days = floor, min_entries, min_countersigners, min_age_days
        self.require_leaves = require_leaves
        self.require_anchor, self.require_isolation, self.accept_timestamp_anchor = require_anchor, require_isolation, accept_timestamp_anchor

    def verify(self, envelope: dict[str, Any], *, report: ReportSubmission | dict[str, Any] | None = None,
               leaves: list[dict[str, Any]] | None = None, receipt: dict[str, Any] | None = None,
               reexecution: dict[str, Any] | None = None, ledger_entries: list[dict[str, Any]] | None = None,
               last_seen: tuple[str, int] | None = None, expected_intake: str | None = None,
               expectations: dict[str, Any] | None = None, now_days: float | None = None,
               require_anchor: bool | None = None, require_isolation: str | None = None,
               accept_timestamp_anchor: bool | None = None, required_entries: list[dict[str, Any]] | None = None) -> VerificationResult:
        E, I, N = Pillar("evidence"), Pillar("identity"), Pillar("environment")
        exp = expectations if expectations is not None else self.expectations
        keyring = self.keyring
        req_anchor = self.require_anchor if require_anchor is None else require_anchor
        req_iso = self.require_isolation if require_isolation is None else require_isolation
        accept_ts = self.accept_timestamp_anchor if accept_timestamp_anchor is None else accept_timestamp_anchor
        now_s = now_days * 86400 if now_days is not None else time.time()
        try:
            stmt = canonical_payload(envelope)
            pred = stmt["predicate"]
            if not isinstance(pred, dict):
                raise TypeError("predicate is not an object")
            claimed = int(pred["claimedLevel"])
        except Exception as exc:
            for p in (E, I, N):
                p.run("E1", 1, False, f"envelope unreadable, payload not canonical, or claimedLevel missing: {exc!s}"[:200], "structural")
                p.finalize()
            return VerificationResult(0, 0, "finding", {"evidence": E, "identity": I, "environment": N})
        track = str(pred.get("track") or "finding")
        profile = pred.get("profile", "published")
        fin = pred.get("finder", {}) or {}
        rp = pred.get("reproduction", {}) or {}
        tr = pred.get("transcript", {}) or {}
        models = (pred.get("mbom", {}) or {}).get("models", []) or []
        env = pred.get("environment")
        ts = pred.get("timestamps", {}) or {}
        subj = stmt.get("subject", []) or []
        revision = (subj[1].get("digest", {}).get("gitCommit") if len(subj) > 1 and isinstance(subj[1], dict) else None)
        finder_key_hex = str(fin.get("publicKey", "")).removeprefix("ed25519:")

        # ---------------------------------------------------------------- the receipt (I3), verified before anything reads it
        ch = pred.get("channel") or {}
        intake_hex = str(ch.get("intakeKey", "")).removeprefix("ed25519:")
        pkid = self.platform_keyid or keyring.find("platform", intake_hex) or (keyring.role("platform")[0] if keyring.role("platform") else None)
        pkey = keyring.get(pkid) if pkid else None
        rbody = (_try(lambda: canonical_payload(receipt), {}) if receipt else {}) or {}
        rkid = signer_keyids(receipt)[0] if receipt and signer_keyids(receipt) else None
        received = _ts(rbody.get("receivedAt"))
        t_start, t_end = _ts(ts.get("startedAt")), _ts(ts.get("finishedAt"))
        # One evaluation instant for every window: the anchor's time (a third party's), else the receipt's, else our clock.
        anchor_ok, anchor_form, anchor_why = verify_anchor(rbody, keyring, now_s=now_s) if rbody else (False, "none", "no receipt")
        t_anchor = _ts((rbody.get("anchor") or {}).get("integratedTime")) if anchor_ok else None
        t_eval = t_anchor if t_anchor is not None else (received if received is not None else now_s)
        rkey = keyring.get(rkid, at=t_eval) if rkid else None
        anchor_accepted = anchor_ok and (anchor_form == "log-inclusion" or (anchor_form == "signed-timestamp" and accept_ts))
        receipt_ok = (bool(ch) and bool(receipt) and bool(rbody) and rkid is not None and rkid.startswith("platform:") and rkey is not None
                      and pkid is not None and rkid == pkid and rkey.public_hex == intake_hex
                      and verify_receipt(receipt, rkid, rkey) and rbody.get("statementDigest") == _try(lambda: statement_digest(envelope))
                      and rbody.get("channel") == ch.get("intake") and received is not None and t_start is not None and t_end is not None
                      and t_start <= t_end <= received <= now_s + CLOCK_SKEW_S and bool((rbody.get("reexecution") or {}).get("status"))
                      and (anchor_accepted or not req_anchor))

        # ---------------------------------------------------------------- Evidence
        ok_schema, why = _schema_ok(pred)
        E.run("E1", 1, envelope.get("payloadType") == PAYLOAD_TYPE and stmt.get("_type") == STATEMENT_TYPE
              and stmt.get("predicateType") == PREDICATE_TYPE and ok_schema, f"{why}; payload canonical", "structural")
        fkid = f"finder:{fin.get('identity')}"
        fkey = keyring.get(fkid)
        E.run("E2", 1, fkey is not None and verify_signature(envelope, fkid, fkey, PAYLOAD_TYPE) and fkey.public_hex == finder_key_hex, fkid)
        # E3: subject binds the report and a revision; the reproduction ran at that revision; times are ordered
        r_start, r_end = _ts(rp.get("startedAt")), _ts(rp.get("finishedAt"))
        ordered = (t_start is not None and t_end is not None and t_start <= t_end <= now_s + CLOCK_SKEW_S
                   and (r_start is None or r_end is None or (t_start <= r_start <= r_end <= t_end)))
        bound = len(subj) > 1 and bool(revision) and rp.get("revision") == revision
        if report is not None:
            rd = _try(lambda: report_digest(report))
            E.run("E3", 1, bound and ordered and rd is not None and subj[0].get("digest", {}).get("sha256") == rd, "subject[0] vs report; revision binding; time order")
        else:
            E.run("E3", 1, bound and ordered, "report not supplied: revision binding and time order only", "structural")
        # E4: MBOM complete; self-hosted/tee models carry a weight digest or say they are unmeasured
        weights_ok = all(("digest" in (m.get("weights") or {})) or (m.get("weights") or {}).get("unmeasured") is True for m in _models_with_weights(models))
        E.run("E4", 1, bool(models) and all(m.get("serving") in ("api", "self-hosted", "tee") for m in models) and weights_ok, f"{len(models)} models", "structural")
        # E5: Merkle root, measured first leaf, and a verify leaf that matches the reproduction section (structural: the finder wrote both)
        sup = leaves if leaves is not None else tr.get("leaves")
        if sup is not None:
            vleaf = next((x for x in sup if isinstance(x, dict) and x.get("kind") == "verify" and x.get("what") == "reproduction"), None)
            cmd_match = (vleaf is not None and ((rp.get("command") is not None and vleaf.get("command") == rp.get("command"))
                                                 or (rp.get("commandDigest") is not None and sha256_hex(str(vleaf.get("command", "")).encode()) == rp["commandDigest"].get("sha256"))))
            vleaf_ok = (vleaf is not None and cmd_match and vleaf.get("exit") == rp.get("observedExit")
                        and vleaf.get("securityFailure") == rp.get("securityFailure") and vleaf.get("output") == rp.get("outputDigest"))
            root = _try(lambda: merkle_root(leaf_bytes(sup)))
            E.run("E5", 1, root is not None and root == tr.get("root") and len(sup) == tr.get("leafCount")
                  and bool(sup) and isinstance(sup[0], dict) and sup[0].get("kind") == "measure" and vleaf_ok,
                  f"{len(sup)} leaves; verify leaf {'matches' if vleaf_ok else 'missing or mismatched'}", "structural")
        else:
            E.run("E5", 1, not self.require_leaves and tr.get("algorithm") == "rfc6962-sha256" and bool(tr.get("root")), "leaves not supplied: root only", "structural")
        # E6: reproduction executed by code with the right outcome (the finder's own account; structural)
        cmd_profile_ok = (profile == "published" and "command" in rp and "commandDigest" not in rp) or (profile == "embargoed" and "commandDigest" in rp and "command" not in rp)
        if track == "patch":
            pt = pred.get("patch", {}) or {}
            E.run("E6", 1, rp.get("executor") == "code" and cmd_profile_ok and pt.get("applied") is True and pt.get("reproductionPasses") is True and pt.get("suitePasses") is True,
                  "patch: applied, repro passes, suite passes", "structural")
        else:
            E.run("E6", 1, rp.get("executor") == "code" and cmd_profile_ok and rp.get("observedExit") == rp.get("expectedExit") == 1 and rp.get("securityFailure") is True,
                  f"exit {rp.get('observedExit')}", "structural")
        # E7: re-executed by someone other than the finder, at the subject revision, with the receiver's own classifier.
        # A receipt is evidence only once I3 verified it.
        rx = reexecution or ((rbody.get("reexecution") or {}) if receipt_ok else {}) or {}
        who = "verifier" if reexecution else ("platform receipt" if receipt_ok else ("unverified receipt (ignored)" if receipt else "nobody"))
        iso = (rx.get("sandbox") or {}).get("isolation")
        rx_at_rev = rx.get("status") == "matched" and rx.get("revision") == revision and _isolation_ok(rx, req_iso)
        if track == "patch":
            E.run("E7", 2, rx_at_rev and rx.get("applied") is True and rx.get("reproductionPasses") is True and rx.get("suitePasses") is True,
                  f"re-execution status={rx.get('status')!r} isolation={iso} by {who}")
            rv = rx.get("review") or {}
            scope_ok = rx.get("scope") == "source-only"
            E.run("E8", 2, rx_at_rev and rv.get("approved") is True and rv.get("distinctFamily") is True and scope_ok,
                  f"receiver review approved={rv.get('approved')} distinctFamily={rv.get('distinctFamily')} scope={rx.get('scope')}; finder-asserted review is informational")
        else:
            E.run("E7", 2, rx_at_rev and rx.get("observedExit") == 1 and rx.get("securityFailure") is True and rx.get("touchedSubject") is True,
                  f"re-execution status={rx.get('status')!r} touchedSubject={rx.get('touchedSubject')} isolation={iso} by {who}")

        # ---------------------------------------------------------------- Identity
        auth = pred.get("authorization", {}) or {}
        finder_key = f"ed25519:{finder_key_hex}"
        chain = successor_chain(ledger_entries or [], finder_key)
        revoked = [r for r in revocations(ledger_entries or [], keyring, chain) if r[1] <= t_eval]
        key_valid = fkey is not None and keyring.get(fkid, at=t_eval) is not None and not revoked
        I.run("I1", 1, key_valid and bool(fin.get("operator")) and bool((fin.get("harness") or {}).get("digest")) and bool(auth.get("basis")),
              f"{fkid} {'valid' if key_valid else 'revoked or outside its window'} at t_eval={datetime.fromtimestamp(t_eval, UTC).isoformat()}"
              f"{' (' + ', '.join(r[2] for r in revoked) + ')' if revoked else ''}; authorization={auth.get('basis')}")
        I.run("I2", 2, bool(ch) and (expected_intake is None or ch.get("intake") == expected_intake)
              and pkey is not None and intake_hex == pkey.public_hex, ch.get("intake") or "no channel")
        I.run("I3", 2, receipt_ok,
              (f"{rkid}; {anchor_why}" if receipt_ok else
               f"{rkid or 'no receipt'}: " + ("anchor required: " + anchor_why if receipt and req_anchor and not anchor_accepted else
                                               "not a verified receipt from the pinned platform key the statement names, with finishedAt <= receivedAt <= now")))
        hist = pred.get("history") or {}
        if ledger_entries is None:
            I.run("I4", 2, False, "ledger not supplied: a self-reported summary is not evidence (VSLA-V-3)")
        else:
            formed, why_formed = ledger_well_formed(ledger_entries)
            bodies, dropped = verified_ledger(ledger_entries, keyring, finder=chain, track=track)
            root_ok = _try(lambda: ledger_root(ledger_entries) == hist.get("root"), False)
            consistent = last_seen is None or ledger_consistent(ledger_entries, *last_seen)
            omitted = missing_entries(ledger_entries, required_entries or [])
            tscore = _try(lambda: trust_score(bodies, now_days=t_eval / 86400), trust_score([]))   # evaluated at t_eval; a malformed `at` fails, never crashes
            floor_ok, why_floor = meets_floor(tscore, floor=self.floor, min_entries=self.min_entries, min_countersigners=self.min_countersigners, min_age_days=self.min_age_days)
            reason = ("ledger-fork: does not extend the ledger this verifier was shown" if not consistent
                      else f"ledger-fork: omits {omitted} entr{'y' if omitted == 1 else 'ies'} this verifier countersigned" if omitted
                      else why_formed if not formed else "history.root mismatch" if not root_ok else "" if floor_ok else "below floor")
            I.run("I4", 2, consistent and not omitted and formed and root_ok and floor_ok,
                  f"{reason or 'ok'}; {why_floor}; {dropped} outcome entries dropped (unverifiable, other finder or other track); chain of {len(chain)} key(s)")

        # ---------------------------------------------------------------- Environment
        N.run("N1", 1, bool(models) and all(m.get("serving") for m in models), "serving modes declared", "structural")
        harness = fin.get("harness") or {}
        harness_d = (harness.get("digest") or {}).get("sha256")
        sb_d = ((rp.get("sandbox") or {}).get("digest") or {}).get("sha256")
        first = (sup[0] if sup else None) if sup is not None else tr.get("firstLeaf")
        first_ok = isinstance(first, dict) and first.get("kind") == "measure" and (first.get("harness") or {}).get("sha256") == harness_d \
            and (sb_d is None or (first.get("sandbox") or {}).get("sha256") == sb_d)
        expected_h = ((exp.get("harness") or {}).get(str(harness.get("name", "")), {}) or {}).get(str(harness.get("version", "")))
        att_ok = all(verify_weights_attestation(m["weights"]["attestation"], keyring, (m["weights"].get("digest") or {}).get("sha256"))
                     for m in _models_with_weights(models) if (m.get("weights") or {}).get("attestation"))
        if expected_h is None:
            N.run("N2", 2, False, f"no expectation for harness {harness.get('name')} {harness.get('version')}: measured digest cannot be checked (VSLA-V-6)")
        else:
            N.run("N2", 2, first_ok and harness_d == expected_h and att_ok,
                  f"measured first leaf vs expectation; weight attestations {'ok' if att_ok else 'failed'}. Below L3 the digest is the finder's own measurement and detects drift, not fraud")
        api_served = [m.get("name") for m in models if m.get("serving") == "api"]
        enclave_pub_hex = str((env or {}).get("enclaveKey", "")).removeprefix("ed25519:") or None
        binding = {"enclaveKey": enclave_pub_hex, "harness": harness_d,
                   "weights": [m["weights"]["digest"]["sha256"] for m in _models_with_weights(models) if "digest" in (m.get("weights") or {})], "sandbox": sb_d}
        cos = sorted(str(c) for c in (env or {}).get("coSigners", []) or [])
        meas_allowed = any(x.get("type") == (env or {}).get("type") and x.get("value") == ((env or {}).get("measurement") or {}).get("value") and x.get("harness") == harness_d
                           and ("coSigners" not in x or sorted(str(c) for c in x["coSigners"]) == cos)
                           for x in exp.get("measurements", []) or [])
        all_attested = bool(_models_with_weights(models)) and all((m.get("weights") or {}).get("attestation") for m in _models_with_weights(models)) and att_ok
        quote_ok = bool(env) and env.get("type") != "none" and _try(lambda: self.environment.verify(env, binding, keyring), False)
        if not env or env.get("type") == "none":
            n3_ok = N.run("N3", 3, False, "no environment")
        elif api_served:
            n3_ok = N.run("N3", 3, False, f"api-served models cannot be measured: {api_served}")
        else:
            n3_ok = N.run("N3", 3, quote_ok and set(REQUIRED_MEASURES) <= set(env.get("measures", [])) and meas_allowed and all_attested and bool(sb_d),
                          f"quote {'ok' if quote_ok else 'failed'}; measurement {'allowlisted' if meas_allowed else 'not in expectations'}; weights {'all attested' if all_attested else 'not all attested'}")
        # I5: the enclave signature verifies under the key the (verified) quote binds; never a pinned key
        ekid = f"enclave:{(env or {}).get('type')}:{str(((env or {}).get('measurement') or {}).get('value', ''))[:16]}"
        try:
            epub = Identity.from_public_hex(ekid, enclave_pub_hex) if enclave_pub_hex else None
        except ValueError:
            epub = None
        I.run("I5", 3, n3_ok and epub is not None and verify_signature(envelope, ekid, epub, PAYLOAD_TYPE), ekid if n3_ok else "environment check failed, so no enclave key (if N3 fails, I5 fails)")

        for p in (E, I, N):
            p.finalize()
        return VerificationResult(claimed, min(E.level, I.level, N.level, claimed), track, {"evidence": E, "identity": I, "environment": N})


def vsla_keyring(*, reporters: dict[str, str], platform: Identity | None = None, platform_name: str | None = None,
                 roots: dict[str, Any] | None = None, countersigners: dict[str, Any] | None = None,
                 providers: dict[str, Any] | None = None, operators: dict[str, Any] | None = None,
                 logs: dict[str, Any] | None = None) -> Keyring:
    """Build the VSLA keyring from qudisclose's pinned reporters (finder:<identity>), the platform key, the countersigners
    the platform pins (platform:<name> / maintainer:<name>, with optional validity windows), providers, operators,
    transparency logs and environment roots. No enclave: keys (VSLA-V-1)."""
    ring = Keyring()
    for name, hexkey in reporters.items():
        ring.add(f"finder:{name}", hexkey)
    if platform is not None and platform_name:
        ring.add(f"platform:{platform_name}", platform)
    for name, key in (roots or {}).items():
        ring.add(f"root:{name}", key)
    for kid, key in (countersigners or {}).items():
        if kid.split(":", 1)[0] not in ("platform", "maintainer"):
            raise ValueError(f"pinned countersigner {kid!r} must be a platform: or maintainer: keyid")
        ring.add(kid, key)
    for name, key in (providers or {}).items():
        ring.add(f"provider:{name}", key)
    for name, key in (operators or {}).items():
        ring.add(f"operator:{name}", key)
    for name, key in (logs or {}).items():
        ring.add(f"log:{name}", key)
    return ring
