"""Cross-check against the VSLA *reference* verifier (github.com/AAI-Society/vsla, tools/vsla_verify.py, spec v1.0 rev 3):
statements, receipts and ledger entries qudisclose produces verify there at the level qudisclose itself computes, the
canonical bytes and Merkle/ledger roots agree byte for byte, and the reference examples verify under qudisclose's verifier.
Skipped when the sibling checkout is not present."""

import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qudisclose.security import Identity
from qudisclose.vsla import Keyring, Verifier, canonical, merkle_root
from qudisclose.vsla.dsse import envelope_payload
from qudisclose.vsla.ledger import ledger_root, make_ledger_entry, missing_entries, successor_chain, verified_ledger
from qudisclose.vsla.merkle import leaf_bytes
from qudisclose.vsla.rubric import trust_score
from tests.conftest import new_report
from tests.test_vsla import _fid, _finder_bundle, _platform, _submit

VSLA = next((p for p in (Path(__file__).resolve().parents[2] / "vsla", Path.home() / "Desktop" / "vsla") if (p / "tools" / "vsla_verify.py").exists()), None)
pytestmark = pytest.mark.skipif(VSLA is None, reason="sibling vsla checkout not found")
T0_DAYS = 20756.583333  # 2026-10-30T14:00Z, the reference examples' "now"


def _ref():
    spec = importlib.util.spec_from_file_location("vsla_verify", VSLA / "tools" / "vsla_verify.py")
    mod = importlib.util.module_from_spec(spec); sys.modules["vsla_verify"] = mod; spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _expectations(orch):
    return orch.expectations


def test_canonical_json_is_byte_identical_to_the_reference():
    """VSLA-F-1: RFC 8785 on both sides, including ES6 number formatting and UTF-16 key order."""
    ref = _ref()
    samples = [{"b": 1, "a": [True, None, "xé\n", 0.1, 1.0, 1e21, 1e-7, 123456789012345680.0, -1.5e-10]},
               {"€": 1, "\U0001d11e": 2, "z": 3, "score": 0.8645, "floor": 0.6}, [], {}, "s", 0, -0.0, 2.5]
    for s in samples:
        assert canonical(s) == ref.canonical(s), s
    leaves = [{"seq": 0, "kind": "measure", "harness": {"sha256": "ab" * 32}}, {"seq": 1, "kind": "turn", "x": 1.5}]
    assert merkle_root(leaf_bytes(leaves)) == ref.merkle_root(ref.transcript_leaves(leaves))
    k = Identity.generate("platform:x")
    entry = make_ledger_entry({"at": "2026-01-01T00:00:00Z", "finder": "ed25519:" + "ab" * 32, "outcome": "accepted", "claimed": 1, "verified": 1,
                               "platform": "x", "track": "finding"}, [("platform:x", k)])
    ring = ref.Keyring({"platform:x": "ed25519:" + k.public_hex})
    assert ref.ledger_root([entry]) == ledger_root([entry])
    bodies, dropped = ref.verified_ledger([entry], ring)
    assert dropped == 0 and bodies == verified_ledger([entry], Keyring({"platform:x": k.public_hex}))[0]


def test_qudisclose_statements_verify_under_reference_verifier(env):
    """Both tracks, both profiles: the reference verifier accepts the finder signature, schema, subject binding, verify
    leaf, MBOM and measured first leaf (with the harness expectation), and lands where qudisclose does."""
    cfg, store, audit, provider, orch = env
    ref = _ref()
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    orch.run_case(rep.id)
    arts = store.artifacts(rep.id)
    ring = ref.Keyring({f"finder:{orch.attestation_identity.name}": "ed25519:" + orch.attestation_identity.public_hex,
                        f"platform:{orch.platform_name}": "ed25519:" + orch.platform_identity.public_hex})
    for track in ("finding", "patch"):
        for form in (f"vsla_{track}", f"vsla_{track}_published"):
            env_ = arts[form]
            stmt = envelope_payload(env_)
            n = stmt["predicate"]["transcript"]["leafCount"]
            rev = stmt["subject"][1]["digest"]["gitCommit"]
            reexec = {"status": "matched", "revision": rev, "observedExit": 1, "securityFailure": True, "touchedSubject": True, "outputDigest": {"sha256": "0" * 64},
                      "applied": True, "reproductionPasses": True, "suitePasses": True, "scope": "source-only",
                      "review": {"approved": True, "distinctFamily": True, "reviewerFamily": "qwen", "verdictDigest": {"sha256": "1" * 64}}}
            res = ref.verify(env_, ring, expectations=_expectations(orch), report=rep.submission.model_dump(), leaves=arts["vsla_leaves"][:n],
                             reexecution=reexec, expected_intake=cfg.public_url)
            assert res.claimed == 1 and res.verified == 1, (form, res.to_dict())
            assert res.pillars["evidence"].level >= 2 and res.pillars["environment"].level == 2 and res.pillars["identity"].failed == "I3", (form, res.to_dict())
            assert stmt["predicate"]["profile"] == ("published" if form.endswith("_published") else "embargoed")
            # and qudisclose's own verifier agrees check for check
            mine = orch.verifier.verify(env_, report=rep.submission, leaves=arts["vsla_leaves"][:n], reexecution=reexec, expected_intake=cfg.public_url)
            assert {c.id: c.ok for p in mine.pillars.values() for c in p.checks} == {c.id: c.ok for p in res.pillars.values() for c in p.checks}
    assert merkle_root(leaf_bytes(arts["vsla_leaves"])) == ref.merkle_root(ref.transcript_leaves(arts["vsla_leaves"]))


def test_qudisclose_receipt_and_ledger_verify_under_reference_verifier(tmp_path, repo):
    """VSLA-P-3/P-4/P-6: the platform's DSSE receipt (its own re-execution at the subject revision, classifier, coverage)
    and the countersigned ledger entries it writes verify under the reference, and the reference computes the same L2."""
    ref = _ref()
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, countersigners = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    receipt = store.get_artifact(rep.id, "vsla_receipt")
    assert receipt["payloadType"] == ref.RECEIPT_PAYLOAD_TYPE
    ring = ref.Keyring({f"finder:{forch.attestation_identity.name}": "ed25519:" + forch.attestation_identity.public_hex,
                        f"platform:{orch.platform_name}": "ed25519:" + orch.platform_identity.public_hex,
                        **{kid: "ed25519:" + k.public_hex for kid, k in countersigners}})
    assert ref.verify_receipt(receipt, f"platform:{orch.platform_name}", ring.get(f"platform:{orch.platform_name}"))
    res = ref.verify(bundle["statement"], ring, expectations=_expectations(orch), report=rep.submission.model_dump(), leaves=bundle["leaves"],
                     receipt=receipt, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    mine = store.get_artifact(rep.id, "vsla_verification")
    assert res.claimed == 2 and res.verified == 2 == mine["verified"], res.to_dict()
    rx = ref.envelope_payload(receipt)["reexecution"]
    assert rx["status"] == "matched" and rx["revision"] == envelope_payload(bundle["statement"])["subject"][1]["digest"]["gitCommit"]
    assert rx["securityFailure"] is True and rx["touchedSubject"] is True and rx["sandbox"]["isolation"] == "process"
    # the entry this platform countersigned at close verifies under the reference; the finder appends it to the ledger it
    # handed over, and both implementations compute the same root and rubric score over that extended ledger
    own = orch.ledger.entries(_fid(forch), "finding")
    assert len(own) == 1 and own[0]["payloadType"] == ref.LEDGER_PAYLOAD_TYPE
    bodies, dropped = ref.verified_ledger(own, ring)
    assert dropped == 0 and bodies[0]["outcome"] == "accepted" and bodies[0]["kind"] == "outcome" and bodies[0]["claimed"] == bodies[0]["verified"] == 2
    extended = bundle["ledger"] + own
    assert ref.ledger_root(extended) == ledger_root(extended)
    all_bodies, dropped = ref.verified_ledger(extended, ring)
    assert dropped == 0 and len(all_bodies) == 6 and ref.trust_score(all_bodies)["score"] == trust_score(all_bodies)["score"]
    assert ref.ledger_root(own) == orch.ledger.root(_fid(forch), "finding") and "seq" not in bodies[0]
    assert orch.ledger.last_seen(_fid(forch), "finding") == (ref.ledger_root(bundle["ledger"]), len(bundle["ledger"]))   # what the platform was shown
    assert ref.missing_entries(extended, own) == 0 and ref.missing_entries(bundle["ledger"], own) == 1                 # the own entry must be included next time


def test_reference_examples_verify_under_qudisclose_verifier():
    ex = VSLA / "schema" / "examples"
    if not (ex / "finding-l3.dsse.json").exists():
        import subprocess
        subprocess.run([sys.executable, str(VSLA / "tools" / "make_examples.py")], check=True, capture_output=True)
    load = lambda n: json.loads((ex / n).read_text())
    ring = Keyring(load("keyring.json"))
    v = Verifier(ring, platform_keyid="platform:cvd.example.org", expectations=load("expectations.json"))

    def run(name, **over):
        kw = dict(report=load("report.json"), leaves=load("leaves.json"), ledger_entries=load("ledger-patch.json" if "patch" in name else "ledger.json"),
                  reexecution=load("reexecution-patch.json" if "patch" in name else "reexecution.json"),
                  expected_intake="https://cvd.example.org/mcp", now_days=T0_DAYS)
        if (ex / f"{name}.receipt.dsse.json").exists():
            kw["receipt"] = load(f"{name}.receipt.dsse.json")
        kw.update(over)
        return v.verify(load(f"{name}.dsse.json"), **kw)

    for name, level in (("finding-l1", 1), ("finding-l2", 2), ("finding-l3", 3), ("patch-l1", 1), ("patch-l2", 2), ("patch-l3", 3)):
        res = run(name)
        assert res.claimed == level and res.verified == level, (name, res.to_dict())
    # honest degradation, as the reference tests pin it
    assert run("finding-l2", ledger_entries=None).pillars["identity"].failed == "I4"                       # self-reported summary is not evidence
    assert run("finding-l2", expectations={}).pillars["environment"].failed == "N2"                        # no expectation for the harness
    assert run("finding-l2", receipt=None, reexecution=None).pillars["evidence"].failed == "E7"            # nobody re-executed
    ledger = load("ledger.json")
    res = run("finding-l2", last_seen=(ledger_root(ledger[:7] + [ledger[9]]), 8))
    assert res.verified == 1 and "ledger-fork" in res.detail("I4")
    rx = load("reexecution-patch.json"); rx.pop("review")
    assert run("patch-l2", receipt=None, reexecution=rx).pillars["evidence"].failed == "E8"                # finder-asserted review never satisfies E8
    assert run("patch-l2", receipt=None, reexecution={**load("reexecution-patch.json"), "scope": "mixed"}).pillars["evidence"].failed == "E8"
    assert run("patch-l2", ledger_entries=ledger).pillars["identity"].failed == "I4"                           # a finding ledger buys no patch trust
    res = run("finding-l2", ledger_entries=ledger[5:] + ledger[:5])                                              # reordered: the root the statement commits to no longer matches
    assert res.pillars["identity"].failed == "I4" and "history.root mismatch" in res.detail("I4")
    assert "log-inclusion in" in run("finding-l2", reexecution=None, require_anchor=True).detail("I3")        # the example receipts carry log-inclusion anchors
    assert "omits 1 entry" in run("finding-l2", required_entries=[ledger[9]], ledger_entries=ledger[:9] + ledger[10:]).detail("I4")
    # every check agrees with the reference, including the receipt-only path and the required-anchor path
    ref = _ref(); rring = ref.Keyring(load("keyring.json"))
    for name in ("finding-l2", "finding-l3", "patch-l2", "patch-l3"):
        mine = run(name, reexecution=None, require_anchor=True)
        theirs = ref.verify(load(f"{name}.dsse.json"), rring, expectations=load("expectations.json"), report=load("report.json"), leaves=load("leaves.json"),
                            ledger_entries=load("ledger-patch.json" if "patch" in name else "ledger.json"), receipt=load(f"{name}.receipt.dsse.json"),
                            expected_intake="https://cvd.example.org/mcp", quote_verifier=ref.signed_quote_verifier(rring), now_days=T0_DAYS, require_anchor=True)
        assert {c.id: (c.ok, c.kind) for p in mine.pillars.values() for c in p.checks} == {c.id: (c.ok, c.kind) for p in theirs.pillars.values() for c in p.checks}, name


def test_round3_semantics_agree_with_the_reference():
    """Round 3: successor chains, revoke entries, required-entry omission, both anchor forms and t_eval key windows give the
    same (ok, kind) per check in both verifiers, on inputs built with the reference's own primitives."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ref = _ref()
    ex = VSLA / "schema" / "examples"
    load = lambda n: json.loads((ex / n).read_text())
    old, new, pk, lk, op = (Ed25519PrivateKey.generate() for _ in range(5))
    hexof = lambda k: ref.public_hex(k.public_key())
    ring_json = load("keyring.json")
    ring_json["finder:agent:researcher-1"] = "ed25519:" + hexof(new)
    ring_json["platform:cvd.example.org"] = "ed25519:" + hexof(pk)
    ring_json["log:log.example.org"] = "ed25519:" + hexof(lk)
    ring_json["operator:quome.com"] = "ed25519:" + hexof(op)
    ma, mb = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    ring_json["maintainer:test/a"] = "ed25519:" + hexof(ma); ring_json["maintainer:test/b"] = "ed25519:" + hexof(mb)
    # six accepted entries earned under the OLD key, then a successor entry to the new key
    ledger = []
    for i in range(6):
        body = {"at": f"2026-0{7 if i < 3 else 8}-{10 + i:02d}T00:00:00Z", "finder": "ed25519:" + hexof(old), "statement": {"sha256": "%064x" % (i + 1)},
                "platform": "test", "track": "finding", "outcome": "accepted", "claimed": 2, "verified": 2}
        ledger.append(ref.make_ledger_entry(body, [[("maintainer:test/a", ma), ("maintainer:test/b", mb)][i % 2]]))
    rot = ref.make_successor_entry(at="2026-09-01T00:00:00Z", old=old, new=new, old_keyid="finder:agent:researcher-1")
    rotated = ledger + [rot]
    env = load("finding-l2.dsse.json"); stmt = ref.envelope_payload(env)
    stmt["predicate"]["finder"]["publicKey"] = ring_json["finder:agent:researcher-1"]
    stmt["predicate"]["channel"]["intakeKey"] = ring_json["platform:cvd.example.org"]
    stmt["predicate"]["history"]["root"] = ref.ledger_root(rotated)
    env = ref.sign_envelope(stmt, [("finder:agent:researcher-1", new)])
    rx = {k: v for k, v in load("reexecution.json").items() if k != "command"} | {"commandDigest": {"sha256": "0" * 64}}

    def anchor(body):
        leaves = [ref.canonical({"n": 1}), ref.canonical(ref.anchor_body(body))]
        return ref.make_inclusion_anchor(body, log="log.example.org", key=lk, leaves=leaves, leaf_index=1, integrated_time="2026-10-30T14:06:00Z")
    incl = ref.make_receipt(env, keyid="platform:cvd.example.org", key=pk, channel="https://cvd.example.org/mcp", received_at="2026-10-30T14:05:00Z", reexecution=rx, anchor_fn=anchor)
    stamp = ref.make_receipt(env, keyid="platform:cvd.example.org", key=pk, channel="https://cvd.example.org/mcp", received_at="2026-10-30T14:05:00Z", reexecution=rx,
                             anchor_log=("log.example.org", lk, "e1", "2026-10-30T14:06:00Z"))
    rev = ref.make_revoke_entry(at="2026-10-01T00:00:00Z", finder_key_hex=hexof(new), operator_keyid="operator:quome.com", operator=op)
    revoked_ring = dict(ring_json); revoked_ring["finder:agent:researcher-1"] = {"public": ring_json["finder:agent:researcher-1"], "revokedAt": "2026-10-30T14:05:30Z"}
    cases = {
        "successor chain": dict(ledger_entries=rotated, receipt=incl),
        "no successor: history dropped": dict(ledger_entries=ledger, receipt=incl),
        "revoke entry": dict(ledger_entries=rotated + [rev], receipt=incl),
        "required entry omitted": dict(ledger_entries=rotated, receipt=incl, required_entries=[ledger[2]]),
        "required entry present": dict(ledger_entries=rotated + [ledger[2]], receipt=incl, required_entries=[ledger[2]]),
        "inclusion anchor required": dict(ledger_entries=rotated, receipt=incl, require_anchor=True),
        "timestamp anchor, inclusion required": dict(ledger_entries=rotated, receipt=stamp, require_anchor=True),
        "timestamp anchor accepted": dict(ledger_entries=rotated, receipt=stamp, require_anchor=True, accept_timestamp_anchor=True),
        "key revoked before the anchor": dict(ledger_entries=rotated, receipt=incl, keyring=revoked_ring),
    }
    for name, kw in cases.items():
        rj = kw.pop("keyring", ring_json)
        theirs = ref.verify(env, ref.Keyring(rj), expectations=load("expectations.json"), report=load("report.json"), leaves=load("leaves.json"),
                            expected_intake="https://cvd.example.org/mcp", quote_verifier=ref.signed_quote_verifier(ref.Keyring(rj)), now_days=T0_DAYS, **kw)
        mine = Verifier(Keyring(rj), platform_keyid="platform:cvd.example.org", expectations=load("expectations.json")).verify(
            env, report=load("report.json"), leaves=load("leaves.json"), expected_intake="https://cvd.example.org/mcp", now_days=T0_DAYS, **kw)
        assert {c.id: (c.ok, c.kind) for p in mine.pillars.values() for c in p.checks} == {c.id: (c.ok, c.kind) for p in theirs.pillars.values() for c in p.checks}, name
        assert mine.verified == theirs.verified, name
    assert ref.successor_chain(rotated, "ed25519:" + hexof(new)) == successor_chain(rotated, "ed25519:" + hexof(new))
    assert ref.missing_entries(rotated, [ledger[2], ledger[3]]) == missing_entries(rotated, [ledger[2], ledger[3]]) == 0
