"""Round-3 review fixes, pinned (spec v1.0, revision 4). Each test is one finding of the third review (a transparency-log
maintainer and the threat-intelligence researcher) against the platform or its verifier. Requirement ids refer to
https://github.com/AAI-Society/vsla/blob/main/spec/v1.0/requirements.md."""

import base64
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qudisclose.demo import demo_reporter, demo_submission
from qudisclose.models import Report, Reporter, ReportSubmission, Source, Status
from qudisclose.security import Identity
from qudisclose.vsla import Keyring, Verifier, canonical, make_inclusion_anchor, make_receipt, verify_anchor
from qudisclose.vsla.dsse import LEDGER_PAYLOAD_TYPE, PAYLOAD_TYPE, anchor_body, envelope_payload, pae, sign_envelope
from qudisclose.vsla.ledger import (ledger_root, ledger_well_formed, make_revoke_entry, make_successor_entry, missing_entries, revocations,
                                    successor_chain, verified_ledger)
from qudisclose.vsla.rubric import trust_score
from tests.test_vsla import _countersigners, _fid, _finder_bundle, _platform, _seed_ledger, _submit

VSLA = next((p for p in (Path(__file__).resolve().parents[2] / "vsla", Path.home() / "Desktop" / "vsla") if (p / "tools" / "vsla_verify.py").exists()), None)


def _check(ver, cid):
    return next(c for c in ver["checks"] if c["id"] == cid)


def _rebundle(forch, title, *, track="finding"):
    """The finder runs another case on its own deployment and hands over a fresh bundle whose history covers everything in
    its mirror for that track (what a finder does after importing the entries platforms returned to it)."""
    rep = Report.from_submission(ReportSubmission(**{**demo_submission().model_dump(), "title": title}), source=Source.MCP, reporter=demo_reporter())
    rep, is_new = forch.intake(rep, actor="agent:researcher-1")
    assert is_new, "a retitled submission must be a new case, or the bundle would be the old statement"
    forch.run_case(rep.id)
    arts = forch.store.artifacts(rep.id)
    repro = arts["reproduction"]
    stmt = arts[f"vsla_{track}"]
    n = envelope_payload(stmt)["predicate"]["transcript"]["leafCount"]
    bundle = {"statement": stmt, "leaves": arts["vsla_leaves"][:n],
              "reproduction": {"test_path": repro["test_path"], "test_source": repro["test_source"], "command": repro["command"]},
              "ledger": forch.ledger.entries(_fid(forch), track)}
    if track == "patch":
        bundle["patch"] = {"diff": arts["patch"]["proposal"]["diff"]}
    return bundle


def _submit_titled(orch, forch, bundle, title, *, identity=None):
    sub = ReportSubmission(**{**demo_submission().model_dump(), "title": title, "attestation": bundle})
    rep = Report.from_submission(sub, source=Source.MCP, reporter=Reporter(identity=identity or forch.attestation_identity.name, public_key=forch.attestation_identity.public_hex))
    rep, is_new = orch.intake(rep, actor=rep.reporter.identity)
    assert is_new
    return rep


def _import_own(forch, platform_orch, track=None):
    """The finder imports the entries a platform countersigned for it (what `get_ledger` returns), pinning that platform."""
    if not forch.keyring.has(platform_orch.ledger.keyid):
        forch.keyring.add(platform_orch.ledger.keyid, platform_orch.platform_identity)
    for e in platform_orch.ledger.own_entries(_fid(forch), track):
        assert forch.ledger.import_entry(_fid(forch), e)


# ----------------------------------------------------------------------------- the ledger index belongs to the finder (VSLA-P-6, P-14)

def test_two_honest_in_flight_cases_at_one_platform_do_not_fork(tmp_path, repo):
    """Round 3 (log maintainer, major 1): two cases submitted before either closed carry the same ledger; neither is a fork,
    and the platform's two entries carry no index."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch, url="http://finder.example/mcp")
    rep1 = _submit_titled(orch, forch, bundle, "First finding: path traversal in resolve_path")
    rep2 = _submit_titled(orch, forch, bundle, "Second finding, submitted before the first closed")
    orch.run_case(rep1.id); orch.run_case(rep2.id)
    for rep in (rep1, rep2):
        ver = store.get_artifact(rep.id, "vsla_verification")
        assert _check(ver, "I4")["ok"], (rep.id, _check(ver, "I4")["detail"])
        assert ver["pillars"]["identity"]["level"] == 2        # (the retitled copy fails E3 on purpose: it is the same statement; Identity is what this test is about)
    own = orch.ledger.own_entries(_fid(forch), "finding")
    assert [envelope_payload(e)["outcome"] for e in own] == ["accepted", "accepted"] and all("seq" not in envelope_payload(e) for e in own)
    assert orch.ledger.last_seen(_fid(forch), "finding") == (ledger_root(bundle["ledger"]), 5)
    # a third submission after both closed must include both entries; the finder appends them in its own order
    _import_own(forch, orch, "finding")
    bundle3 = _rebundle(forch, "Third finding, after both closed")
    assert len(bundle3["ledger"]) == 7 and ledger_well_formed(bundle3["ledger"])[0]
    rep3 = _submit_titled(orch, forch, bundle3, "Third finding, after both closed")
    orch.run_case(rep3.id)
    assert _check(store.get_artifact(rep3.id, "vsla_verification"), "I4")["ok"]
    assert orch.ledger.last_seen(_fid(forch), "finding") == (ledger_root(bundle3["ledger"]), 7)


def test_a_finder_using_two_platforms_satisfies_both(tmp_path, repo):
    """Round 3 (log maintainer, major 1): platforms A and B each close a case for the same finder; the finder presents
    P + A + B to both; each finds its shown prefix intact and its own entry included."""
    cfg_a, store_a, A = _platform(tmp_path, repo, "A", url="http://a.example/mcp")
    cfg_b, store_b, B = _platform(tmp_path, repo, "B", url="http://b.example/mcp")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, A, url="http://finder.example/mcp")
    for kid, k in cs:
        B.keyring.add(kid, k)
    ra = _submit_titled(A, forch, bundle, "Finding at A"); A.run_case(ra.id)
    rb = _submit_titled(B, forch, bundle, "Finding at B"); B.run_case(rb.id)
    assert _check(store_a.get_artifact(ra.id, "vsla_verification"), "I4")["ok"] and _check(store_b.get_artifact(rb.id, "vsla_verification"), "I4")["ok"]
    _import_own(forch, A, "finding"); _import_own(forch, B, "finding")
    bundle2 = _rebundle(forch, "Second round, ledger P+A+B")
    assert len(bundle2["ledger"]) == 7
    ra2 = _submit_titled(A, forch, bundle2, "Second at A"); A.run_case(ra2.id)
    rb2 = _submit_titled(B, forch, bundle2, "Second at B"); B.run_case(rb2.id)
    for store, rep in ((store_a, ra2), (store_b, rb2)):
        i4 = _check(store.get_artifact(rep.id, "vsla_verification"), "I4")
        assert i4["ok"], i4["detail"]
    # a ledger that drops everything B wrote is a fork at B (B has closed two cases by now) and fine at A
    b_own = B.ledger.own_entries(_fid(forch), "finding")
    without_b = [e for e in bundle2["ledger"] if e not in b_own]
    assert len(b_own) == 2 and missing_entries(without_b, b_own) == 2
    a_own = A.ledger.own_entries(_fid(forch), "finding")
    assert len(a_own) == 2 and missing_entries(without_b, a_own[:1]) == 0 and missing_entries(without_b, a_own) == 1   # A's second entry postdates bundle2


def test_per_track_finder_survives_a_patch_close(tmp_path, repo):
    """Round 3 (log maintainer, major 5): a Patch-track close writes the finding entry under (key, finding) and the patch
    entry under (key, patch); a finder that keeps one ledger per track includes each in its own ledger."""
    from qudisclose.demo import demo_provider
    cfg, store, orch = _platform(tmp_path, repo, "platform", reviewer_provider=demo_provider())
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch, track="patch", url="http://finder.example/mcp")
    assert {envelope_payload(e)["track"] for e in bundle["ledger"]} == {"patch"}
    rep = _submit(orch, forch, bundle)
    r = orch.run_case(rep.id)
    assert r.status == Status.CLOSED
    fid = _fid(forch)
    assert [envelope_payload(e)["outcome"] for e in orch.ledger.own_entries(fid, "patch")] == ["accepted"]
    assert [envelope_payload(e)["outcome"] for e in orch.ledger.own_entries(fid, "finding")] == ["accepted"]
    assert orch.ledger.last_seen(fid, "patch") == (ledger_root(bundle["ledger"]), 5) and orch.ledger.last_seen(fid, "finding") is None
    _import_own(forch, orch)
    patch_ledger = forch.ledger.entries(fid, "patch")
    assert len(patch_ledger) == 6 and {envelope_payload(e)["track"] for e in patch_ledger} == {"patch"}
    bundle2 = _rebundle(forch, "Second patch", track="patch")
    rep2 = _submit_titled(orch, forch, bundle2, "Second patch")
    orch.run_case(rep2.id)
    i4 = _check(store.get_artifact(rep2.id, "vsla_verification"), "I4")
    assert i4["ok"], i4["detail"]


def test_stale_ledger_under_a_second_name_for_the_same_key_forks(tmp_path, repo):
    """Round 3 (log maintainer, major 5): ledger state is keyed by the finder's key, not the reporter name."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    rep2 = _submit_titled(orch, forch, bundle, "Same key, new name, stale ledger", identity="agent:alias")
    orch.run_case(rep2.id)
    i4 = _check(store.get_artifact(rep2.id, "vsla_verification"), "I4")
    assert not i4["ok"] and "omits 1 entry" in i4["detail"]
    forks = [envelope_payload(e) for e in orch.ledger.entries(_fid(forch)) if envelope_payload(e)["outcome"] == "ledger-fork"]
    assert len(forks) == 1 and forks[0]["finder"] == _fid(forch)


def test_deferred_submission_is_not_an_over_claim(tmp_path, repo):
    """Round 3 (log maintainer, major 6a): a not-attempted receipt leaves claimed/verified out of the close entry."""
    cfg, store, orch = _platform(tmp_path, repo, "platform", reexec_per_identity_per_hour=0)
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    assert envelope_payload(store.get_artifact(rep.id, "vsla_receipt"))["reexecution"]["status"] == "not-attempted"
    own = [envelope_payload(e) for e in orch.ledger.own_entries(_fid(forch), "finding")]
    assert [e["outcome"] for e in own] == ["accepted"] and "claimed" not in own[0] and "verified" not in own[0]
    assert orch.ledger.score(_fid(forch), "finding")["over_claims"] == 0


# ----------------------------------------------------------------------------- one evaluation instant (VSLA-V-7, F-20)

def _anchored_receipt(orch, cfg, stmt, rx, *, received_at, anchor_at, log):
    def fn(body):
        leaves = [canonical({"n": 1}), canonical(anchor_body(body))]
        return make_inclusion_anchor(body, log="test-log", key=log, leaves=leaves, leaf_index=1, integrated_time=anchor_at)
    return make_receipt(stmt, platform=orch.platform_identity, keyid=orch.ledger.keyid, channel=cfg.public_url, received_at=received_at, reexecution=rx, anchor_fn=fn)


def _rx_for(stmt):
    rev = envelope_payload(stmt)["subject"][1]["digest"]["gitCommit"]
    return {"status": "matched", "revision": rev, "observedExit": 1, "securityFailure": True, "touchedSubject": True, "sandbox": {"backend": "quome", "isolation": "vm"}}


def test_key_windows_and_revocations_are_evaluated_at_t_eval(tmp_path, repo):
    """VSLA-V-7 / F-20: the finder key is judged at the anchor's time (else the receipt's, else now), never at the
    finder-written finishedAt; an operator-signed revoke entry in the ledger ends the key; one signed by a log key is ignored."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    log = Identity.generate("log:test-log"); orch.keyring.add("log:test-log", log)
    orch.keyring.add(f"finder:{forch.attestation_identity.name}", forch.attestation_identity)
    stmt = bundle["statement"]
    fin = envelope_payload(stmt)["predicate"]["timestamps"]["finishedAt"]
    now = datetime.now(UTC)
    rc = _anchored_receipt(orch, cfg, stmt, _rx_for(stmt), received_at=(now + timedelta(seconds=1)).isoformat(), anchor_at=(now + timedelta(seconds=2)).isoformat(), log=log)
    kid = f"finder:{forch.attestation_identity.name}"
    good = Verifier(orch.keyring, platform_keyid=orch.ledger.keyid, expectations=orch.expectations)
    res = good.verify(stmt, receipt=rc, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    assert res.verified == 2 and "t_eval=" in res.detail("I1")
    # revoked by keyring window after finishedAt but before the anchor: fails at t_eval
    ring = Keyring(orch.keyring.to_dict()); ring.add(kid, {"public": forch.attestation_identity.public_hex, "revokedAt": (datetime.fromisoformat(fin.replace("Z", "+00:00")) + timedelta(seconds=1)).isoformat()})
    res = Verifier(ring, platform_keyid=orch.ledger.keyid, expectations=orch.expectations).verify(stmt, receipt=rc, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    assert res.verified == 0 and not res.ok("I1") and "revoked" in res.detail("I1")
    # revoked by an operator-signed revoke entry
    op = Identity.generate("operator:quome.com"); orch.keyring.add("operator:quome.com", op)
    rev = make_revoke_entry(at=(now - timedelta(days=1)).isoformat(), finder_key_hex=forch.attestation_identity.public_hex, operator_keyid="operator:quome.com", operator=op, reason="laptop stolen")
    res = good.verify(stmt, receipt=rc, ledger_entries=bundle["ledger"] + [rev], expected_intake=cfg.public_url)
    assert not res.ok("I1") and "operator:quome.com" in res.detail("I1")
    assert revocations(bundle["ledger"] + [rev], orch.keyring, [_fid(forch)]) and revocations(bundle["ledger"] + [rev], orch.keyring, ["ed25519:" + "ab" * 32]) == []
    # a revoke dated after t_eval does not apply yet; one signed by a non-operator key is ignored
    late = make_revoke_entry(at=(now + timedelta(days=1)).isoformat(), finder_key_hex=forch.attestation_identity.public_hex, operator_keyid="operator:quome.com", operator=op)
    assert good.verify(stmt, receipt=rc, ledger_entries=bundle["ledger"] + [late], expected_intake=cfg.public_url).ok("I1")
    from qudisclose.vsla.dsse import dsse_sign
    bogus = dsse_sign({"kind": "revoke", "at": (now - timedelta(days=1)).isoformat(), "finder": _fid(forch), "revokedBy": "log:test-log"}, LEDGER_PAYLOAD_TYPE, [("log:test-log", log)])
    assert revocations([bogus], orch.keyring, [_fid(forch)]) == []
    # the time chain: finishedAt after receivedAt fails I3 (and E7); finishedAt in the future fails E3
    early = make_receipt(stmt, platform=orch.platform_identity, keyid=orch.ledger.keyid, channel=cfg.public_url,
                         received_at=(datetime.fromisoformat(fin.replace("Z", "+00:00")) - timedelta(seconds=1)).isoformat(), reexecution=_rx_for(stmt))
    res = good.verify(stmt, receipt=early, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    assert not res.ok("I3") and not res.ok("E7")


def test_rubric_is_evaluated_at_t_eval_not_the_verifier_clock(tmp_path, repo):
    """VSLA-V-7: the same anchored statement verifies identically today and in ninety days."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    log = Identity.generate("log:test-log"); orch.keyring.add("log:test-log", log)
    orch.keyring.add(f"finder:{forch.attestation_identity.name}", forch.attestation_identity)
    stmt = bundle["statement"]; now = datetime.now(UTC)
    rc = _anchored_receipt(orch, cfg, stmt, _rx_for(stmt), received_at=(now + timedelta(seconds=1)).isoformat(), anchor_at=(now + timedelta(seconds=2)).isoformat(), log=log)
    v = Verifier(orch.keyring, platform_keyid=orch.ledger.keyid, expectations=orch.expectations, require_anchor=True)
    a = v.verify(stmt, receipt=rc, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url, now_days=now.timestamp() / 86400)
    b = v.verify(stmt, receipt=rc, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url, now_days=now.timestamp() / 86400 + 90)
    assert a.verified == b.verified == 2 and a.detail("I4") == b.detail("I4") and "log-inclusion in test-log" in a.detail("I3")


def test_successor_chain_keeps_history(tmp_path, repo):
    """VSLA-F-20: outcomes earned under the old key count for the new key through a two-signature successor entry."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    old, new = forch.attestation_identity, Identity.generate("agent:rotated")
    rot = make_successor_entry(at=datetime.now(UTC).isoformat(), old=old, new=new, old_keyid=f"finder:{old.name}")
    assert successor_chain(bundle["ledger"] + [rot], f"ed25519:{new.public_hex}") == [f"ed25519:{new.public_hex}", _fid(forch)]
    kept, dropped = verified_ledger(bundle["ledger"] + [rot], orch.keyring, finder=successor_chain(bundle["ledger"] + [rot], f"ed25519:{new.public_hex}"))
    assert len(kept) == 5 and dropped == 0
    assert verified_ledger(bundle["ledger"], orch.keyring, finder=f"ed25519:{new.public_hex}")[0] == []
    # a successor entry without the new key's signature proves nothing
    from qudisclose.vsla.dsse import dsse_sign
    half = dsse_sign(envelope_payload(rot), LEDGER_PAYLOAD_TYPE, [(f"finder:{old.name}", old)])
    assert successor_chain(bundle["ledger"] + [half], f"ed25519:{new.public_hex}") == [f"ed25519:{new.public_hex}"]
    # a statement signed by the new key, with the rotated ledger, keeps the history (I4 counts a chain of 2 keys)
    s = envelope_payload(bundle["statement"]); s["predicate"]["finder"]["publicKey"] = f"ed25519:{new.public_hex}"
    rotated = bundle["ledger"] + [rot]
    s["predicate"]["history"]["root"] = ledger_root(rotated)
    env = sign_envelope(s, [(f"finder:{old.name}", new)])
    ring = Keyring(orch.keyring.to_dict()); ring.add(f"finder:{old.name}", new)
    res = Verifier(ring, platform_keyid=orch.ledger.keyid, expectations=orch.expectations).verify(env, ledger_entries=rotated, expected_intake=cfg.public_url)
    assert res.ok("I4") and "chain of 2 key(s)" in res.detail("I4") and "0 outcome entries dropped" in res.detail("I4")


# ----------------------------------------------------------------------------- DSSE and depth (VSLA-F-1, V-3)

def test_junk_signature_does_not_veto_a_valid_one(tmp_path, repo):
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    orch.keyring.add(f"finder:{forch.attestation_identity.name}", forch.attestation_identity)
    stmt = dict(bundle["statement"])
    stmt["signatures"] = [{"keyid": stmt["signatures"][0]["keyid"], "sig": base64.b64encode(b"A" * 64).decode()}, *stmt["signatures"]]
    assert orch.verifier.verify(stmt, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url).ok("E2")


def test_deeply_nested_or_oversized_payload_fails_a_check(tmp_path, repo):
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    orch.keyring.add(f"finder:{forch.attestation_identity.name}", forch.attestation_identity)
    deep = {"payloadType": LEDGER_PAYLOAD_TYPE, "payload": base64.b64encode(("[" * 100000 + "]" * 100000).encode()).decode(), "signatures": [{"keyid": orch.ledger.keyid, "sig": "AA=="}]}
    res = orch.verifier.verify(bundle["statement"], ledger_entries=bundle["ledger"] + [deep], expected_intake=cfg.public_url)
    assert not res.ok("I4") and "not a canonical" in res.detail("I4")
    big = {**deep, "payload": base64.b64encode(b'"' + b"x" * (4 * 1024 * 1024 + 1) + b'"').decode()}
    assert not orch.verifier.verify(bundle["statement"], ledger_entries=bundle["ledger"] + [big], expected_intake=cfg.public_url).ok("I4")


# ----------------------------------------------------------------------------- anchors (VSLA-P-16)

def test_log_inclusion_anchor_roundtrip_and_tamper(tmp_path, repo):
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    log = Identity.generate("log:test-log"); orch.keyring.add("log:test-log", log)
    orch.keyring.add(f"finder:{forch.attestation_identity.name}", forch.attestation_identity)
    stmt = bundle["statement"]; now = datetime.now(UTC)
    rc = _anchored_receipt(orch, cfg, stmt, _rx_for(stmt), received_at=(now + timedelta(seconds=1)).isoformat(), anchor_at=(now + timedelta(seconds=2)).isoformat(), log=log)
    body = envelope_payload(rc)
    ok, form, why = verify_anchor(body, orch.keyring)
    assert ok and form == "log-inclusion" and body["anchor"]["treeSize"] == 2 and body["anchor"]["leafIndex"] == 1
    tampered = json.loads(json.dumps(body)); tampered["anchor"]["inclusionProof"][0][1] = "0" * 64
    assert verify_anchor(tampered, orch.keyring)[0] is False and "inclusion proof" in verify_anchor(tampered, orch.keyring)[2]
    strict = Verifier(orch.keyring, platform_keyid=orch.ledger.keyid, expectations=orch.expectations, require_anchor=True)
    assert strict.verify(stmt, receipt=rc, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url).verified == 2


# ----------------------------------------------------------------------------- embargo (VSLA-P-13) and admission (VSLA-P-12)

def test_embargoed_statement_names_no_repository(env):
    """The embargoed profile's subject[1].name is a digest of the repository URL; the published profile keeps the URL."""
    from tests.conftest import new_report
    cfg, store, audit, provider, orch = env
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    orch.run_case(rep.id)
    arts = store.artifacts(rep.id)
    emb, pub = envelope_payload(arts["vsla_finding"]), envelope_payload(arts["vsla_finding_published"])
    assert emb["subject"][1]["name"].startswith("repo:sha256:") and pub["subject"][1]["name"].startswith("git+https://github.com/")
    assert emb["subject"][1]["digest"]["gitCommit"] == pub["subject"][1]["digest"]["gitCommit"]


async def test_audit_trail_postmortem_and_advisory_are_withheld_while_embargoed(env):
    """Round 3 (threat-intel, major 1): every read surface is gated by VSLA-P-13, not only the status summary."""
    import json as _json
    from mcp import Client
    from tests.conftest import new_report
    from tests.test_vsla import _server
    cfg, store, audit, provider, orch = env
    current = {"identity": "agent:researcher-1", "scopes": {"report:read"}}
    mcp = _server(cfg, orch, audit, current)
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    async with Client(mcp) as c:
        mine = (await c.call_tool("get_audit_trail", {"query": {"report_id": rep.id}})).structured_content
        assert "entries" in mine and mine["entries"]
        current["identity"] = "agent:researcher-2"
        for tool in ("get_audit_trail", "get_postmortem", "get_advisory"):
            out = (await c.call_tool(tool, {"query": {"report_id": rep.id}})).structured_content
            assert out["embargoed"] is True and "entries" not in out and "postmortem" not in out and "advisory" not in out and "fixed_version" not in out, tool
        current["scopes"] = {"report:read", "report:admin"}
        assert "entries" in (await c.call_tool("get_audit_trail", {"query": {"report_id": rep.id}})).structured_content
        current["scopes"] = {"report:read"}
        orch.run_case(rep.id)
        assert "entries" in (await c.call_tool("get_audit_trail", {"query": {"report_id": rep.id}})).structured_content


def test_a_free_duplicate_does_not_admit_an_unknown_identity(tmp_path, repo):
    """Round 3 (threat-intel, major 2): a byte-identical resubmission earns a neutral `duplicate`, which counts for nothing
    toward admission; only non-neutral verified entries make an identity known (VSLA-P-12)."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    assert store.get_report(rep.id).classification == "public"
    stranger = Identity.generate("agent:stranger")
    copy = Report.from_submission(ReportSubmission(**{**demo_submission().model_dump(), "attestation": bundle}), source=Source.MCP,
                                  reporter=Reporter(identity="agent:stranger", public_key=stranger.public_hex))
    dup, is_new = orch.intake(copy, actor="agent:stranger")
    assert not is_new and dup.id == rep.id
    free = orch.ledger.entries(f"ed25519:{stranger.public_hex}")
    assert [envelope_payload(e)["outcome"] for e in free] == ["duplicate"]
    # the stranger now presents that one platform-countersigned entry as its history
    forch2, bundle2, _ = _finder_bundle(tmp_path, repo, orch, with_history=False)
    bundle2["ledger"] = free
    rep2 = Report.from_submission(ReportSubmission(**{**demo_submission().model_dump(), "title": "Stranger's own finding, admitted on a free duplicate?", "attestation": bundle2}),
                                  source=Source.MCP, reporter=Reporter(identity="agent:stranger2", public_key=forch2.attestation_identity.public_hex))
    rep2, _ = orch.intake(rep2, actor="agent:stranger2")
    assert orch._verified_presented(rep2) == 0
    orch.run_case(rep2.id)
    assert envelope_payload(store.get_artifact(rep2.id, "vsla_receipt"))["reexecution"]["status"] == "not-attempted"


# ----------------------------------------------------------------------------- the schema copy

@pytest.mark.skipif(VSLA is None, reason="sibling vsla checkout not found")
def test_schema_copy_is_byte_identical_to_the_reference():
    mine = Path(__file__).resolve().parents[1] / "src" / "qudisclose" / "vsla" / "vsla-provenance-v1.schema.json"
    assert mine.read_bytes() == (VSLA / "schema" / "vsla-provenance-v1.schema.json").read_bytes()
