"""DSSE envelopes for every signed VSLA object (spec: provenance.md). The statement (in-toto Statement v1), the
platform receipt, each ledger entry and a provider's weight attestation are all `dsse_sign(body, payload_type,
signers)`: Ed25519 over PAE(payloadType, canonical body), each with its own payload type so a signature over one
kind of object can never be replayed as another (VSLA-F-1, VSLA-P-3). A receipt may carry an anchor (VSLA-P-16) in one
of two forms: `signed-timestamp` (a pinned `log:<name>` key's timestamp over the anchor-less receipt body: proof the body
existed by `integratedTime`, on that key's word) or `log-inclusion` (the body is a leaf of an RFC 6962 log; the anchor
carries the log's signed checkpoint and the inclusion proof). Verification accepts any verifying signature under a keyid
(DSSE semantics), so a junk signature beside a valid one does not veto it."""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, Callable

from qudisclose.security.keys import Identity
from qudisclose.vsla.canonical import canonical, parse_canonical, sha256_hex
from qudisclose.vsla.merkle import inclusion_proof, merkle_root, verify_inclusion

if TYPE_CHECKING:
    from qudisclose.vsla.keyring import Keyring

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://vsla.dev/provenance/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
RECEIPT_PAYLOAD_TYPE = "application/vnd.vsla.receipt+json"
LEDGER_PAYLOAD_TYPE = "application/vnd.vsla.ledger-entry+json"
WEIGHTS_PAYLOAD_TYPE = "application/vnd.vsla.weights-attestation+json"
TIMESTAMP_PAYLOAD_TYPE = "application/vnd.vsla.receipt-timestamp+json"
CHECKPOINT_PAYLOAD_TYPE = "application/vnd.vsla.log-checkpoint+json"
ANCHOR_PAYLOAD_TYPE = TIMESTAMP_PAYLOAD_TYPE    # the signed-timestamp form
CLOCK_SKEW_S = 600.0       # a receipt or anchor may be at most this far ahead of the verifier's clock


def pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def statement(subject: list[dict[str, Any]], predicate: dict[str, Any]) -> dict[str, Any]:
    return {"_type": STATEMENT_TYPE, "subject": subject, "predicateType": PREDICATE_TYPE, "predicate": predicate}


def dsse_sign(body: dict[str, Any], payload_type: str, signers: list[tuple[str, Identity]]) -> dict[str, Any]:
    """A DSSE envelope over the canonical body, signed by each (keyid, identity)."""
    payload = canonical(body)
    return {"payloadType": payload_type, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": kid, "sig": base64.b64encode(ident.sign(pae(payload_type, payload))).decode()} for kid, ident in signers]}


def sign_envelope(stmt: dict[str, Any], signers: list[tuple[str, Identity]]) -> dict[str, Any]:
    return dsse_sign(stmt, PAYLOAD_TYPE, signers)


def add_signature(envelope: dict[str, Any], keyid: str, ident: Identity) -> dict[str, Any]:
    payload = base64.b64decode(envelope["payload"])
    return {**envelope, "signatures": [*envelope["signatures"], {"keyid": keyid, "sig": base64.b64encode(ident.sign(pae(envelope["payloadType"], payload))).decode()}]}


def envelope_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    """The parsed payload. Lenient (any JSON); `canonical_payload` is the strict form the verifier uses."""
    return json.loads(base64.b64decode(envelope["payload"]))


def canonical_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    """The payload, which MUST be RFC 8785 canonical with no duplicate keys. Raises ValueError otherwise."""
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("envelope has no decodable payload") from exc
    obj = parse_canonical(raw)
    if not isinstance(obj, dict):
        raise ValueError("payload is not an object")
    return obj


def statement_digest(envelope: dict[str, Any]) -> str:
    return sha256_hex(base64.b64decode(envelope["payload"]))


def signer_keyids(envelope: dict[str, Any]) -> list[str]:
    return [s.get("keyid", "") for s in envelope.get("signatures", []) if isinstance(s, dict)]


def verify_signature(envelope: dict[str, Any], keyid: str, ident: Identity, payload_type: str | None = None) -> bool:
    """True iff some signature with `keyid` verifies over PAE(payloadType, payload) and the payload type is as expected."""
    try:
        if payload_type is not None and envelope.get("payloadType") != payload_type:
            return False
        payload = base64.b64decode(envelope["payload"])
    except Exception:
        return False
    for s in envelope.get("signatures", []):
        if not isinstance(s, dict) or s.get("keyid") != keyid:
            continue
        try:
            if ident.verify(base64.b64decode(s["sig"]), pae(envelope["payloadType"], payload)):
                return True
        except Exception:
            continue
    return False


def _ts(v: Any) -> float | None:
    """ISO-8601 (or epoch seconds) to epoch seconds, or None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


# receipts and anchors --------------------------------------------------------

def anchor_body(receipt_body: dict[str, Any]) -> dict[str, Any]:
    """What a log witnesses: the receipt body without its own anchor."""
    return {k: v for k, v in receipt_body.items() if k != "anchor"}


def make_anchor(receipt_body: dict[str, Any], *, log: str, key: Identity, entry_id: str, integrated_time: str) -> dict[str, Any]:
    """The `signed-timestamp` form, identical to the reference verifier's: proof that this receipt body existed by
    `integratedTime` on the word of the pinned log key; nothing about append-only-ness."""
    body = {"log": log, "entryId": entry_id, "integratedTime": integrated_time, "receipt": {"sha256": sha256_hex(canonical(anchor_body(receipt_body)))}}
    sig = key.sign(pae(TIMESTAMP_PAYLOAD_TYPE, canonical(body)))
    return {"form": "signed-timestamp", **body, "signature": base64.b64encode(sig).decode()}


make_timestamp_anchor = make_anchor


def checkpoint_body(log: str, tree_size: int, root_hash: str, integrated_time: str) -> dict[str, Any]:
    return {"log": log, "treeSize": tree_size, "rootHash": root_hash, "integratedTime": integrated_time}


def make_inclusion_anchor(receipt_body: dict[str, Any], *, log: str, key: Identity, leaves: list[bytes], leaf_index: int,
                          integrated_time: str) -> dict[str, Any]:
    """The `log-inclusion` form: the canonical anchor-less receipt body is a leaf of an RFC 6962 log; the anchor carries the
    log's signed checkpoint (tree size, root hash, time) and the inclusion proof for the leaf."""
    leaf = canonical(anchor_body(receipt_body))
    if leaves[leaf_index] != leaf:
        raise ValueError("leaf_index does not point at this receipt")
    root = merkle_root(leaves)
    cp = checkpoint_body(log, len(leaves), root, integrated_time)
    sig = key.sign(pae(CHECKPOINT_PAYLOAD_TYPE, canonical(cp)))
    return {"form": "log-inclusion", "log": log, "treeSize": len(leaves), "rootHash": root, "leafIndex": leaf_index,
            "inclusionProof": [[side, h] for side, h in inclusion_proof(leaves, leaf_index)], "integratedTime": integrated_time,
            "checkpointSignature": base64.b64encode(sig).decode()}


def verify_anchor(receipt_body: dict[str, Any], keyring: "Keyring", *, now_s: float | None = None) -> tuple[bool, str, str]:
    """(ok, form, why), identical to the reference: the anchor verifies under the pinned `log:<name>` key, commits to this
    receipt body, and its integratedTime is not before receivedAt nor ahead of the verifier's clock."""
    anc = receipt_body.get("anchor")
    if not isinstance(anc, dict):
        return False, "none", "no anchor"
    form = str(anc.get("form") or ("log-inclusion" if "inclusionProof" in anc else "signed-timestamp"))
    try:
        pub = keyring.get(f"log:{anc.get('log')}", at=anc.get("integratedTime"))
        if pub is None:
            return False, form, f"log {anc.get('log')!r} not pinned"
        leaf = canonical(anchor_body(receipt_body))
        if form == "log-inclusion":
            proof = [(str(side), str(h)) for side, h in anc["inclusionProof"]]
            if not verify_inclusion(leaf, proof, str(anc["rootHash"])):
                return False, form, "inclusion proof does not reach the checkpoint root for this receipt"
            cp = checkpoint_body(str(anc["log"]), int(anc["treeSize"]), str(anc["rootHash"]), str(anc["integratedTime"]))
            if not pub.verify(base64.b64decode(anc["checkpointSignature"]), pae(CHECKPOINT_PAYLOAD_TYPE, canonical(cp))):
                return False, form, "anchor signature or proof invalid"
        elif form == "signed-timestamp":
            body = {k: anc[k] for k in ("log", "entryId", "integratedTime", "receipt")}
            if body["receipt"] != {"sha256": sha256_hex(leaf)}:
                return False, form, "timestamp commits to a different receipt"
            if not pub.verify(base64.b64decode(anc["signature"]), pae(TIMESTAMP_PAYLOAD_TYPE, canonical(body))):
                return False, form, "anchor signature or proof invalid"
        else:
            return False, form, f"unknown anchor form {form!r}"
    except Exception:
        return False, form, "anchor signature or proof invalid"
    t_int, t_rcv = _ts(anc.get("integratedTime")), _ts(receipt_body.get("receivedAt"))
    now = time.time() if now_s is None else now_s
    if t_int is None or t_rcv is None or t_int < t_rcv or t_int > now + CLOCK_SKEW_S:
        return False, form, "anchor time is before receipt or in the future"
    return True, form, f"{form} in {anc.get('log')}"


def make_receipt(envelope: dict[str, Any], *, platform: Identity, keyid: str, channel: str, received_at: str,
                 reexecution: dict[str, Any] | None, anchor: dict[str, Any] | None = None,
                 anchor_log: tuple[str, Identity, str, str] | None = None,
                 anchor_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None) -> dict[str, Any]:
    """VSLA-P-3/P-4: the platform's countersignature, a DSSE envelope with the receipt payload type over
    {vslaVersion, statementDigest, channel, receivedAt, reexecution, anchor?}. A receipt is issued in every case;
    `reexecution.status` says what the platform did (`not-attempted` when it did nothing). `anchor_log = (log name,
    log Identity, entry id, integrated time)` produces a signed-timestamp over the body; `anchor_fn(body)` any other form."""
    body: dict[str, Any] = {"vslaVersion": "1.0", "statementDigest": statement_digest(envelope), "channel": channel, "receivedAt": received_at,
                            "reexecution": reexecution or {"status": "not-attempted"}}
    if anchor_fn is not None:
        anchor = anchor_fn(body)
    elif anchor_log is not None:
        log, lkey, entry_id, at = anchor_log
        anchor = make_anchor(body, log=log, key=lkey, entry_id=entry_id, integrated_time=at)
    if anchor:
        body["anchor"] = anchor
    return dsse_sign(body, RECEIPT_PAYLOAD_TYPE, [(keyid, platform)])


def verify_receipt(receipt: dict[str, Any], keyid: str, ident: Identity) -> bool:
    return verify_signature(receipt, keyid, ident, RECEIPT_PAYLOAD_TYPE)


def receipt_body(receipt: dict[str, Any]) -> dict[str, Any]:
    return envelope_payload(receipt)


# weight attestations ---------------------------------------------------------

def make_weights_attestation(body: dict[str, Any], keyid: str, provider: Identity) -> dict[str, Any]:
    """Provider-signed attestation over base weights: {model, weights: {sha256}, quantization?, issuedAt}."""
    return dsse_sign(body, WEIGHTS_PAYLOAD_TYPE, [(keyid, provider)])
