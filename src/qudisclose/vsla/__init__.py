"""VSLA (Vulnerability-disclosure Supply-chain Levels for Agents) in qudisclose.

Spec: https://github.com/AAI-Society/vsla (spec/v1.0, revision 4). qudisclose is both a finder (it emits Finding and
Patch statements for every case it verifies) and a disclosure platform (it verifies statements a reporter submits,
re-executes the reproduction at the subject revision with its own classifier, signs a DSSE receipt, and keeps the
reporter's countersigned trust ledger).

  canonical.py    RFC 8785 canonical JSON, byte-identical to the reference verifier (VSLA-F-1)
  merkle.py       RFC 6962 tree over transcript leaves (VSLA-F-4)
  dsse.py         DSSE envelopes: statement, receipt, ledger entry, weight attestation (VSLA-F-1, VSLA-P-3)
  keyring.py      pinned keys with validity windows (VSLA-V-1, VSLA-F-20)
  transcript.py   records every model turn and tool call as a leaf, per case
  attest.py       builds and signs Finding / Patch statements in both profiles (VSLA-F-*)
  ledger.py       countersigned outcomes per (finder key, track) as DSSE entries; shown roots; successor/revoke (VSLA-P-6, P-14, P-15, F-20)
  rubric.py       the trust rubric v1.1 (trust-rubric.md)
  environment.py  Environment-pillar adapters (VSLA-F-15..17, VSLA-P-8)
  verify.py       the verification procedure: claimed -> verified level (verification.md)
"""

from qudisclose.vsla.attest import Attestor, MBOMEntry, diff_paths, model_family, non_source_paths, non_text_changes, scope_of
from qudisclose.vsla.canonical import canonical, parse_canonical, sha256_hex
from qudisclose.vsla.dsse import (
    ANCHOR_PAYLOAD_TYPE, CHECKPOINT_PAYLOAD_TYPE, LEDGER_PAYLOAD_TYPE, PAYLOAD_TYPE, RECEIPT_PAYLOAD_TYPE, TIMESTAMP_PAYLOAD_TYPE,
    WEIGHTS_PAYLOAD_TYPE, canonical_payload, dsse_sign, envelope_payload, make_anchor, make_inclusion_anchor, make_receipt,
    make_timestamp_anchor, sign_envelope, statement_digest, verify_anchor, verify_receipt, verify_signature,
)
from qudisclose.vsla.environment import EnvironmentAttestor, NoEnvironment, SignedQuoteEnvironment
from qudisclose.vsla.keyring import Keyring
from qudisclose.vsla.ledger import (Ledger, finder_id, ledger_root, ledger_well_formed, make_ledger_entry, make_revoke_entry, make_successor_entry,
                                    missing_entries, revocations, successor_chain, verified_ledger)
from qudisclose.vsla.merkle import inclusion_proof, leaf_bytes, merkle_root, verify_inclusion
from qudisclose.vsla.rubric import countersigner_operator, meets_floor, trust_score
from qudisclose.vsla.transcript import RecordingProvider, TranscriptRecorder
from qudisclose.vsla.verify import VerificationResult, Verifier, vsla_keyring

__all__ = ["Attestor", "MBOMEntry", "diff_paths", "model_family", "non_source_paths", "non_text_changes", "scope_of", "canonical", "parse_canonical", "sha256_hex",
           "ANCHOR_PAYLOAD_TYPE", "CHECKPOINT_PAYLOAD_TYPE", "LEDGER_PAYLOAD_TYPE", "PAYLOAD_TYPE", "RECEIPT_PAYLOAD_TYPE", "TIMESTAMP_PAYLOAD_TYPE",
           "WEIGHTS_PAYLOAD_TYPE", "canonical_payload", "dsse_sign", "envelope_payload", "make_anchor", "make_inclusion_anchor", "make_receipt",
           "make_timestamp_anchor", "sign_envelope", "statement_digest", "verify_anchor", "verify_receipt", "verify_signature",
           "EnvironmentAttestor", "NoEnvironment", "SignedQuoteEnvironment", "Keyring", "Ledger", "finder_id", "ledger_root", "ledger_well_formed",
           "make_ledger_entry", "make_revoke_entry", "make_successor_entry", "missing_entries", "revocations", "successor_chain", "verified_ledger", "inclusion_proof", "leaf_bytes", "merkle_root", "verify_inclusion", "countersigner_operator", "meets_floor", "trust_score",
           "RecordingProvider", "TranscriptRecorder", "VerificationResult", "Verifier", "vsla_keyring"]
