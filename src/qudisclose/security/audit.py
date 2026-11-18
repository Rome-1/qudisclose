"""Tamper-evident audit trail: hash-chained, Ed25519-signed entries that record inputs AND outputs.

Append-only, in the same database as everything else; the chain can be re-verified at any time with
`verify_chain()`. The agents never hold the audit signing key. The read-prev-hash-then-insert runs in
one backend transaction (the backend holds its lock for the whole block) so concurrent writers across
the server's event loop and the pipeline threads cannot fork the chain.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from qudisclose.db import SERIAL, Backend
from qudisclose.models import canonical_json, sha256_hex
from qudisclose.security.keys import Identity
from qudisclose.security.scanner import Redactor

GENESIS = "0" * 64

AUDIT_DDL = f"""CREATE TABLE IF NOT EXISTS audit (
    seq {SERIAL},
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    report_id TEXT,
    input TEXT NOT NULL,
    output TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    sig TEXT NOT NULL
)"""


class AuditLog:
    def __init__(self, backend: Backend, signer: Identity, redactor: Redactor | None = None) -> None:
        self._db = backend
        self._signer = signer
        self._redactor = redactor or Redactor()
        self._db.ddl([AUDIT_DDL])

    @staticmethod
    def _entry_hash(at: str, actor: str, action: str, report_id: str | None, inp: str, out: str, prev: str) -> str:
        return sha256_hex(canonical_json({"at": at, "actor": actor, "action": action, "report_id": report_id,
                                          "input": inp, "output": out, "prev_hash": prev}))

    def record(self, *, actor: str, action: str, input: Any, output: Any, report_id: str | None = None) -> int:
        at = datetime.now(UTC).isoformat()
        inp = self._redactor.redact(canonical_json(input).decode())
        out = self._redactor.redact(canonical_json(output).decode())
        with self._db.tx() as cur:
            row = cur.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            h = self._entry_hash(at, actor, action, report_id, inp, out, prev)
            sig = self._signer.sign(h.encode()).hex()
            seq = cur.execute(
                "INSERT INTO audit (at, actor, action, report_id, input, output, prev_hash, hash, sig) "
                "VALUES (?,?,?,?,?,?,?,?,?) RETURNING seq",
                (at, actor, action, report_id, inp, out, prev, h, sig),
            ).fetchone()[0]
        return int(seq)

    def entries(self, report_id: str | None = None) -> list[dict[str, Any]]:
        cols = ["seq", "at", "actor", "action", "report_id", "input", "output", "prev_hash", "hash", "sig"]
        q = f"SELECT {', '.join(cols)} FROM audit"
        params: tuple[Any, ...] = ()
        if report_id:
            q += " WHERE report_id = ?"
            params = (report_id,)
        q += " ORDER BY seq"
        return [dict(zip(cols, row, strict=True)) for row in self._db.query(q, params)]

    def verify_chain(self, verifier: Identity | None = None) -> tuple[bool, str]:
        verifier = verifier or self._signer
        prev = GENESIS
        for e in self.entries():
            if e["prev_hash"] != prev:
                return False, f"chain break at seq {e['seq']}"
            h = self._entry_hash(e["at"], e["actor"], e["action"], e["report_id"], e["input"], e["output"], e["prev_hash"])
            if h != e["hash"]:
                return False, f"hash mismatch at seq {e['seq']}"
            if not verifier.verify(bytes.fromhex(e["sig"]), h.encode()):
                return False, f"bad signature at seq {e['seq']}"
            prev = h
        return True, "ok"
