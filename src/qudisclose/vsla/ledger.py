"""The trust ledger (VSLA-P-6, P-14, P-15): countersigned outcomes per finder key and track, in the same database as the cases.

Each entry is a DSSE envelope with payload type `application/vnd.vsla.ledger-entry+json` whose `signatures[0].keyid` is
the countersigner, over {kind, at, finder, statement, platform, track, outcome, claimed?, verified?, reason?, vouched?}.
The ledger's Merkle leaves are the canonical bytes of each envelope (RFC 6962), so the root commits to the signatures as
well as the bodies, and two platforms compute the same root over the same entries.

Who owns the index (revision 4): the finder's operator. A countersigned entry carries no `seq`; the finder appends it
wherever its log is at, and the rubric window is ordered by countersigned `at`, which the finder cannot choose. A
platform therefore stores, per `(finder key, track)`, the root and count of the ledger it was *shown* (VSLA-P-14) and
separately the entries it wrote; the next ledger must extend the shown prefix and *include* each own entry (canonical
bytes, anywhere). Two honest in-flight cases, or two platforms closing for the same finder, never collide.

qudisclose is the maintainer's authoritative agent, so it countersigns with the platform identity and says so
(`platform:<name>`). Entries other platforms countersigned reach this mirror through `import_entry` (the output of the
`get_ledger` tool on another qudisclose is directly importable; there is no network path). `accepted` means the
disclosure's outcome was accepted (fix merged / advisory published); a finding that was reproduced but not resolved is
`reproduced-unresolved` (neutral); every negative or disqualifying outcome carries a `reason` (VSLA-P-15)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

from qudisclose.db import SERIAL, Backend
from qudisclose.security.keys import Identity
from qudisclose.vsla.canonical import canonical
from qudisclose.vsla.dsse import LEDGER_PAYLOAD_TYPE, _ts, canonical_payload, dsse_sign, envelope_payload, pae, signer_keyids, verify_signature
from qudisclose.vsla.keyring import Keyring
from qudisclose.vsla.merkle import merkle_root
from qudisclose.vsla.rubric import DISQUALIFYING, NEGATIVE, trust_score

LEDGER_DDL = f"""CREATE TABLE IF NOT EXISTS vsla_ledger (
    seq {SERIAL},
    finder TEXT NOT NULL,
    finder_seq INTEGER NOT NULL,
    at TEXT NOT NULL,
    report_id TEXT,
    statement_digest TEXT,
    track TEXT,
    outcome TEXT,
    claimed INTEGER,
    verified INTEGER,
    countersigner TEXT NOT NULL,
    envelope TEXT NOT NULL
)"""
SEEN_DDL = """CREATE TABLE IF NOT EXISTS vsla_ledger_seen (
    finder TEXT NOT NULL,
    track TEXT NOT NULL,
    root TEXT NOT NULL,
    count INTEGER NOT NULL,
    at TEXT NOT NULL,
    PRIMARY KEY (finder, track)
)"""

OUTCOMES = ("accepted", "duplicate", "rejected", "false-positive", "reproduced-unresolved", "withdrawn",
            "non-authoritative-release", "retracted", "ledger-fork")
ENTRY_KINDS = ("outcome", "successor", "revoke")
TRACKS = ("finding", "patch")


def _try(fn, default=None):
    try:
        return fn()
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        return default


# ----------------------------------------------------------------------------- module functions (mirror the reference)

def make_ledger_entry(body: dict[str, Any], signers: list[tuple[str, Identity]]) -> dict[str, Any]:
    """A countersigned outcome entry. No `seq`: the index belongs to the finder's operator."""
    return dsse_sign({"kind": "outcome", **body}, LEDGER_PAYLOAD_TYPE, signers)


def make_successor_entry(*, at: str, old: Identity, new: Identity, old_keyid: str) -> dict[str, Any]:
    """Key rotation (VSLA-F-20): {kind: successor, at, finder: old key, successor: new key}, signed by both keys."""
    body = {"kind": "successor", "at": at, "finder": f"ed25519:{old.public_hex}", "successor": f"ed25519:{new.public_hex}"}
    return dsse_sign(body, LEDGER_PAYLOAD_TYPE, [(old_keyid, old), ("successor", new)])


def make_revoke_entry(*, at: str, finder_key_hex: str, operator_keyid: str, operator: Identity, reason: str = "") -> dict[str, Any]:
    """Key revocation (VSLA-F-20): {kind: revoke, at, finder, revokedBy}, signed by the pinned operator key it names."""
    body: dict[str, Any] = {"kind": "revoke", "at": at, "finder": f"ed25519:{finder_key_hex}", "revokedBy": operator_keyid}
    if reason:
        body["reason"] = reason[:500]
    return dsse_sign(body, LEDGER_PAYLOAD_TYPE, [(operator_keyid, operator)])


def ledger_root(entries: list[dict[str, Any]]) -> str:
    """RFC 6962 root whose leaves are the canonical bytes of each entry's DSSE envelope."""
    return merkle_root([canonical(e) for e in entries])


def ledger_well_formed(entries: list[dict[str, Any]]) -> tuple[bool, str]:
    """Every presented entry parses as a canonical DSSE payload. Order is the finder's own; the rubric window is by
    countersigned `at`, so presented order cannot move the score."""
    if not isinstance(entries, list):
        return False, "ledger is not a list"
    for i, env in enumerate(entries):
        if _try(lambda: canonical_payload(env)) is None:
            return False, f"entry {i} is not a canonical DSSE payload"
    return True, "ok"


def _raw_ident(hexkey: Any) -> Identity | None:
    try:
        return Identity.from_public_hex("raw", str(hexkey).removeprefix("ed25519:"))
    except (ValueError, TypeError):
        return None


def _sig_verifies(env: dict[str, Any], ident: Identity, keyid: str | None = None) -> bool:
    """A signature in `env` (under `keyid`, or any keyid when None) that verifies under `ident`."""
    try:
        payload = base64.b64decode(env["payload"])
    except (KeyError, TypeError, ValueError):
        return False
    for s in env.get("signatures", []):
        if not isinstance(s, dict) or (keyid is not None and s.get("keyid") != keyid):
            continue
        try:
            if ident.verify(base64.b64decode(s["sig"]), pae(env["payloadType"], payload)):
                return True
        except Exception:
            continue
    return False


def successor_chain(entries: list[dict[str, Any]], finder: str) -> list[str]:
    """Keys this finder's history may be recorded under: `finder` and, following valid `successor` entries backwards,
    every predecessor. A successor entry is valid when it is a canonical ledger-entry payload signed by BOTH the old key
    and the new key, each verified under the raw key the body names; the chain is acyclic."""
    succ: dict[str, str] = {}
    for env in entries:
        body = _try(lambda: canonical_payload(env))
        if not body or body.get("kind") != "successor" or env.get("payloadType") != LEDGER_PAYLOAD_TYPE:
            continue
        old, new = _raw_ident(body.get("finder")), _raw_ident(body.get("successor"))
        if old is None or new is None or not _sig_verifies(env, old) or not _sig_verifies(env, new):
            continue
        succ[str(body["successor"])] = str(body["finder"])
    chain = [finder]
    while chain[-1] in succ and succ[chain[-1]] not in chain and len(chain) < 64:
        chain.append(succ[chain[-1]])
    return chain


def revocations(entries: list[dict[str, Any]], keyring: Keyring, keys: list[str]) -> list[tuple[str, float, str]]:
    """(key, at seconds, revokedBy) for every valid `revoke` entry naming one of `keys`: a canonical ledger-entry payload
    signed under the pinned `operator:` keyid it names."""
    out = []
    for env in entries:
        body = _try(lambda: canonical_payload(env))
        if not body or body.get("kind") != "revoke" or env.get("payloadType") != LEDGER_PAYLOAD_TYPE or body.get("finder") not in keys:
            continue
        kid = str(body.get("revokedBy", ""))
        pub = keyring.get(kid) if kid.startswith("operator:") else None
        at = _ts(body.get("at"))
        if pub is None or at is None or not verify_signature(env, kid, pub, LEDGER_PAYLOAD_TYPE):
            continue
        out.append((str(body["finder"]), at, kid))
    return out


def verified_ledger(entries: list[dict[str, Any]], keyring: Keyring, *, finder: str | list[str] | None = None, track: str | None = None) -> tuple[list[dict[str, Any]], int]:
    """Bodies of the OUTCOME entries whose countersignature verifies under a pinned `platform:`/`maintainer:` key, each
    with `countersigner` set; and how many were dropped (VSLA-V-5). With `finder` (`ed25519:<hex>`, or the list
    `successor_chain` returns) and `track`, outcome entries naming another finder or another track are dropped too.
    Lifecycle entries (successor, revoke) are neither counted nor dropped."""
    keys = None if finder is None else ([finder] if isinstance(finder, str) else list(finder))
    kept, dropped = [], 0
    for env in entries:
        body = _try(lambda: canonical_payload(env))
        kids = signer_keyids(env) if isinstance(env, dict) else []
        if body is None or not kids:
            dropped += 1
            continue
        if body.get("kind", "outcome") != "outcome":
            continue
        kid = kids[0]
        pub = keyring.get(kid, at=body.get("at"))
        role_ok = kid.split(":", 1)[0] in ("platform", "maintainer")
        finder_ok = keys is None or body.get("finder") in keys
        track_ok = track is None or body.get("track") == track
        if pub is None or not role_ok or not finder_ok or not track_ok or not verify_signature(env, kid, pub, LEDGER_PAYLOAD_TYPE):
            dropped += 1
            continue
        kept.append({**body, "countersigner": kid})
    return kept, dropped


def missing_entries(entries: list[dict[str, Any]], required: list[dict[str, Any]]) -> int:
    """How many of `required` (entries this verifier countersigned for the finder) are absent from the presented ledger,
    compared by canonical bytes. An own entry must be *included*; its position is the finder's business."""
    present = {_try(lambda: canonical(e)) for e in entries}
    return sum(1 for r in required if _try(lambda: canonical(r)) not in present)


def ledger_consistent(entries: list[dict[str, Any]], last_seen_root: str, last_seen_count: int) -> bool:
    """VSLA-P-14: the new ledger extends the one this platform was shown: the root over its first `count` entries is the stored root."""
    if last_seen_count > len(entries):
        return False
    return _try(lambda: ledger_root(entries[:last_seen_count]) == last_seen_root, False)


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def finder_id(identity: str, public_key: str | None) -> str:
    """The ledger key for a reporter: its Ed25519 key when known (`ed25519:<hex>`), else its name. A second name for the
    same key sees the same ledger state."""
    return f"ed25519:{public_key}" if public_key else identity


# ----------------------------------------------------------------------------- the platform's mirror

class Ledger:
    """Keyed by `(finder id, track)`; see `finder_id`."""

    def __init__(self, backend: Backend, platform: Identity, *, platform_name: str, keyring: Keyring | None = None) -> None:
        self._db = backend
        self._platform = platform
        self.keyid = f"platform:{platform_name}"
        self.platform_name = platform_name
        self.keyring = keyring or Keyring()
        if self.keyring.get(self.keyid) is None:
            self.keyring.add(self.keyid, platform)
        self._migrate()
        self._db.ddl([LEDGER_DDL, SEEN_DDL])

    def _migrate(self) -> None:
        """A pre-revision-2 `vsla_ledger` (flat rows signed as raw JSON) cannot be converted; it is kept aside as
        `vsla_ledger_v1`. A revision-3 `vsla_ledger_seen` (keyed by name only, roots that included the platform's own
        entries) is dropped: revision 4 keys it by (key, track) and stores only what was shown."""
        try:
            self._db.query("SELECT envelope FROM vsla_ledger LIMIT 1")
        except Exception as exc:
            if "vsla_ledger" in str(exc) and "envelope" not in str(exc):
                return
            try:
                self._db.execute("ALTER TABLE vsla_ledger RENAME TO vsla_ledger_v1")
            except Exception:
                pass
        try:
            self._db.query("SELECT track FROM vsla_ledger_seen LIMIT 1")
        except Exception as exc:
            if "vsla_ledger_seen" in str(exc) and "track" not in str(exc):
                return
            try:
                self._db.execute("DROP TABLE vsla_ledger_seen")
            except Exception:
                pass

    # -- writing

    def append(self, *, finder: str, outcome: str, track: str = "finding", report_id: str | None = None,
               statement_digest: str | None = None, claimed: int | None = None, verified: int | None = None,
               reason: str | None = None, finder_key: str | None = None, vouched: bool = False,
               at: datetime | None = None) -> dict[str, Any]:
        """Countersign an outcome for `finder` (a ledger id, see `finder_id`; `finder_key` is the ed25519 hex the body names)."""
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {outcome!r}")
        if track not in TRACKS:
            raise ValueError(f"unknown track {track!r}")
        if outcome in NEGATIVE | DISQUALIFYING and not reason:
            raise ValueError(f"outcome {outcome!r} requires a reason (VSLA-P-6)")
        key = f"ed25519:{finder_key}" if finder_key else (finder if finder.startswith("ed25519:") else finder)
        body: dict[str, Any] = {"at": _iso(at or datetime.now(UTC)), "finder": key, "platform": self.platform_name, "track": track, "outcome": outcome}
        if statement_digest:
            body["statement"] = {"sha256": statement_digest}
        if claimed is not None:
            body["claimed"] = int(claimed)
        if verified is not None:
            body["verified"] = int(verified)
        if reason:
            body["reason"] = reason[:500]
        if vouched:
            body["vouched"] = True
        env = make_ledger_entry(body, [(self.keyid, self._platform)])
        self._store(finder, body, env, report_id)
        return env

    def import_entry(self, finder: str, envelope: dict[str, Any], *, report_id: str | None = None) -> bool:
        """Append an entry another platform countersigned (e.g. one element of another qudisclose's `get_ledger` output).
        Only an entry whose countersignature verifies under a pinned key is stored."""
        kept, _ = verified_ledger([envelope], self.keyring)
        if not kept:
            return False
        self._store(finder, kept[0], envelope, report_id)
        return True

    def _store(self, finder: str, body: dict[str, Any], env: dict[str, Any], report_id: str | None) -> None:
        self._db.execute(
            "INSERT INTO vsla_ledger (finder, finder_seq, at, report_id, statement_digest, track, outcome, claimed, verified, countersigner, envelope) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (finder, self._count(finder), body["at"], report_id, (body.get("statement") or {}).get("sha256"), body.get("track"),
             body.get("outcome"), body.get("claimed"), body.get("verified"), signer_keyids(env)[0], canonical(env).decode()))

    def _count(self, finder: str) -> int:
        row = self._db.query_one("SELECT COUNT(*) FROM vsla_ledger WHERE finder = ?", (finder,))
        return int(row[0]) if row else 0

    # -- reading

    def entries(self, finder: str, track: str | None = None) -> list[dict[str, Any]]:
        """The finder's entries as DSSE envelopes, in the order this mirror received them (all tracks, or one)."""
        import json
        if track is None:
            rows = self._db.query("SELECT envelope FROM vsla_ledger WHERE finder = ? ORDER BY seq", (finder,))
        else:
            rows = self._db.query("SELECT envelope FROM vsla_ledger WHERE finder = ? AND track = ? ORDER BY seq", (finder, track))
        return [json.loads(r[0]) for r in rows]

    def own_entries(self, finder: str, track: str | None = None) -> list[dict[str, Any]]:
        """The entries THIS platform countersigned for the finder (its mirror may also hold imported ones)."""
        return [e for e in self.entries(finder, track) if signer_keyids(e)[:1] == [self.keyid]]

    def missing_from(self, finder: str, track: str, presented: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Own entries for `(finder, track)` the presented ledger does not contain (canonical bytes): a trimmed history."""
        have = {_try(lambda: canonical(e)) for e in presented}
        return [e for e in self.own_entries(finder, track) if canonical(e) not in have]

    def rows(self, finder: str) -> list[dict[str, Any]]:
        """Decoded entries with this platform's case id (for the operator's own surfaces; never published as-is)."""
        import json
        rows = self._db.query("SELECT report_id, envelope FROM vsla_ledger WHERE finder = ? ORDER BY seq", (finder,))
        out = []
        for report_id, env in rows:
            e = json.loads(env)
            out.append({**envelope_payload(e), "countersigner": signer_keyids(e)[0], "report_id": report_id})
        return out

    def bodies(self, finder: str, track: str | None = None) -> list[dict[str, Any]]:
        return verified_ledger(self.entries(finder, track), self.keyring, track=track)[0]

    def root(self, finder: str, track: str | None = None) -> str:
        return ledger_root(self.entries(finder, track))

    def score(self, finder: str, track: str | None = None, *, now_days: float | None = None) -> dict[str, Any]:
        return trust_score(self.bodies(finder, track), now_days=now_days)

    def summary(self, finder: str, *, floor: float, track: str = "finding") -> dict[str, Any]:
        """The `history` section of a statement (provenance.md) for one track: a summary; the entries are what a verifier checks."""
        bodies = self.bodies(finder, track)
        ts = trust_score(bodies)
        out = {"ledger": f"qudisclose://ledger/{finder}/{track}", "root": self.root(finder, track), "entries": ts["n"], "accepted": ts["accepted"],
               "rejected": ts["rejected"], "countersigners": ts["countersigners"], "score": ts["score"], "floor": floor}
        if bodies:
            out["oldestAt"] = min(b["at"] for b in bodies)
        return out

    def verify_entry(self, envelope: dict[str, Any], keyring: Keyring | None = None) -> bool:
        kept, _ = verified_ledger([envelope], keyring or self.keyring)
        return bool(kept)

    # -- consistency (VSLA-P-14): what this platform was shown, per (finder, track)

    def last_seen(self, finder: str, track: str = "finding") -> tuple[str, int] | None:
        row = self._db.query_one("SELECT root, count FROM vsla_ledger_seen WHERE finder = ? AND track = ?", (finder, track))
        return (row[0], int(row[1])) if row else None

    def remember(self, finder: str, track: str, root: str, count: int) -> None:
        self._db.execute("INSERT INTO vsla_ledger_seen (finder, track, root, count, at) VALUES (?,?,?,?,?) "
                         "ON CONFLICT (finder, track) DO UPDATE SET root = excluded.root, count = excluded.count, at = excluded.at",
                         (finder, track, root, int(count), _iso(datetime.now(UTC))))
