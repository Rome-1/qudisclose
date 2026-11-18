"""Pinned VSLA keys (VSLA-V-1): obtained out of band, never from a statement. Keyids are `<role>:<name>`; roles are
finder:, platform:, maintainer:, provider:, root:, operator:, log:. A key is usable at time `at` only inside its validity
window (`validFrom`, `revokedAt`), which is how revocation (VSLA-F-20) reaches the verifier. The `enclave:` key is
never pinned: a verifier derives it from a verified quote (VSLA-F-16)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from qudisclose.security.keys import Identity


def _ts(v: Any) -> float | None:
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, datetime):
        return v.timestamp()
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


class Keyring:
    """{keyid: "ed25519:<hex>" | "<hex>" | {"public": ..., "validFrom"?: iso, "revokedAt"?: iso} | Identity}."""

    def __init__(self, keys: dict[str, Any] | None = None) -> None:
        self._keys: dict[str, tuple[Identity, float | None, float | None]] = {}
        self._meta: dict[str, dict[str, Any]] = {}
        for kid, v in (keys or {}).items():
            self.add(kid, v)

    def add(self, keyid: str, public: str | dict[str, Any] | Identity) -> None:
        if isinstance(public, Identity):
            ident = Identity(keyid, None, public.public_key)
            meta: dict[str, Any] = {"public": f"ed25519:{ident.public_hex}"}
        else:
            meta = dict(public) if isinstance(public, dict) else {"public": public}
            hexkey = str(meta["public"]).removeprefix("ed25519:")
            ident = Identity.from_public_hex(keyid, hexkey)
        self._keys[keyid] = (ident, _ts(meta.get("validFrom")), _ts(meta.get("revokedAt")))
        self._meta[keyid] = {"public": f"ed25519:{ident.public_hex}", **{k: meta[k] for k in ("validFrom", "revokedAt") if meta.get(k)}}

    def add_identity(self, identity: Identity) -> None:
        """Pin an Identity under its own name (the name must already be a `<role>:<name>` keyid)."""
        self.add(identity.name, identity)

    def has(self, keyid: str) -> bool:
        return keyid in self._keys

    def get(self, keyid: str | None, at: Any = None) -> Identity | None:
        if keyid is None:
            return None
        rec = self._keys.get(keyid)
        if rec is None:
            return None
        ident, valid_from, revoked_at = rec
        t = _ts(at) if at is not None else None
        if t is not None and ((valid_from is not None and t < valid_from) or (revoked_at is not None and t >= revoked_at)):
            return None
        return ident

    def revoked(self, keyid: str) -> bool:
        rec = self._keys.get(keyid)
        return rec is not None and rec[2] is not None

    def role(self, role: str) -> list[str]:
        return [k for k in self._keys if k.startswith(role + ":")]

    def find(self, role: str, hexkey: str) -> str | None:
        """The pinned keyid of `role` whose public key is `hexkey`, if any."""
        for k in self.role(role):
            if hexkey and hexkey == self._keys[k][0].public_hex:
                return k
        return None

    def names(self) -> list[str]:
        return sorted(self._keys)

    def to_dict(self) -> dict[str, Any]:
        """The pinned keys as a verifier publishes them (VSLA-P-5): {keyid: "ed25519:<hex>" | {public, validFrom?, revokedAt?}}."""
        return {k: (m["public"] if set(m) == {"public"} else m) for k, m in sorted(self._meta.items())}
