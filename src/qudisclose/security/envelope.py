"""Per-message signing at the protocol layer (NSA: TLS alone is not sufficient).

Every tool call carries a `SignedEnvelope` in MCP `_meta["qudisclose/sig"]`: an Ed25519 signature
over the canonical JSON of {tool, args_hash, nonce, iat, exp, sender}. The server rejects
expired envelopes, replayed nonces, unknown senders and argument tampering.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Any

from pydantic import Field

from qudisclose.models import Strict, canonical_json, sha256_hex
from qudisclose.security.keys import Identity, KeyRing

DEFAULT_TTL_SECONDS = 120
MAX_CLOCK_SKEW_SECONDS = 30


class EnvelopeError(Exception):
    pass


class SignedEnvelope(Strict):
    sender: str
    tool: str
    args_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    nonce: str = Field(min_length=16, max_length=64)
    iat: int
    exp: int
    sig: str = Field(pattern=r"^[0-9a-f]{128}$")

    @staticmethod
    def _payload(sender: str, tool: str, args_hash: str, nonce: str, iat: int, exp: int) -> bytes:
        return canonical_json({"sender": sender, "tool": tool, "args_hash": args_hash,
                               "nonce": nonce, "iat": iat, "exp": exp})

    @classmethod
    def create(cls, identity: Identity, tool: str, args: dict[str, Any], *,
               ttl: int = DEFAULT_TTL_SECONDS, now: int | None = None) -> SignedEnvelope:
        iat = int(now if now is not None else time.time())
        exp = iat + ttl
        nonce = secrets.token_hex(16)
        args_hash = sha256_hex(canonical_json(args))
        sig = identity.sign(cls._payload(identity.name, tool, args_hash, nonce, iat, exp)).hex()
        return cls(sender=identity.name, tool=tool, args_hash=args_hash, nonce=nonce, iat=iat, exp=exp, sig=sig)

    def verify(self, keyring: KeyRing, nonces: NonceCache, tool: str, args: dict[str, Any], *,
               now: int | None = None) -> Identity:
        """Return the verified sender identity or raise EnvelopeError. Order matters: cheap checks first."""
        t = int(now if now is not None else time.time())
        if self.tool != tool:
            raise EnvelopeError("envelope tool does not match called tool")
        if self.exp <= t:
            raise EnvelopeError("envelope expired")
        if self.iat > t + MAX_CLOCK_SKEW_SECONDS:
            raise EnvelopeError("envelope issued in the future")
        if self.exp - self.iat > 3600:
            raise EnvelopeError("envelope ttl too long")
        if sha256_hex(canonical_json(args)) != self.args_hash:
            raise EnvelopeError("arguments do not match signed hash")
        sender = keyring.get(self.sender)
        if sender is None:
            raise EnvelopeError(f"unknown sender {self.sender!r}")
        payload = self._payload(self.sender, self.tool, self.args_hash, self.nonce, self.iat, self.exp)
        if not sender.verify(bytes.fromhex(self.sig), payload):
            raise EnvelopeError("bad signature")
        if not nonces.consume(f"{self.sender}:{self.nonce}", self.exp):
            raise EnvelopeError("replayed nonce")
        return sender


class NonceCache:
    """Thread-safe replay cache. Nonces live until their envelope's `exp`, then are swept."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(self, key: str, exp: int, *, now: int | None = None) -> bool:
        t = int(now if now is not None else time.time())
        with self._lock:
            if len(self._seen) > 10_000:
                self._seen = {k: e for k, e in self._seen.items() if e > t}
            if key in self._seen:
                return False
            self._seen[key] = exp
            return True

    def __len__(self) -> int:
        return len(self._seen)
