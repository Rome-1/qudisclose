"""Distinct non-human identities: every agent, reporter and the server itself has its own Ed25519 key pair."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class Identity:
    """An Ed25519 identity. `name` is the stable identifier used in tokens, audit entries and rate limits."""

    name: str
    private_key: Ed25519PrivateKey | None
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls, name: str) -> Identity:
        priv = Ed25519PrivateKey.generate()
        return cls(name=name, private_key=priv, public_key=priv.public_key())

    @classmethod
    def from_public_hex(cls, name: str, public_hex: str) -> Identity:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        return cls(name=name, private_key=None, public_key=pub)

    @property
    def public_hex(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ).hex()

    def sign(self, data: bytes) -> bytes:
        if self.private_key is None:
            raise ValueError(f"identity {self.name!r} has no private key")
        return self.private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self.public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    # -- persistence (private key material never leaves the deployment host)

    def save(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{self.name}.json"
        payload: dict[str, str] = {"name": self.name, "public": self.public_hex}
        if self.private_key is not None:
            raw = self.private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            payload["private"] = raw.hex()
        path.write_text(json.dumps(payload, indent=2))
        path.chmod(0o600)
        return path

    @classmethod
    def load(cls, path: Path | str) -> Identity:
        payload = json.loads(Path(path).read_text())
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(payload["public"]))
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(payload["private"])) if "private" in payload else None
        return cls(name=payload["name"], private_key=priv, public_key=pub)


class KeyRing:
    """Pinned public keys the server trusts (trust chain). Anything not here is unverified."""

    def __init__(self) -> None:
        self._keys: dict[str, Identity] = {}

    def add(self, identity: Identity) -> None:
        self._keys[identity.name] = Identity(identity.name, None, identity.public_key)

    def get(self, name: str) -> Identity | None:
        return self._keys.get(name)

    def names(self) -> list[str]:
        return sorted(self._keys)
