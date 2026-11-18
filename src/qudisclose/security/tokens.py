"""Scoped bearer tokens. Least privilege at the tool-call boundary: a token carries scopes, a short
expiry, and an audience bound to this server; each tool declares the one scope it requires."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

import jwt
from cryptography.hazmat.primitives import serialization
from mcp.server.auth.provider import AccessToken, TokenVerifier

from qudisclose.security.keys import Identity

ALG = "EdDSA"
SCOPES = frozenset({"report:submit", "report:read", "triage:write", "patch:propose", "release:publish", "admin"})


@dataclass
class TokenIssuer:
    issuer: Identity
    audience: str
    default_ttl: int = 3600
    revoked: set[str] = field(default_factory=set)

    def issue(self, subject: str, scopes: list[str], *, ttl: int | None = None) -> str:
        bad = set(scopes) - SCOPES
        if bad:
            raise ValueError(f"unknown scopes: {sorted(bad)}")
        now = int(time.time())
        claims = {
            "iss": self.issuer.name, "sub": subject, "aud": self.audience,
            "iat": now, "exp": now + (ttl or self.default_ttl), "scope": " ".join(sorted(scopes)),
            "jti": secrets.token_hex(12),
        }
        pem = self.issuer.private_key.private_bytes(  # type: ignore[union-attr]
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        return jwt.encode(claims, pem, algorithm=ALG)

    def revoke(self, jti: str) -> None:
        self.revoked.add(jti)


class ScopedTokenVerifier(TokenVerifier):
    """MCP SDK `TokenVerifier` that validates EdDSA JWTs issued by our pinned issuer key."""

    def __init__(self, issuer: Identity, audience: str, revoked: set[str] | None = None) -> None:
        self._pub_pem = issuer.public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self._issuer = issuer.name
        self._audience = audience
        self._revoked = revoked if revoked is not None else set()

    def verify_sync(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(token, self._pub_pem, algorithms=[ALG], audience=self._audience, issuer=self._issuer)
        except jwt.PyJWTError:
            return None
        if claims.get("jti") in self._revoked:
            return None
        return AccessToken(
            token=token, client_id=str(claims["sub"]), scopes=str(claims.get("scope", "")).split(),
            expires_at=int(claims["exp"]), resource=self._audience, subject=str(claims["sub"]), claims=claims,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        return self.verify_sync(token)
