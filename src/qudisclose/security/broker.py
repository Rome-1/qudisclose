"""Credential brokering: agents never hold long-lived keys.

The broker issues `CredentialLease`s scoped to one purpose, one repo and a short TTL, issued by an
authority outside the agents' trust domain (this process, not the model). In production the
`fetch` callables mint a GitHub App installation token / cloud STS credential; the default
implementation reads a long-lived token from the environment and hands out time-boxed views of it,
which still removes ambient authority from the agents' context."""

from __future__ import annotations

import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

Purpose = str  # "repo:read" | "repo:write" | "pr:create" | "advisory:publish"


@dataclass(frozen=True)
class CredentialLease:
    lease_id: str
    purpose: Purpose
    repo: str
    holder: str
    expires_at: float
    _secret: str = field(repr=False)

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    def reveal(self) -> str:
        if self.expired:
            raise PermissionError(f"lease {self.lease_id} expired")
        return self._secret


class CredentialBroker:
    def __init__(self, fetch: Callable[[Purpose, str], str] | None = None, *, default_ttl: int = 900,
                 require_human_for: frozenset[Purpose] = frozenset()) -> None:
        self._fetch = fetch or self._fetch_from_env
        self._ttl = default_ttl
        self._require_human = require_human_for
        self._human_approvals: set[tuple[Purpose, str]] = set()
        self._active: dict[str, CredentialLease] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _fetch_from_env(purpose: Purpose, repo: str) -> str:
        tok = os.environ.get("QUDISCLOSE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not tok:
            raise PermissionError("no GitHub credential configured (QUDISCLOSE_GITHUB_TOKEN)")
        return tok

    def approve_human(self, purpose: Purpose, repo: str) -> None:
        self._human_approvals.add((purpose, repo))

    def lease(self, *, purpose: Purpose, repo: str, holder: str, ttl: int | None = None) -> CredentialLease:
        if purpose in self._require_human and (purpose, repo) not in self._human_approvals:
            raise PermissionError(f"{purpose} on {repo} requires human approval")
        secret = self._fetch(purpose, repo)
        lease = CredentialLease(
            lease_id=secrets.token_hex(8), purpose=purpose, repo=repo, holder=holder,
            expires_at=time.time() + (ttl or self._ttl), _secret=secret,
        )
        with self._lock:
            self._active[lease.lease_id] = lease
        return lease

    def revoke(self, lease_id: str) -> None:
        with self._lock:
            self._active.pop(lease_id, None)

    def active(self) -> list[CredentialLease]:
        with self._lock:
            return [l for l in self._active.values() if not l.expired]
