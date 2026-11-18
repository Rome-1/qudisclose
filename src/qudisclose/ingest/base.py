from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, Protocol

import httpx2

from qudisclose.models import Report

FetchJSON = Callable[[str, dict[str, str] | None], Any]
"""(url, headers) -> parsed JSON. Injected so adapters are testable and egress goes through one allowlisted client."""

ALLOWED_HOSTS = frozenset({"api.github.com", "api.osv.dev"})


def default_fetch(allowed_hosts: frozenset[str] = ALLOWED_HOSTS, timeout: float = 30.0) -> FetchJSON:
    """HTTP GET with an egress allowlist (NSA: outbound filtering)."""
    client = httpx2.Client(timeout=timeout, follow_redirects=False)

    def fetch(url: str, headers: dict[str, str] | None = None) -> Any:
        host = httpx2.URL(url).host
        if host not in allowed_hosts:
            raise PermissionError(f"egress to {host} is not allowlisted")
        r = client.get(url, headers=headers or {})
        r.raise_for_status()
        return r.json()

    return fetch


class IngestSource(Protocol):
    name: str

    def poll(self) -> Iterable[Report]: ...


class PollingIngestor:
    """Runs every source once and hands new reports to a sink (the orchestrator's `intake`)."""

    def __init__(self, sources: list[IngestSource], sink: Callable[[Report], Any]) -> None:
        self.sources = sources
        self.sink = sink

    def run_once(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for src in self.sources:
            n = 0
            try:
                for report in src.poll():
                    self.sink(report)
                    n += 1
            except Exception as exc:  # one broken feed must not stop the others
                counts[f"{src.name}:error"] = 1
                counts[f"{src.name}:error_msg"] = 0
                self._last_error = (src.name, repr(exc))
            counts[src.name] = n
        return counts
