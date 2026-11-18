"""Dependabot alerts: vulnerable dependencies reachable from the maintained repo.

GET /repos/{owner}/{repo}/dependabot/alerts?state=open. These are routed through the same pipeline but the
patcher's job is typically a version bump, so the lane is usually `scheduled` unless triage finds a reachable
exploit path."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from qudisclose.ingest.base import FetchJSON
from qudisclose.models import Report, Reporter, ReportSubmission, Source

API = "https://api.github.com"


class DependabotSource:
    name = "dependabot"

    def __init__(self, repos: list[str], token: str | None, fetch: FetchJSON, min_severity: str = "medium") -> None:
        self.repos, self.token, self.fetch = repos, token, fetch
        self.min_severity = min_severity

    _ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def to_report(self, repo: str, alert: dict[str, Any]) -> Report | None:
        adv = alert.get("security_advisory") or {}
        vuln = alert.get("security_vulnerability") or {}
        sev = (adv.get("severity") or "medium").lower()
        if self._ORDER.get(sev, 1) < self._ORDER.get(self.min_severity, 1):
            return None
        pkg = (vuln.get("package") or {}).get("name") or (alert.get("dependency") or {}).get("package", {}).get("name")
        manifest = (alert.get("dependency") or {}).get("manifest_path", "")
        cwe = None
        for c in adv.get("cwes") or []:
            cwe = c.get("cwe_id") or cwe
        sub = ReportSubmission(
            title=f"Dependabot: {adv.get('summary') or pkg}"[:200],
            description=(f"{adv.get('description') or ''}\n\nManifest: {manifest}\n"
                         f"Vulnerable range: {vuln.get('vulnerable_version_range')}\n"
                         f"First patched: {(vuln.get('first_patched_version') or {}).get('identifier')}").ljust(20),
            repo=repo,
            package=pkg,
            affected_versions=[str(vuln.get("vulnerable_version_range") or "")],
            cwe=cwe,
            cvss_vector=((adv.get("cvss") or {}).get("vector_string")),
            suggested_fix=f"Upgrade {pkg} to {(vuln.get('first_patched_version') or {}).get('identifier')}",
        )
        return Report.from_submission(
            sub, source=Source.DEPENDABOT, external_id=f"{repo}#{alert.get('number')}",
            reporter=Reporter(identity="github:dependabot", credit=False),
            embargo_days=0,
        )

    def poll(self) -> Iterable[Report]:
        for repo in self.repos:
            data = self.fetch(f"{API}/repos/{repo}/dependabot/alerts?state=open&per_page=100", self._headers())
            for alert in data or []:
                r = self.to_report(repo, alert)
                if r:
                    yield r
