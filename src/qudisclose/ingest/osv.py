"""OSV.dev: public vulnerabilities already filed against the maintained package (e.g. via PyPA, GHSA, Go).

POST https://api.osv.dev/v1/query {"package": {"name", "ecosystem"}}. Public already, so classification is
`public` and embargo is zero; the pipeline still patches and publishes a fixed version fast."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

import httpx2

from qudisclose.models import Classification, Report, Reporter, ReportSubmission, Source

API = "https://api.osv.dev/v1/query"

PostJSON = Callable[[str, dict[str, Any]], Any]


def default_post(timeout: float = 30.0) -> PostJSON:
    client = httpx2.Client(timeout=timeout)

    def post(url: str, body: dict[str, Any]) -> Any:
        if httpx2.URL(url).host != "api.osv.dev":
            raise PermissionError("egress not allowlisted")
        r = client.post(url, json=body)
        r.raise_for_status()
        return r.json()

    return post


class OSVSource:
    name = "osv"

    def __init__(self, packages: list[tuple[str, str, str]], post: PostJSON) -> None:
        """packages: (ecosystem, package_name, owner/repo)"""
        self.packages = packages
        self.post = post

    @staticmethod
    def to_report(repo: str, package: str, vuln: dict[str, Any]) -> Report:
        affected = vuln.get("affected") or []
        versions: list[str] = []
        for a in affected:
            for r in a.get("ranges") or []:
                for ev in r.get("events") or []:
                    if "introduced" in ev:
                        versions.append(f">={ev['introduced']}")
                    if "fixed" in ev:
                        versions.append(f"<{ev['fixed']}")
        refs = "\n".join(r.get("url", "") for r in vuln.get("references") or [])
        sev_vec = None
        for s in vuln.get("severity") or []:
            if str(s.get("type", "")).startswith("CVSS"):
                sev_vec = s.get("score")
        sub = ReportSubmission(
            title=f"{vuln.get('summary') or 'OSV entry'} ({vuln.get('id')})"[:200],
            description=((vuln.get("details") or "") + "\n\nReferences:\n" + refs).ljust(20),
            repo=repo, package=package, affected_versions=versions[:50], cvss_vector=sev_vec,
        )
        rep = Report.from_submission(sub, source=Source.OSV, external_id=vuln.get("id"),
                                     reporter=Reporter(identity="osv.dev", credit=False), embargo_days=0)
        rep.classification = Classification.PUBLIC
        return rep

    def poll(self) -> Iterable[Report]:
        for ecosystem, package, repo in self.packages:
            data = self.post(API, {"package": {"name": package, "ecosystem": ecosystem}})
            for vuln in (data or {}).get("vulns") or []:
                yield self.to_report(repo, package, vuln)
