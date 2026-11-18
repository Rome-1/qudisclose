"""GitHub private vulnerability reports and repository security advisories.

Uses GET /repos/{owner}/{repo}/security-advisories (states: triage = new private reports; draft = advisories
the maintainer opened). Requires a token with `repository_advisories:read` on the repo."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from qudisclose.ingest.base import FetchJSON
from qudisclose.models import Report, Reporter, ReportSubmission, Source

API = "https://api.github.com"


class GitHubAdvisorySource:
    name = "github_advisory"

    def __init__(self, repos: list[str], token: str | None, fetch: FetchJSON, states: tuple[str, ...] = ("triage", "draft")) -> None:
        self.repos = repos
        self.token = token
        self.fetch = fetch
        self.states = states

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    @staticmethod
    def to_report(repo: str, adv: dict[str, Any]) -> Report:
        vulns = adv.get("vulnerabilities") or []
        package = None
        versions: list[str] = []
        for v in vulns:
            pkg = (v.get("package") or {}).get("name")
            package = package or pkg
            if v.get("vulnerable_version_range"):
                versions.append(str(v["vulnerable_version_range"]))
        cwe = None
        for c in adv.get("cwes") or []:
            cwe = c.get("cwe_id") or cwe
        submitter = adv.get("submission", {}) or {}
        reporter_login = (adv.get("submitter") or {}).get("login") or (adv.get("author") or {}).get("login") or "github"
        sub = ReportSubmission(
            title=f"{adv.get('summary') or 'Untitled GitHub advisory'} ({adv.get('ghsa_id')})"[:200],
            description=(adv.get("description") or "No description provided.").ljust(20),
            repo=repo,
            package=package,
            affected_versions=versions[:50],
            cwe=cwe,
            cvss_vector=((adv.get("cvss") or {}).get("vector_string")),
            wants_credit=bool(submitter.get("accepted", True)),
        )
        return Report.from_submission(
            sub, source=Source.GITHUB_ADVISORY, external_id=adv.get("ghsa_id"),
            reporter=Reporter(identity=f"github:{reporter_login}"),
        )

    def poll(self) -> Iterable[Report]:
        for repo in self.repos:
            for state in self.states:
                data = self.fetch(f"{API}/repos/{repo}/security-advisories?state={state}&per_page=50", self._headers())
                for adv in data or []:
                    yield self.to_report(repo, adv)
