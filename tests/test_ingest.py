import json

from qudisclose.ingest import DependabotSource, GitHubAdvisorySource, OSVSource, PollingIngestor, SignedWebhookSource
from qudisclose.ingest.webhook import WebhookSignatureError
from qudisclose.models import Source


def test_github_advisory_adapter_normalizes():
    payload = [{"ghsa_id": "GHSA-xxxx-yyyy-zzzz", "summary": "Path traversal in files", "description": "x" * 30, "state": "triage",
                "submitter": {"login": "alice"}, "cwes": [{"cwe_id": "CWE-22"}], "cvss": {"vector_string": "CVSS:3.1/AV:N"},
                "vulnerabilities": [{"package": {"name": "vulnpkg", "ecosystem": "pip"}, "vulnerable_version_range": "< 1.4.3"}]}]
    src = GitHubAdvisorySource(["example/vulnpkg"], "tok", fetch=lambda url, h: payload if "state=triage" in url else [])
    reps = list(src.poll())
    assert len(reps) == 1 and reps[0].source == Source.GITHUB_ADVISORY and reps[0].external_id == "GHSA-xxxx-yyyy-zzzz"
    assert reps[0].submission.cwe == "CWE-22" and reps[0].reporter.identity == "github:alice"


def test_dependabot_filters_by_severity():
    alerts = [{"number": 7, "security_advisory": {"summary": "bad dep", "description": "d" * 30, "severity": "low", "cwes": []},
               "security_vulnerability": {"package": {"name": "left-pad"}, "vulnerable_version_range": "< 2", "first_patched_version": {"identifier": "2.0.0"}},
               "dependency": {"manifest_path": "requirements.txt"}},
              {"number": 8, "security_advisory": {"summary": "worse dep", "description": "d" * 30, "severity": "critical", "cwes": [{"cwe_id": "CWE-79"}]},
               "security_vulnerability": {"package": {"name": "ujson"}, "vulnerable_version_range": "< 5", "first_patched_version": {"identifier": "5.0.0"}},
               "dependency": {"manifest_path": "requirements.txt"}}]
    src = DependabotSource(["example/vulnpkg"], None, fetch=lambda u, h: alerts)
    reps = list(src.poll())
    assert [r.external_id for r in reps] == ["example/vulnpkg#8"] and reps[0].embargo_until is not None


def test_osv_adapter_is_public():
    data = {"vulns": [{"id": "PYSEC-2026-1", "summary": "s", "details": "d" * 30, "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.4.3"}]}]}],
                       "references": [{"url": "https://x"}], "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}]}
    src = OSVSource([("PyPI", "vulnpkg", "example/vulnpkg")], post=lambda url, body: data)
    reps = list(src.poll())
    assert reps[0].classification == "public" and reps[0].submission.affected_versions == [">=0", "<1.4.3"]


def test_signed_webhook_roundtrip_and_rejections():
    src = SignedWebhookSource({"huntr": "s3cret"})
    body = json.dumps({"external_id": "H-1", "title": "Prototype pollution in merge", "description": "x" * 40, "repo": "example/vulnpkg"}).encode()
    sig, ts = SignedWebhookSource.sign("s3cret", body)
    rep = src.receive(sender="huntr", body=body, signature=sig, timestamp=ts)
    assert rep.external_id == "huntr:H-1" and src.poll() == [rep] and src.poll() == []
    try:
        src.receive(sender="huntr", body=body + b" ", signature=sig, timestamp=ts)
        assert False
    except WebhookSignatureError:
        pass
    try:
        src.receive(sender="huntr", body=body, signature=sig, timestamp=str(int(ts) - 10_000))
        assert False
    except WebhookSignatureError:
        pass
    # unknown fields are rejected (strict schema)
    bad = json.dumps({"title": "t" * 10, "description": "x" * 40, "repo": "a/b", "exec": "rm -rf /"}).encode()
    sig2, ts2 = SignedWebhookSource.sign("s3cret", bad)
    import pydantic
    try:
        src.receive(sender="huntr", body=bad, signature=sig2, timestamp=ts2)
        assert False
    except pydantic.ValidationError:
        pass


def test_polling_ingestor_isolates_failures():
    class Broken:
        name = "broken"
        def poll(self):
            raise RuntimeError("api down")
    seen = []
    src = SignedWebhookSource({"a": "k"})
    counts = PollingIngestor([Broken(), src], seen.append).run_once()
    assert counts["broken:error"] == 1 and counts["webhook"] == 0
