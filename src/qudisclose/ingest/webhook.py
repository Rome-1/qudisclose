"""Generic signed webhook intake for bug-bounty platforms and fuzzers (huntr, HackerOne, Intigriti, OSS-Fuzz,
your CI's sanitizer job). The sender HMAC-SHA256 signs the raw body with a shared secret; the payload must
match `ReportSubmission` exactly (strict schema, NSA: serialization risk)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

from qudisclose.models import Report, Reporter, ReportSubmission, Source


class WebhookSignatureError(Exception):
    pass


class SignedWebhookSource:
    name = "webhook"

    def __init__(self, secrets: dict[str, str], max_age_seconds: int = 300) -> None:
        """secrets: sender name -> shared secret."""
        self.secrets = secrets
        self.max_age = max_age_seconds
        self._queue: list[Report] = []

    def receive(self, *, sender: str, body: bytes, signature: str, timestamp: str) -> Report:
        secret = self.secrets.get(sender)
        if not secret:
            raise WebhookSignatureError(f"unknown sender {sender!r}")
        try:
            ts = int(timestamp)
        except ValueError as e:
            raise WebhookSignatureError("bad timestamp") from e
        if abs(time.time() - ts) > self.max_age:
            raise WebhookSignatureError("stale webhook")
        expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature.removeprefix("sha256=")):
            raise WebhookSignatureError("bad signature")
        payload = json.loads(body)
        external_id = payload.pop("external_id", None)
        sub = ReportSubmission.model_validate(payload)
        report = Report.from_submission(sub, source=Source.WEBHOOK, external_id=f"{sender}:{external_id}" if external_id else None,
                                        reporter=Reporter(identity=f"webhook:{sender}", contact=sub.reporter_contact))
        self._queue.append(report)
        return report

    @staticmethod
    def sign(secret: str, body: bytes, timestamp: int | None = None) -> tuple[str, str]:
        ts = timestamp or int(time.time())
        return f"sha256={hmac.new(secret.encode(), f'{ts}.'.encode() + body, hashlib.sha256).hexdigest()}", str(ts)

    def poll(self) -> list[Report]:
        out, self._queue = self._queue, []
        return out
