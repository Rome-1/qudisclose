"""Ingest adapters: pull vulnerability reports from the places they already arrive for open-source projects.

Every adapter yields normalized `Report` objects; the orchestrator dedups and acknowledges them exactly as it
does MCP submissions. Replace traditional CVD intake (security@ mailboxes, web forms) with these feeds plus
the MCP `submit_report` tool."""

from qudisclose.ingest.base import FetchJSON, IngestSource, PollingIngestor
from qudisclose.ingest.dependabot import DependabotSource
from qudisclose.ingest.github import GitHubAdvisorySource
from qudisclose.ingest.osv import OSVSource
from qudisclose.ingest.webhook import SignedWebhookSource, WebhookSignatureError

__all__ = ["FetchJSON", "IngestSource", "PollingIngestor", "DependabotSource", "GitHubAdvisorySource",
           "OSVSource", "SignedWebhookSource", "WebhookSignatureError"]
