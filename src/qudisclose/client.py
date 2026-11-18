"""Reporter-side client: what a researcher's agent (or a scanner) uses to submit over MCP.

Trust chain: the client pins the server's public key and the catalog fingerprint; it refuses to call tools
if either changes. Every mutating call carries a signed envelope."""

from __future__ import annotations

import json
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

from qudisclose.models import ReportSubmission
from qudisclose.security import Identity, SignedEnvelope, catalog_fingerprint

META_SIG_KEY = "qudisclose/sig"


class TrustError(Exception):
    pass


class ReporterClient:
    def __init__(self, url: str, token: str, identity: Identity, *, pinned_server_key: str | None = None,
                 pinned_fingerprint: str | None = None, timeout: float = 300.0) -> None:
        self.url, self.token, self.identity = url, token, identity
        self.pinned_server_key, self.pinned_fingerprint = pinned_server_key, pinned_fingerprint
        self.timeout = timeout
        self._client: Client | None = None
        self._http: httpx2.AsyncClient | None = None
        self._cm: Any = None
        self.fingerprint: str | None = None

    async def __aenter__(self) -> ReporterClient:
        self._http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {self.token}"}, timeout=httpx2.Timeout(30.0, read=self.timeout))
        await self._http.__aenter__()
        self._cm = Client(streamable_http_client(self.url, http_client=self._http))
        self._client = await self._cm.__aenter__()
        await self.verify_trust()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self._cm.__aexit__(*exc)
        await self._http.__aexit__(*exc)  # type: ignore[union-attr]

    # -- trust

    async def verify_trust(self) -> str:
        assert self._client
        tools = (await self._client.list_tools()).tools
        live = catalog_fingerprint(tools)
        res = await self._client.call_tool("catalog_fingerprint", {})
        claimed = _structured(res)
        if claimed.get("fingerprint") != live:
            raise TrustError("server-claimed catalog fingerprint differs from the catalog it serves")
        server = Identity.from_public_hex(claimed["server"], claimed["server_public_key"])
        if self.pinned_server_key and server.public_hex != self.pinned_server_key:
            raise TrustError("server identity key does not match pin")
        if not server.verify(bytes.fromhex(claimed["signature"]), live.encode()):
            raise TrustError("server fingerprint signature invalid")
        if self.pinned_fingerprint and live != self.pinned_fingerprint:
            raise TrustError(f"tool catalog changed since pin ({live[:12]} != {self.pinned_fingerprint[:12]}); refusing to operate")
        self.fingerprint = live
        return live

    # -- calls

    async def _call(self, tool: str, args: dict[str, Any], *, signed: bool) -> dict[str, Any]:
        assert self._client
        meta = {META_SIG_KEY: SignedEnvelope.create(self.identity, tool, args).model_dump()} if signed else None
        try:
            res = await self._client.call_tool(tool, args, meta=meta)
        except MCPError as e:
            raise RuntimeError(f"{tool}: {e.message}") from e
        if res.is_error:
            raise RuntimeError(_text(res))
        return _structured(res)

    async def submit(self, submission: ReportSubmission) -> dict[str, Any]:
        return await self._call("submit_report", {"report": submission.model_dump(exclude_none=True)}, signed=True)

    async def status(self, report_id: str) -> dict[str, Any]:
        return await self._call("get_report_status", {"query": {"report_id": report_id}}, signed=False)

    async def advisory(self, report_id: str) -> dict[str, Any]:
        return await self._call("get_advisory", {"query": {"report_id": report_id}}, signed=False)

    async def postmortem(self, report_id: str) -> dict[str, Any]:
        return await self._call("get_postmortem", {"query": {"report_id": report_id}}, signed=False)

    async def policy(self) -> dict[str, Any]:
        assert self._client
        res = await self._client.read_resource("qudisclose://policy")
        return json.loads(res.contents[0].text)  # type: ignore[union-attr]


def _structured(res: Any) -> dict[str, Any]:
    if getattr(res, "structured_content", None):
        return dict(res.structured_content)
    return json.loads(_text(res))


def _text(res: Any) -> str:
    return "\n".join(getattr(c, "text", "") for c in res.content)
