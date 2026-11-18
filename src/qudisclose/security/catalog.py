"""Tool inventory pinning (rug-pull / definition-drift protection).

The fingerprint covers every tool's name, description and input schema. Clients pin it on first
connect and refuse to call tools if the live catalog differs (see qudisclose.client)."""

from __future__ import annotations

from typing import Any

from qudisclose.models import canonical_json, sha256_hex


def catalog_fingerprint(tools: list[Any]) -> str:
    """`tools` may be mcp_types.Tool objects or dicts with name/description/inputSchema."""
    rows = []
    for t in tools:
        if isinstance(t, dict):
            name, desc, schema = t.get("name"), t.get("description"), t.get("inputSchema") or t.get("input_schema")
        else:
            name = getattr(t, "name")
            desc = getattr(t, "description", None)
            schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None)
        rows.append({"name": name, "description": desc or "", "schema": schema or {}})
    rows.sort(key=lambda r: r["name"])
    return sha256_hex(canonical_json(rows))
