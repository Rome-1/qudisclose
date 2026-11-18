"""RFC 6962 Merkle tree over transcript leaves (VSLA spec: provenance.md, "Transcript Merkle tree").

leaf = SHA-256(0x00 || leaf bytes); node = SHA-256(0x01 || left || right); an odd node is promoted unchanged.
Leaf bytes are the RFC 8785 canonical JSON of the leaf body. Byte-for-byte identical to the reference verifier."""

from __future__ import annotations

import hashlib
from typing import Any

from qudisclose.vsla.canonical import canonical, sha256_hex


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> str:
    if not leaves:
        return sha256_hex(b"")
    level = [leaf_hash(x) for x in leaves]
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1]) if i + 1 < len(level) else level[i] for i in range(0, len(level), 2)]
    return level[0].hex()


def inclusion_proof(leaves: list[bytes], index: int) -> list[tuple[str, str]]:
    level = [leaf_hash(x) for x in leaves]
    path: list[tuple[str, str]] = []
    i = index
    while len(level) > 1:
        sib = i ^ 1
        if sib < len(level):
            path.append(("L" if sib < i else "R", level[sib].hex()))
        level = [node_hash(level[j], level[j + 1]) if j + 1 < len(level) else level[j] for j in range(0, len(level), 2)]
        i //= 2
    return path


def verify_inclusion(leaf: bytes, proof: list[tuple[str, str]], root: str) -> bool:
    h = leaf_hash(leaf)
    for side, sib in proof:
        s = bytes.fromhex(sib)
        h = node_hash(s, h) if side == "L" else node_hash(h, s)
    return h.hex() == root


def leaf_bytes(leaves: list[dict[str, Any]]) -> list[bytes]:
    """Canonical bytes of each transcript leaf (the reference verifier's `transcript_leaves`)."""
    return [canonical(x) for x in leaves]
