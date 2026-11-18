"""RFC 8785 (JCS) canonical JSON, byte-identical to the reference verifier's `canonical()` in the vsla repository
(tools/vsla_verify.py). Every signed body in VSLA (statement, receipt, ledger entry, weight attestation, anchor, quote
body) and every Merkle leaf goes through this function; two implementations that canonicalise differently reject each
other's signatures and compute different ledger roots (spec: provenance.md, "Canonical JSON").

JCS numbers are IEEE-754 doubles: an integer outside the exact range (|n| > 2^53) is serialised as the double it parses
to, so a Go or JavaScript implementation computes the same bytes. A lone surrogate is not UTF-8 and raises. Signed
payloads are parsed with `parse_canonical`, which rejects duplicate keys and bytes that do not re-serialise to themselves,
so two conforming parsers cannot read different values from one signed payload."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

MAX_SAFE_INT = 2**53


def _es6_number(x: float) -> str:
    """Number serialisation per ECMAScript Number::toString, as RFC 8785 requires."""
    if x != x or x in (math.inf, -math.inf):
        raise ValueError("NaN and Infinity are not JSON")
    if x == 0:
        return "0"
    sign, x = ("-" if x < 0 else ""), abs(x)
    r = repr(x)
    mant, exp = (r.split("e") + ["0"])[:2] if "e" in r else (r, "0")
    ip, fp = (mant.split(".") + [""])[:2]
    if ip.strip("0") == "":
        n = -(len(fp) - len(fp.lstrip("0"))) + int(exp)
    else:
        n = len(ip.lstrip("0")) + int(exp)
    digits = (ip + fp).lstrip("0").rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    es = ("+" if e >= 0 else "-") + str(abs(e))
    return sign + (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + es


def _jcs(obj: Any, out: list[str]) -> None:
    if obj is None:
        out.append("null")
    elif obj is True:
        out.append("true")
    elif obj is False:
        out.append("false")
    elif isinstance(obj, int):
        out.append(str(obj) if abs(obj) <= MAX_SAFE_INT else _es6_number(float(obj)))
    elif isinstance(obj, float):
        out.append(_es6_number(obj))
    elif isinstance(obj, str):
        out.append(json.dumps(obj, ensure_ascii=False))
    elif isinstance(obj, (list, tuple)):
        out.append("[")
        for i, v in enumerate(obj):
            if i:
                out.append(",")
            _jcs(v, out)
        out.append("]")
    elif isinstance(obj, dict):
        out.append("{")
        for i, k in enumerate(sorted(obj, key=lambda s: s.encode("utf-16-be", "surrogatepass"))):
            if not isinstance(k, str):
                raise TypeError("object keys must be strings")
            if i:
                out.append(",")
            out.append(json.dumps(k, ensure_ascii=False))
            out.append(":")
            _jcs(obj[k], out)
        out.append("}")
    else:
        raise TypeError(f"not JSON-serialisable: {type(obj).__name__}")


def canonical(obj: Any) -> bytes:
    """RFC 8785 (JCS): keys sorted by UTF-16 code units, no whitespace, ES6 number formatting, UTF-8.
    Raises ValueError/TypeError on NaN, lone surrogates and non-JSON values."""
    out: list[str] = []
    _jcs(obj, out)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("lone surrogate is not valid UTF-8") from exc


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


MAX_PAYLOAD_BYTES = 4 * 1024 * 1024   # a signed payload larger than this fails the check that reads it


def parse_canonical(data: bytes) -> Any:
    """Parse bytes that MUST be RFC 8785 canonical JSON (no duplicate keys; re-serialises to itself). Raises ValueError,
    also for an oversized or pathologically nested payload."""
    if len(data) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload too large")
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"not JSON: {exc}") from exc
    if canonical(obj) != data:
        raise ValueError("payload is not RFC 8785 canonical")
    return obj


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> dict[str, str]:
    """{"sha256": ...} over bytes, a UTF-8 string, or the canonical JSON of anything else."""
    data = obj if isinstance(obj, bytes) else (obj.encode() if isinstance(obj, str) else canonical(obj))
    return {"sha256": sha256_hex(data)}
