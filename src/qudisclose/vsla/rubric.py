"""The trust rubric, v1.1 (spec: trust-rubric.md). Identical arithmetic to the reference verifier.

Inputs are verified ledger bodies (the caller has already dropped entries whose countersignature did
not verify under a pinned key, or that name another finder or track; VSLA-V-5). Neutral outcomes (duplicate,
withdrawn, reproduced-unresolved) are excluded from the window so they can neither pump nor sink the score; rejections
are summed with decay; over-claiming half the window disqualifies; the age gate is a hard floor, not a term. `m`
counts distinct operators (the name part of the countersigner keyid), not keyids."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

DISQUALIFYING = {"non-authoritative-release", "ledger-fork", "retracted"}
NEGATIVE = {"rejected", "false-positive"}
NEUTRAL = {"duplicate", "withdrawn", "reproduced-unresolved"}


def _days(v: Any) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, datetime):
        return v.timestamp() / 86400
    return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() / 86400


def countersigner_operator(keyid: str) -> str:
    """A keyid is `<role>:<operator name>`; two keys of one operator (platform:acme and maintainer:acme) are one countersigner."""
    return keyid.split(":", 1)[1] if ":" in keyid else keyid


def trust_score(entries: list[dict[str, Any]], *, window: int = 50, now_days: float | None = None) -> dict[str, Any]:
    """The window is the last W counted entries by countersigned `at` (stable on presented index), so presented order cannot
    move the score; `now_days` is the evaluation instant (a verifier passes t_eval)."""
    ents = [e for e in entries if e.get("countersigner") and e.get("kind", "outcome") == "outcome" and e.get("outcome") not in NEUTRAL]
    ents = [e for _, e in sorted(enumerate(ents), key=lambda ie: (_days(ie[1]["at"]), ie[0]))][-window:]
    n = len(ents)
    if n == 0:
        return {"score": 0.0, "n": 0, "accepted": 0, "rejected": 0, "disqualifying": 0, "countersigners": 0, "over_claims": 0,
                "age_days": 0.0, "components": {}, "reason": "no countersigned entries"}
    now = now_days if now_days is not None else datetime.now(UTC).timestamp() / 86400
    a = sum(e["outcome"] == "accepted" and not e.get("vouched") for e in ents)
    x = sum(e["outcome"] in DISQUALIFYING for e in ents)
    m = len({countersigner_operator(e["countersigner"]) for e in ents})
    o = sum(1 for e in ents if e.get("claimed") is not None and e.get("verified") is not None and e["claimed"] > e["verified"])
    age = max(0.0, now - min(_days(e["at"]) for e in ents))
    neg_ages = [max(0.0, now - _days(e["at"])) for e in ents if e["outcome"] in NEGATIVE]
    P = a / n
    B = min(1.0, m / 3)
    S = min(1.0, age / 90) * min(1.0, n / 10)
    C = max(0.0, 1 - 2 * o / n)
    R = 1 - 0.5 * min(1.0, sum(math.exp(-d / 30) for d in neg_ages))
    disqualified = x > 0 or o / n >= 0.5
    score = 0.0 if disqualified else P * (0.5 + 0.2 * B + 0.2 * S + 0.1 * C) * R
    return {"score": round(score, 4), "n": n, "accepted": a, "rejected": len(neg_ages), "disqualifying": x,
            "countersigners": m, "over_claims": o, "age_days": round(age, 1),
            "components": {"P": round(P, 4), "B": round(B, 4), "S": round(S, 4), "C": round(C, 4), "R": round(R, 4)}}


def meets_floor(ts: dict[str, Any], *, floor: float = 0.6, min_entries: int = 5, min_countersigners: int = 2, min_age_days: float = 30) -> tuple[bool, str]:
    ok = (ts["n"] >= min_entries and ts["countersigners"] >= min_countersigners and ts["age_days"] >= min_age_days and ts["score"] >= floor)
    return ok, f"score {ts['score']} n={ts['n']} m={ts['countersigners']} age={ts['age_days']}d (floor {floor}, n>={min_entries}, m>={min_countersigners}, age>={min_age_days}d)"
