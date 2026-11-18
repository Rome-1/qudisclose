"""Token-bucket rate limiting per non-human identity."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, rate_per_minute: int = 60, burst: int | None = None) -> None:
        self._rate = rate_per_minute / 60.0
        self._burst = burst or rate_per_minute
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, identity: str, *, now: float | None = None) -> bool:
        t = now if now is not None else time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(identity, (float(self._burst), t))
            tokens = min(self._burst, tokens + (t - last) * self._rate)
            if tokens < 1:
                self._buckets[identity] = (tokens, t)
                return False
            self._buckets[identity] = (tokens - 1, t)
            return True
