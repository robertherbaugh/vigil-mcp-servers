"""A sliding-window limit per key (usually the tool name).

This is the server's own cap, independent of Vigil's ``released_per_hour``: a
caller that bypasses Vigil still meets it.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass


class RateLimited(RuntimeError):
    """The key has used its calls for the window."""

    def __init__(self, key: str, retry_after: float):
        super().__init__(f"rate limit for {key!r}: retry after {retry_after:.0f}s")
        self.key = key
        self.retry_after = retry_after


@dataclass(frozen=True)
class Limit:
    calls: int
    per_seconds: float

    def __post_init__(self) -> None:
        if self.calls < 0 or self.per_seconds <= 0:
            raise ValueError("calls must be >= 0 and per_seconds > 0")


class RateLimiter:
    """``acquire(key)`` takes one call from ``key``'s window or raises ``RateLimited``."""

    def __init__(
        self,
        limits: dict[str, Limit],
        default: Limit | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._limits = dict(limits)
        self._default = default
        self._clock = clock
        self._calls: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def limit_for(self, key: str) -> Limit | None:
        return self._limits.get(key, self._default)

    def acquire(self, key: str) -> None:
        limit = self.limit_for(key)
        if limit is None:
            return
        now = self._clock()
        with self._lock:
            window = self._calls.setdefault(key, deque())
            while window and window[0] <= now - limit.per_seconds:
                window.popleft()
            if len(window) >= limit.calls:
                retry = (window[0] + limit.per_seconds - now) if window else limit.per_seconds
                raise RateLimited(key, retry)
            window.append(now)

    def describe(self) -> dict[str, dict[str, float]]:
        out = {k: {"calls": v.calls, "per_seconds": v.per_seconds} for k, v in self._limits.items()}
        if self._default is not None:
            out["*"] = {"calls": self._default.calls, "per_seconds": self._default.per_seconds}
        return out
