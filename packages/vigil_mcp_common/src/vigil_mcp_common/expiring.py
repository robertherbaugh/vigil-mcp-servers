"""Actions that undo themselves after a TTL.

Prefer the vendor's own expiry when it has one (a firewall rule with an end time,
a Grafana silence's ``endsAt``): it survives this server going away. Use this
registry when the vendor has none. Records are plain JSON, optionally kept in a
state file, so a restart still undoes what was applied before it.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

Undo = Callable[["ExpiringAction"], None]


class TtlOutOfRange(ValueError):
    """The requested TTL is outside the server's bounds."""


@dataclass(frozen=True)
class TtlBounds:
    min_seconds: int = 60
    max_seconds: int = 24 * 3600

    def clamp_check(self, seconds: int) -> int:
        """Return ``seconds`` if it is within bounds; refuse it otherwise (never clamp silently)."""
        if not self.min_seconds <= seconds <= self.max_seconds:
            raise TtlOutOfRange(
                f"ttl_seconds must be between {self.min_seconds} and {self.max_seconds}"
            )
        return seconds


@dataclass
class ExpiringAction:
    kind: str
    target: str
    expires_at: float
    params: dict[str, Any] = field(default_factory=dict)
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    applied_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class SweepResult:
    undone: list[str]
    failed: dict[str, str]


class ExpiringActions:
    """Track applied actions and undo each one when its TTL ends.

    Register one undo handler per ``kind``. ``sweep()`` undoes every expired action;
    an undo that raises stays in the registry and is retried on the next sweep.
    """

    def __init__(
        self,
        state_file: str | os.PathLike[str] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self._state_file = Path(state_file) if state_file else None
        self._clock = clock
        self._undo: dict[str, Undo] = {}
        self._actions: dict[str, ExpiringAction] = {}
        self._lock = threading.Lock()
        self._load()

    def on_expiry(self, kind: str, undo: Undo) -> None:
        self._undo[kind] = undo

    def add(self, kind: str, target: str, ttl_seconds: float, **params: Any) -> ExpiringAction:
        if kind not in self._undo:
            raise KeyError(f"no undo handler registered for {kind!r}")
        action = ExpiringAction(kind, target, self._clock() + ttl_seconds, dict(params))
        with self._lock:
            self._actions[action.action_id] = action
            self._save()
        return action

    def remove(self, action_id: str) -> ExpiringAction | None:
        """Forget an action (it was undone early). Returns it, or None."""
        with self._lock:
            action = self._actions.pop(action_id, None)
            self._save()
        return action

    def active(self) -> list[ExpiringAction]:
        with self._lock:
            return sorted(self._actions.values(), key=lambda a: a.expires_at)

    def find(self, kind: str, target: str) -> ExpiringAction | None:
        return next((a for a in self.active() if a.kind == kind and a.target == target), None)

    def sweep(self) -> SweepResult:
        now = self._clock()
        with self._lock:
            due = [a for a in self._actions.values() if a.expires_at <= now]
        undone: list[str] = []
        failed: dict[str, str] = {}
        for action in due:
            try:
                self._undo[action.kind](action)
            except Exception as exc:  # retried on the next sweep
                failed[action.action_id] = type(exc).__name__
                continue
            undone.append(action.action_id)
        with self._lock:
            for action_id in undone:
                self._actions.pop(action_id, None)
            self._save()
        return SweepResult(undone, failed)

    def start_sweeper(self, interval_seconds: float = 15.0) -> threading.Event:
        """Sweep in a daemon thread every ``interval_seconds``. Set the returned event to stop."""
        stop = threading.Event()

        def loop() -> None:
            while not stop.wait(interval_seconds):
                self.sweep()

        threading.Thread(target=loop, name="expiring-actions", daemon=True).start()
        return stop

    def _load(self) -> None:
        if not self._state_file or not self._state_file.exists():
            return
        rows = json.loads(self._state_file.read_text() or "[]")
        self._actions = {row["action_id"]: ExpiringAction(**row) for row in rows}

    def _save(self) -> None:
        if not self._state_file:
            return
        tmp = self._state_file.with_suffix(self._state_file.suffix + ".tmp")
        tmp.write_text(json.dumps([asdict(a) for a in self._actions.values()]))
        tmp.replace(self._state_file)
