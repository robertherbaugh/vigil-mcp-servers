"""One JSON line per tool call: who, what, on which target, and what happened.

Never pass secrets. As a second line of defence, any field whose name looks like a
credential is replaced with ``[redacted]``, at any depth.
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime
from typing import Any, TextIO

_SECRET_HINTS = (
    "token",
    "password",
    "passwd",
    "secret",
    "authorization",
    "private_key",
    "apikey",
    "api_key",
    "cookie",
    "credential",
)
REDACTED = "[redacted]"


def _looks_secret(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(hint in lowered for hint in _SECRET_HINTS)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (REDACTED if _looks_secret(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value


class AuditLog:
    """Writes audit events as JSON lines to ``stream`` (stdout by default)."""

    def __init__(self, server: str, stream: TextIO | None = None):
        self.server = server
        self._stream = stream
        self._lock = threading.Lock()

    def record(
        self,
        *,
        tool: str,
        principal: str | None,
        outcome: str,
        effect: str,
        target: str | None = None,
        detail: str | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "event": "tool_call",
            "server": self.server,
            "tool": tool,
            "effect": effect,
            "principal": principal,
            "target": target,
            "outcome": outcome,
        }
        if detail is not None:
            event["detail"] = detail
        event.update(redact(fields))
        line = json.dumps(event, default=str, sort_keys=True)
        stream = self._stream or sys.stdout
        with self._lock:
            stream.write(line + "\n")
            stream.flush()
        return event
