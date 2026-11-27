"""The poll loop: read new findings, hold back the suppressed ones, forward the rest.

Each poll reads ``[cursor - overlap, now]``. The overlap catches findings that the
indexer writes late. A bounded set of the ids already handled stops a finding in
the overlap from being sent or counted twice. The cursor moves only after every
batch of the poll reached Vigil, so a failure repeats the poll, and Vigil skips
the ids it already stored.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from prometheus_client import CollectorRegistry, Counter, Gauge

from . import mapping
from .suppressions import Suppressions

log = logging.getLogger("vigil_wazuh5_bridge")


class Findings(Protocol):
    def findings_since(self, start_iso: str, end_iso: str) -> Iterable[Mapping[str, Any]]: ...


class Sink(Protocol):
    def send(self, findings: list[dict[str, Any]]) -> dict[str, Any]: ...


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def parse_ts(value: Any) -> dt.datetime | None:
    """An @timestamp, possibly with nanoseconds, to microseconds (the overlap covers the rest)."""
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    head, sep, tail = text.partition(".")
    if sep:
        digits = "".join(ch for ch in tail if ch.isdigit())
        zone = tail[len(digits) :]
        text = f"{head}.{digits[:6].ljust(6, '0')}{zone}"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


class Seen:
    """The most recent finding ids handled, oldest dropped first."""

    def __init__(self, capacity: int):
        self.capacity = capacity
        self._ids: OrderedDict[str, None] = OrderedDict()

    def __contains__(self, fid: str) -> bool:
        return fid in self._ids

    def add(self, fid: str) -> None:
        self._ids[fid] = None
        self._ids.move_to_end(fid)
        while len(self._ids) > self.capacity:
            self._ids.popitem(last=False)


@dataclass
class Metrics:
    registry: CollectorRegistry = field(default_factory=CollectorRegistry)

    def __post_init__(self) -> None:
        r = self.registry
        self.seen = Counter("wazuh5_bridge_findings_seen", "Findings read from Wazuh", registry=r)
        self.forwarded = Counter(
            "wazuh5_bridge_findings_forwarded", "Findings sent to Vigil", registry=r
        )
        self.suppressed = Counter(
            "wazuh5_bridge_findings_suppressed",
            "Findings held back (still in Wazuh), by suppression",
            ["suppression"],
            registry=r,
        )
        self.errors = Counter(
            "wazuh5_bridge_errors", "Failed polls, by stage", ["stage"], registry=r
        )
        self.last_success = Gauge(
            "wazuh5_bridge_last_success_timestamp_seconds",
            "End of the last poll that completed",
            registry=r,
        )
        self.lag = Gauge(
            "wazuh5_bridge_cursor_lag_seconds", "How far the cursor is behind now", registry=r
        )
        self.active = Gauge(
            "wazuh5_bridge_suppression_active",
            "1 while a suppression is in force, 0 after its review date",
            ["suppression"],
            registry=r,
        )


@dataclass
class PollResult:
    seen: int = 0
    forwarded: int = 0
    suppressed: dict[str, int] = field(default_factory=dict)
    skipped_known: int = 0


class Bridge:
    def __init__(
        self,
        findings: Findings,
        sink: Sink,
        suppressions: Suppressions,
        *,
        overlap: dt.timedelta = dt.timedelta(minutes=10),
        initial_lookback: dt.timedelta = dt.timedelta(hours=1),
        max_lookback: dt.timedelta = dt.timedelta(days=1),
        batch_size: int = 200,
        seen_capacity: int = 50_000,
        dry_run: bool = False,
        metrics: Metrics | None = None,
        clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
    ):
        self.findings = findings
        self.sink = sink
        self.suppressions = suppressions
        self.overlap = overlap
        self.initial_lookback = initial_lookback
        self.max_lookback = max_lookback
        self.batch_size = batch_size
        self.dry_run = dry_run
        self.metrics = metrics or Metrics()
        self.clock = clock
        self.cursor: dt.datetime | None = None
        self.last_success: float = 0.0  # epoch seconds of the last completed poll
        self.seen = Seen(seen_capacity)
        self._warned_expired: set[str] = set()

    def _refresh_suppression_state(self, today: dt.date) -> None:
        for s in self.suppressions.entries:
            expired = s.expired(today)
            self.metrics.active.labels(s.id).set(0 if expired else 1)
            if expired and s.id not in self._warned_expired:
                self._warned_expired.add(s.id)
                log.warning(
                    "suppression %s passed its review date %s: its findings reach Vigil again",
                    s.id,
                    s.review_by.isoformat(),
                )

    def poll(self) -> PollResult:
        now = self.clock()
        today = now.date()
        self._refresh_suppression_state(today)
        if self.cursor is None:
            start = now - self.initial_lookback
        else:
            start = max(self.cursor - self.overlap, now - self.max_lookback)
            if self.cursor - self.overlap < now - self.max_lookback:
                # Down for longer than max_lookback: those findings are still in Wazuh,
                # but Vigil does not get them. Say so once per poll that skips them.
                self.metrics.errors.labels("gap").inc()
                log.warning(
                    "gap: findings from %s to %s are not forwarded (older than max_lookback)",
                    iso(self.cursor - self.overlap),
                    iso(start),
                )
        result = PollResult()
        newest = self.cursor
        batch: list[dict[str, Any]] = []
        batch_ids: list[str] = []

        def flush() -> None:
            if not batch:
                return
            if not self.dry_run:
                self.sink.send(list(batch))
            for fid in batch_ids:
                self.seen.add(fid)
            self.metrics.forwarded.inc(len(batch))
            result.forwarded += len(batch)
            batch.clear()
            batch_ids.clear()

        for hit in self.findings.findings_since(iso(start), iso(now)):
            fid = mapping.finding_id(str(hit["_id"]))
            ts = parse_ts(hit.get("_source", {}).get("@timestamp"))
            if ts is not None and (newest is None or ts > newest):
                newest = ts
            if fid in self.seen:
                result.skipped_known += 1
                continue
            result.seen += 1
            self.metrics.seen.inc()
            match = self.suppressions.match(hit.get("_source", {}), today)
            if match is not None:
                self.seen.add(fid)
                self.metrics.suppressed.labels(match.id).inc()
                result.suppressed[match.id] = result.suppressed.get(match.id, 0) + 1
                continue
            batch.append(mapping.to_vigil(hit))
            batch_ids.append(fid)
            if len(batch) >= self.batch_size:
                flush()
        flush()

        # Every batch of this poll arrived: move on. (An exception above skips this.)
        self.cursor = min(newest or now, now)
        self.last_success = now.timestamp()
        self.metrics.last_success.set(self.last_success)
        self.metrics.lag.set(max(0.0, (now - self.cursor).total_seconds()))
        return result

    def run_forever(self, interval: float, stop: Callable[[], bool] = lambda: False) -> None:
        while not stop():
            started = time.monotonic()
            try:
                r = self.poll()
                log.info(
                    "poll: %d new, %d forwarded, %d suppressed %s",
                    r.seen,
                    r.forwarded,
                    sum(r.suppressed.values()),
                    r.suppressed or "",
                )
            except Exception as exc:
                stage = "vigil" if "Vigil" in str(exc) else "indexer"
                self.metrics.errors.labels(stage).inc()
                log.error("poll failed (%s): %s. The next poll repeats it", stage, exc)
            time.sleep(max(0.0, interval - (time.monotonic() - started)))
