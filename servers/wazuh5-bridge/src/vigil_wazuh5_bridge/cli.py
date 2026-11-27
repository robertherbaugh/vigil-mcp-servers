"""``vigil-wazuh5-bridge``: run, validate a suppression file, or report what it would do.

    vigil-wazuh5-bridge run                    # the service (environment below)
    vigil-wazuh5-bridge validate FILE          # CI: exit 1 on an invalid file
    vigil-wazuh5-bridge report --hours 24      # read-only: counts per suppression, no sends

Environment (``run`` and ``report``):

    WAZUH_INDEXER_URL        https://wazuh-indexer.example:9200
    WAZUH_INDEXER_USERNAME   a user with read on the findings indices only
    WAZUH_INDEXER_PASSWORD
    WAZUH_INDEXER_CA         CA bundle for the indexer (optional: system store)
    WAZUH_FINDINGS_INDEX     default wazuh-findings-v5-*
    VIGIL_URL                http://vigil-backend:6987 (``run`` only)
    VIGIL_TOKEN              service-account token: findings.read, findings.write
    VIGIL_CA                 CA bundle for Vigil (optional)
    SUPPRESSIONS_FILE        default /etc/wazuh5-bridge/suppressions.yaml
    POLL_INTERVAL_SECONDS    default 60
    OVERLAP_MINUTES          default 10
    INITIAL_LOOKBACK_HOURS   default 1 (first poll after a start)
    MAX_LOOKBACK_HOURS       default 24
    METRICS_PORT             default 9108 (/metrics, /healthz)
    DRY_RUN                  "true": read and count, never send
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from prometheus_client import generate_latest

from . import suppressions as sup
from .bridge import Bridge, Metrics
from .clients import VigilIngest, WazuhIndexer


def _env(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise SystemExit(f"{name} is required")
    return value or ""


def _verify(ca_var: str) -> str | bool:
    return os.environ.get(ca_var) or True


def _indexer() -> WazuhIndexer:
    client = httpx.Client(
        base_url=_env("WAZUH_INDEXER_URL", required=True),
        auth=(
            _env("WAZUH_INDEXER_USERNAME", required=True),
            _env("WAZUH_INDEXER_PASSWORD", required=True),
        ),
        verify=_verify("WAZUH_INDEXER_CA"),
        timeout=30.0,
    )
    return WazuhIndexer(client, _env("WAZUH_FINDINGS_INDEX", "wazuh-findings-v5-*"))


def _vigil() -> VigilIngest:
    client = httpx.Client(
        base_url=_env("VIGIL_URL", required=True),
        headers={"Authorization": f"Bearer {_env('VIGIL_TOKEN', required=True)}"},
        verify=_verify("VIGIL_CA"),
        timeout=60.0,
    )
    return VigilIngest(client)


class _NoSink:
    def send(self, findings):
        return {}


def _serve(metrics: Metrics, healthy, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/metrics":
                body, status, ctype = generate_latest(metrics.registry), 200, "text/plain"
            elif self.path == "/healthz":
                ok = healthy()
                body, status, ctype = (
                    (b"ok" if ok else b"stale"),
                    (200 if ok else 503),
                    "text/plain",
                )
            else:
                body, status, ctype = b"not found", 404, "text/plain"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # no access log
            pass

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)  # noqa: S104 - in-pod port
    threading.Thread(target=server.serve_forever, daemon=True).start()


def cmd_run() -> int:
    interval = float(_env("POLL_INTERVAL_SECONDS", "60"))
    path = _env("SUPPRESSIONS_FILE", "/etc/wazuh5-bridge/suppressions.yaml")
    try:
        suppressions = sup.load(path)
    except (sup.SuppressionError, OSError, ValueError) as exc:
        # Refuse to start: forwarding everything, or nothing, would both be wrong.
        raise SystemExit(f"suppressions {path}: {exc}") from None
    dry = _env("DRY_RUN", "false").lower() == "true"
    metrics = Metrics()
    bridge = Bridge(
        _indexer(),
        _NoSink() if dry else _vigil(),
        suppressions,
        overlap=dt.timedelta(minutes=float(_env("OVERLAP_MINUTES", "10"))),
        initial_lookback=dt.timedelta(hours=float(_env("INITIAL_LOOKBACK_HOURS", "1"))),
        max_lookback=dt.timedelta(hours=float(_env("MAX_LOOKBACK_HOURS", "24"))),
        dry_run=dry,
        metrics=metrics,
    )

    def healthy() -> bool:
        last = bridge.last_success
        return last > 0 and dt.datetime.now(dt.UTC).timestamp() - last < 5 * interval

    _serve(metrics, healthy, int(_env("METRICS_PORT", "9108")))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    logging.getLogger("vigil_wazuh5_bridge").info(
        "started: %d suppression(s), %s, every %ss",
        len(suppressions.entries),
        "dry run" if dry else "forwarding",
        interval,
    )
    bridge.run_forever(interval, stop.is_set)
    return 0


def cmd_validate(path: str) -> int:
    try:
        s = sup.load(path)
    except (sup.SuppressionError, OSError, ValueError) as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 1
    today = dt.date.today()
    for e in s.entries:
        state = "EXPIRED" if e.expired(today) else f"review by {e.review_by.isoformat()}"
        print(f"ok  {e.id}: {len(e.rule_ids)} rule(s), {len(e.conditions)} condition(s), {state}")
    return 0


def cmd_report(hours: float, path: str) -> int:
    """Read-only: what each suppression would hold back over the last hours."""
    suppressions = sup.load(path)
    bridge = Bridge(
        _indexer(),
        _NoSink(),
        suppressions,
        dry_run=True,
        initial_lookback=dt.timedelta(hours=hours),
    )
    r = bridge.poll()
    print(
        json.dumps(
            {
                "hours": hours,
                "findings": r.seen,
                "would_forward": r.forwarded,
                "would_suppress": r.suppressed,
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="vigil-wazuh5-bridge")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    v = sub.add_parser("validate")
    v.add_argument("file")
    rep = sub.add_parser("report")
    rep.add_argument("--hours", type=float, default=24.0)
    rep.add_argument(
        "--file",
        default=os.environ.get("SUPPRESSIONS_FILE", "/etc/wazuh5-bridge/suppressions.yaml"),
    )
    args = p.parse_args(argv)
    if args.cmd == "run":
        return cmd_run()
    if args.cmd == "validate":
        return cmd_validate(args.file)
    return cmd_report(args.hours, args.file)


if __name__ == "__main__":
    raise SystemExit(main())
