"""The two HTTP clients: the Wazuh indexer (read only) and Vigil (findings ingest)."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

import httpx

# A stable order for paging: one event can match two rules, so it gives two
# findings with the same timestamp and event id. numeric_type keeps the sort
# values comparable when the pattern covers date and date_nanos indices.
SORT = [
    {"@timestamp": {"order": "asc", "numeric_type": "date_nanos"}},
    {"wazuh.event.id": {"order": "asc", "missing": "_last", "unmapped_type": "keyword"}},
    {"wazuh.rule.id": {"order": "asc", "missing": "_last", "unmapped_type": "keyword"}},
]


class UpstreamError(RuntimeError):
    """A call to the indexer or to Vigil did not succeed."""


class WazuhIndexer:
    """Search ``wazuh-findings-v5-*``. Needs only read rights on those indices."""

    def __init__(self, client: httpx.Client, index_pattern: str, page_size: int = 500):
        self.client = client
        self.index_pattern = index_pattern
        self.page_size = page_size

    def findings_since(self, start_iso: str, end_iso: str) -> Iterator[Mapping[str, Any]]:
        """Every finding with start <= @timestamp <= end, oldest first, page by page."""
        search_after: Sequence[Any] | None = None
        while True:
            body: dict[str, Any] = {
                "size": self.page_size,
                "sort": SORT,
                "query": {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                "track_total_hits": False,
            }
            if search_after is not None:
                body["search_after"] = list(search_after)
            path = f"/{self.index_pattern}/_search"
            try:
                resp = self.client.post(path, json=body, params={"ignore_unavailable": "true"})
            except httpx.HTTPError as exc:
                raise UpstreamError(f"indexer search failed: {type(exc).__name__}") from exc
            if resp.status_code != 200:
                raise UpstreamError(f"indexer search failed: HTTP {resp.status_code}")
            hits = resp.json().get("hits", {}).get("hits", [])
            yield from hits
            if len(hits) < self.page_size:
                return
            search_after = hits[-1].get("sort")
            if not search_after:
                return


class VigilIngest:
    """POST findings to Vigil's ``/api/ingest/ingest-string`` with a service-account token.

    The token needs ``findings.read`` and ``findings.write``. Vigil skips a
    finding id it already has, so a retry never duplicates a finding.

    JSON Lines, not JSON: a JSON payload may also carry a ``cases`` array, so Vigil
    asks for ``cases.write`` too. A JSON Lines payload of findings cannot create
    cases, so the token needs only the two findings permissions.
    """

    PATH = "/api/ingest/ingest-string"

    def __init__(self, client: httpx.Client):
        self.client = client

    def send(self, findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        if not findings:
            return {"findings_imported": 0, "findings_skipped": 0, "findings_errors": 0}
        form = {
            "data": "\n".join(json.dumps(f, default=str) for f in findings),
            "format": "jsonl",
            "data_type": "finding",
        }
        try:
            resp = self.client.post(self.PATH, data=form)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"Vigil ingest failed: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise UpstreamError(f"Vigil ingest failed: HTTP {resp.status_code}")
        stats = resp.json()
        if int(stats.get("findings_errors") or 0):
            # The batch is retried at the next poll. Vigil skips the ones it stored.
            raise UpstreamError(f"Vigil rejected {stats['findings_errors']} finding(s)")
        return stats
