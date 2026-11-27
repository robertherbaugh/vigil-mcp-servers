# wazuh5-bridge

Forwards [Wazuh 5](https://wazuh.com) findings to [Vigil](https://github.com/Vigil-SOC/vigil), and holds back the ones that a reviewed suppression file says are normal operation.

**Status:** implemented and tested against the Wazuh 5.0.0-rc2 finding shape. It is not an MCP server: it is a small polling worker. It reads only; it never changes Wazuh.

## Why it exists

- **Vigil cannot read Wazuh 5 findings yet.** Wazuh 5 writes Sigma findings to `wazuh-findings-v5-*` as ECS documents (`wazuh.rule.*`). Vigil's OpenSearch integration reads Security Analytics findings (`queries[]`, `related_doc_ids`), a different shape, and its Wazuh integration reads only the manager API.
- **Wazuh 5.0 cannot tune one standard rule.** The standard ruleset is read-only. You can turn off a whole integration, not one rule, and you cannot add an exception to one ([wazuh-indexer-plugins#1772](https://github.com/wazuh/wazuh-indexer-plugins/issues/1772)). On a Kubernetes node, a few standard rules fire on normal operation thousands of times a day.

So the bridge suppresses where findings are consumed. **Nothing is deleted:** Wazuh keeps every event and finding for its own retention, and the bridge counts what it held back, per suppression.

## How it works

1. Every `POLL_INTERVAL_SECONDS` it searches `wazuh-findings-v5-*` for `@timestamp` in `[cursor - overlap, now]`, oldest first, with `search_after`. The overlap catches findings that the indexer writes late.
2. For each finding it has not handled yet, the first active suppression that matches holds it back. Otherwise it is mapped to a Vigil finding: `wazuh5-<_id>`, the rule title, severity, MITRE techniques, host, user and IPs, with the Wazuh document as raw data.
3. It posts batches to Vigil's `POST /api/ingest/ingest-string` with a service-account token. Vigil skips an id it already has, so a retry never duplicates a finding.
4. The cursor moves only when every batch of the poll arrived. A failure repeats the poll.

After a restart it starts `INITIAL_LOOKBACK_HOURS` back. After an outage longer than `MAX_LOOKBACK_HOURS` it logs a **gap** (`wazuh5_bridge_errors{stage="gap"}`). Those findings are still in Wazuh, but Vigil does not get them.

## Suppressions

A YAML file, reviewed like code. See [`examples/suppressions.example.yaml`](examples/suppressions.example.yaml). The bridge refuses a file that breaks these rules:

- **Narrow.** Each entry names Wazuh rule ids **and** at least one field condition. A rule id alone is too broad.
- **Fails toward forwarding.** Every condition must hold. A missing field fails its condition.
- **Reviewed.** A `reason` and a `review_by` date at most a year ahead. After that date the entry stops suppressing: its findings reach Vigil again until someone reviews it.
- **Operators:** `equals`, `in`, `prefix` (3 characters or more) and `regex` (`re.search`; a pattern that matches an empty string is refused). A list field matches when any element matches.

Check a change before it ships:

```sh
vigil-wazuh5-bridge validate suppressions.yaml        # exit 1 if invalid
vigil-wazuh5-bridge report --hours 24 --file suppressions.yaml   # read only: counts, no sends
```

## Configuration

| Variable | Default | |
|---|---|---|
| `WAZUH_INDEXER_URL` | required | `https://indexer.example:9200` |
| `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD` | required | A user with read on the findings indices only |
| `WAZUH_INDEXER_CA` | system store | CA bundle for the indexer |
| `WAZUH_FINDINGS_INDEX` | `wazuh-findings-v5-*` | Narrow it to exclude old indices |
| `VIGIL_URL` | required | `http://vigil-backend:6987` |
| `VIGIL_TOKEN` | required | Service-account token with `findings.read` and `findings.write` |
| `VIGIL_CA` | system store | |
| `SUPPRESSIONS_FILE` | `/etc/wazuh5-bridge/suppressions.yaml` | |
| `POLL_INTERVAL_SECONDS` | `60` | |
| `OVERLAP_MINUTES` | `10` | |
| `INITIAL_LOOKBACK_HOURS` | `1` | First poll after a start |
| `MAX_LOOKBACK_HOURS` | `24` | |
| `METRICS_PORT` | `9108` | `/metrics` (Prometheus) and `/healthz` |
| `DRY_RUN` | `false` | `true`: read and count, never send |

The indexer role needs only `read` (and `indices:data/read/search`) on the findings indices.

## Metrics

| Metric | |
|---|---|
| `wazuh5_bridge_findings_seen_total` | Findings read |
| `wazuh5_bridge_findings_forwarded_total` | Sent to Vigil |
| `wazuh5_bridge_findings_suppressed_total{suppression}` | Held back, per entry. A sudden change is worth a look |
| `wazuh5_bridge_suppression_active{suppression}` | 1 in force, 0 after its review date |
| `wazuh5_bridge_errors_total{stage}` | `indexer`, `vigil`, `gap` |
| `wazuh5_bridge_last_success_timestamp_seconds`, `wazuh5_bridge_cursor_lag_seconds` | Liveness |

`/healthz` answers 503 when no poll completed in 5 intervals.

## Image

```sh
docker build -f servers/wazuh5-bridge/Dockerfile -t vigil-wazuh5-bridge .
```

Non-root (uid 10001), and it works with a read-only root filesystem.
