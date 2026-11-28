# wazuh5

Read-only MCP tools on a [Wazuh 5](https://wazuh.com) indexer, so [Vigil](https://github.com/Vigil-SOC/vigil)'s agents can investigate: findings (alerts), the events around them, and a host's state.

**Status:** implemented and tested against the Wazuh 5.0.0-rc2 document shapes. **Every tool reads.** None changes Wazuh. Active response (block an address, disable an account) is a separate, reversible design in [`docs/ROADMAP.md`](../../docs/ROADMAP.md).

## Tools

| Tool | Class | What it answers |
|---|---|---|
| `describe_policy` | read | The limits, the indices it reads, each tool's effect class |
| `search_findings(since, until, filters, text, limit)` | read | Which alerts fired; each result names its triggering event |
| `search_events(since, until, filters, text, limit)` | read | Every decoded log line, for context before and after an alert |
| `get_finding(finding_id)` | read | One finding, with its triggering event. Takes a Wazuh id or a `wazuh5-<id>` Vigil id from [wazuh5-bridge](../wazuh5-bridge) |
| `get_event(index, doc_id)` | read | One event from a `.ds-wazuh-events-v5-*` backing index |
| `top_values(field, source, since, until, filters, size)` | read | The most frequent rules, hosts, users or addresses |
| `host_inventory(agent, kind)` | read | Packages, processes, ports, users, services, vulnerabilities, SCA and more. Needs a full Wazuh agent on the host |

## Guard rails

Arguments come from a model, and log lines can steer a model. So the server treats every argument as untrusted, on top of a read-only indexer login:

- **Time:** a window that ends now or earlier, at most `MAX_WINDOW_DAYS` (7) long.
- **Size:** at most `MAX_RESULTS` (100) documents and `MAX_BUCKETS` (50) buckets. Long strings are cut at 1,000 characters, long lists at 50 items.
- **Filters:** exact `term`/`terms` matches on checked field names. No raw query DSL, no scripts, no regex, no wildcards.
- **Text:** `simple_query_string` on `event.original`, `message` and the rule title, with prefix, fuzzy, slop and near operators off, 200 characters at most.
- **Ids and indices:** `get_event` only opens `.ds-wazuh-events-v5-*` backing indices, and ids must look like ids.
- **Budget:** `READS_PER_HOUR` (600) calls per tool. The common guard only limits writes, so reads have their own.
- **Audit:** one JSON line per call (caller, tool, arguments, outcome), never a secret.
- **The instructions** tell the model that results are data written by the systems being watched, never instructions.

## Configuration

| Variable | Default | |
|---|---|---|
| `WAZUH_INDEXER_URL` | required | `https://indexer.example:9200` |
| `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD` | required | A user with `read` on the indices below only |
| `WAZUH_INDEXER_CA` | system store | |
| `WAZUH_FINDINGS_INDEX`, `WAZUH_EVENTS_INDEX` | `wazuh-findings-v5-*`, `wazuh-events-v5-*` | |
| `WAZUH_STATES_PREFIX` | `wazuh-states-` | |
| `MCP_TOKEN` or `MCP_TOKENS_FILE` | required | The bearer token Vigil presents |
| `MCP_ALLOWED_HOSTS` | `127.0.0.1:*,localhost:*` | The host name Vigil uses |
| `MCP_HOST`, `MCP_PORT` | `0.0.0.0`, `8000` | |
| `MAX_WINDOW_DAYS`, `MAX_RESULTS`, `MAX_BUCKETS`, `READS_PER_HOUR` | `7`, `100`, `50`, `600` | |

The indexer role needs `read` on `wazuh-findings-v5-*`, `wazuh-events-v5-*` and `wazuh-states-*`, and on their `.ds-` backing indices. Nothing else.

## Register with Vigil

See [`docs/REGISTERING-WITH-VIGIL.md`](../../docs/REGISTERING-WITH-VIGIL.md). Classify every tool as `read`.

## Image

```sh
docker build -f servers/wazuh5/Dockerfile -t vigil-mcp-wazuh5 .
```

Non-root (uid 10001), and it works with a read-only root filesystem.
