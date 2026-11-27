# vigil-mcp-template

The server to copy when you start a new one ([CONTRIBUTING.md](../../CONTRIBUTING.md#add-a-server)).
It is also safe to deploy as-is: its only action, the **rehearsal hold**, changes nothing outside
this process. Use it to drill Vigil's approval, autonomy and undo flow before any server can touch
a real system.

## Tools

| Tool | Vigil effect class | What it does |
|---|---|---|
| `ping` | read | Server name, version, and which caller you are |
| `describe_policy` | read | Target allow/deny lists, rate limits, TTL bounds, every tool's class |
| `list_rehearsal_holds` | read | Active holds and when they end |
| `rehearsal_hold(target, ttl_seconds, reason)` | reversible | Records a pretend hold on an allowed target; ends by itself at the TTL |
| `rehearsal_release(target)` | reversible | The undo: ends a hold early |

Refusals (target not allowed, TTL out of bounds, rate limit used, hold already active) come back
as tool errors with the reason, and each one writes an audit line.

## Settings

| Variable | Default | |
|---|---|---|
| `MCP_TOKEN` | | Required unless `MCP_TOKENS_FILE` is set. At least 32 characters |
| `MCP_TOKEN_PRINCIPAL` | `vigil` | The caller name `MCP_TOKEN` is logged as |
| `MCP_TOKENS_FILE` | | JSON `{"<caller>": "<token>"}`, for several callers (a mounted Secret) |
| `MCP_HOST` / `MCP_PORT` | `127.0.0.1` / `8000` (image: `0.0.0.0` / `8000`) | Listen address |
| `MCP_ALLOWED_HOSTS` | `127.0.0.1:*,localhost:*` | `Host` header values to accept, comma-separated |
| `TARGET_ALLOW` | empty: nothing allowed | IPs, CIDRs, host names, `*.domain`, comma-separated |
| `TARGET_DENY` | empty | Same format; wins over the allow list |
| `STATE_FILE` | none (memory only) | JSON file that keeps holds across restarts |

Rate limit: 10 actions per hour across both action tools (`Limit(calls=10, per_seconds=3600)` in
`server.py`). TTL bounds: 60 seconds to 24 hours.

## Run

```sh
MCP_TOKEN="$(openssl rand -base64 32)" TARGET_ALLOW=192.0.2.0/24 uv run vigil-mcp-template

docker build -f servers/_template/Dockerfile -t vigil-mcp-template .   # from the repo root
docker run --rm -p 8000:8000 --read-only --cap-drop ALL \
  -e MCP_TOKEN -e TARGET_ALLOW=192.0.2.0/24 -e MCP_ALLOWED_HOSTS='127.0.0.1:*' \
  vigil-mcp-template
```

The image runs as uid 10001 and needs no writable path unless `STATE_FILE` points at a mounted
volume.

## Vigil source

`sources/template-mcp.md` in Vigil's declared intent directory, with the token in
`SOURCE_TEMPLATE_MCP_TOKEN`:

```markdown
---
url: https://template-mcp.example.com/mcp
headers:
  Authorization: "Bearer {{token}}"
credentials: [token]
---

# template-mcp

Rehearsal-only server from vigil-mcp-servers. Changes nothing outside itself.
```

Then accept the source and classify its tools as in the table above:
[docs/REGISTERING-WITH-VIGIL.md](../../docs/REGISTERING-WITH-VIGIL.md).
