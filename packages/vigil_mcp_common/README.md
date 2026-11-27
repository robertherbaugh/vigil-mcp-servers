# vigil-mcp-common

The guard rails every server in this repo shares. Small on purpose; read it in one sitting.

| Module | What |
|---|---|
| `auth` | `TokenSet` (named callers, SHA-256 digests, constant-time compare) and `BearerAuthMiddleware` (401 without a known token; `/healthz` stays open) |
| `allowlist` | `TargetPolicy`: allow and deny lists of IPs, CIDRs, host names and `*.domain`; empty allow list allows nothing; deny wins |
| `ratelimit` | `RateLimiter`: sliding window per key, thread-safe |
| `audit` | `AuditLog`: one JSON line per call; credential-like field names are redacted at any depth |
| `expiring` | `ExpiringActions` (undo after a TTL, optional state file, failed undos retried) and `TtlBounds` (refuse, never clamp) |
| `effects` | `EffectClass` and the MCP annotations and `_meta` entry that declare it |
| `guard` | `Guard.call()`: caller, target, rate limit and audit around a tool body; refusals become `ToolError` |
| `app` | `build_app()`: stateless JSON streamable HTTP at `/mcp`, DNS-rebinding protection, bearer auth, `/healthz` |

Usage: see `servers/_template/src/vigil_mcp_template/server.py`.
