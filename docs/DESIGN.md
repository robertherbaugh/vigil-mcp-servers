# Design

These servers sit between an AI SOC (Vigil) and real infrastructure. The AI decides what it
*wants*; the server decides what is *possible*. Every rule below follows from that split.

## 1. The server holds the credentials, not the AI

- The model never sees a credential, a private key, or a certificate. Vigil never stores one for
  these servers either: it holds only the bearer token it presents to the server.
- A server gets its upstream credentials from its own environment or mounted files, scoped to
  what its tools need (a UniFi user that can block clients but not change the network; a step-ca
  provisioner that can only issue SSH user certificates for the responder's principals).
- Where the upstream supports it, credentials are **short-lived and per action**. The
  `stepca-ssh-responder` gets a fresh SSH user certificate for each action, valid for minutes,
  for one principal.

## 2. The server enforces its own limits

Vigil's approvals and autonomy ceiling only gate calls that go **through Vigil**. Anything else
that can reach the MCP endpoint (another client, a stolen token, a bug) meets only the server's
own checks. So every server enforces, independently of Vigil:

| Limit | Where | Notes |
|---|---|---|
| Who may call | `BearerAuthMiddleware`, `TokenSet` | One named token per caller, so the audit log says who |
| Which targets | `TargetPolicy` | Empty allow list allows nothing; the deny list wins (put crown jewels there too) |
| How often | `RateLimiter` | Per tool, for every non-read tool |
| How long | `TtlBounds` | A TTL outside the bounds is refused, never silently clamped |
| What happened | `AuditLog` | One JSON line per call, every outcome, secrets redacted |

`Guard.call()` applies them all, in that order, around every tool body.

## 3. Every tool declares its Vigil effect class

Vigil stores one effect class per outside tool and decides by it (v1.2.0,
`core/response/ceiling.py`):

| Class | Meaning | Vigil without an approval |
|---|---|---|
| `read` | Changes nothing | Runs |
| `reversible` | Changes something that can be put back, ideally by itself | Only if a person raised reversible autonomy |
| `irreversible` | Can't be put back | Only if a person raised irreversible autonomy |
| unclassified | Not classified yet | Never: it asks first |

A **person** classifies each tool in Vigil; a server's own claim is never trusted. To make that
person's job easy and honest, each tool here:

- sets MCP `annotations` that agree with its class (`readOnlyHint`, `destructiveHint`), and
- puts the class in `_meta` under `io.github.robertherbaugh.vigil-mcp-servers/effect-class`, and
- lists it in the server's `describe_policy` tool and its README.

If a tool's definition changes, Vigil drops its classification and asks again. Don't fight that:
it is how a server update is kept from quietly widening what runs unattended.

## 4. Prefer reversible actions that end by themselves

- Shape actions so the reversible class is honest: *block this IP for 1 hour*, *silence this alert
  for 30 minutes*, *end this session*. Then reversible autonomy is the only switch anyone needs,
  and irreversible autonomy can stay off.
- Every reversible action has a named undo tool (`rehearsal_hold` → `rehearsal_release`), which
  Vigil can bind as the act's way back.
- Use the vendor's own expiry where it exists (it survives this server going away). Otherwise use
  `ExpiringActions`, with a state file, so a restart still undoes what was applied.
- Make actions idempotent per target: a second hold on a held target is refused, not stacked.

## 5. Threat model: alert content is attacker-controlled

Log lines, host names, user agents, file names, email subjects: an attacker writes all of them,
and they reach the model's context. Assume a prompt injection will eventually ask for something
harmful. So:

- **No free-form execution.** No tool takes a shell command, a URL to fetch, or a file path to
  read. The SSH responder runs only named, pre-defined remediation commands with typed,
  validated arguments.
- **Typed, validated arguments.** IPs parse as IPs; host names normalize; enums are enums. A
  value that doesn't validate is refused, not "best-effort" used.
- **Targets come from the allow list, not the alert.** An alert can name any host; the server acts
  only on hosts the operator listed.
- **Output is data.** Tool output that echoes upstream content is returned as data. Vigil treats a
  source's output as input, never instruction; servers should not phrase output as instructions.
- **Rate limits bound the blast radius** of a model that has been talked into a loop.

## 6. Transport

- Streamable HTTP at `/mcp`, stateless, JSON responses: any replica answers any request.
- Vigil's remote sources require an `https` URL. Serve plain HTTP inside the pod and terminate TLS
  at the ingress (or a sidecar).
- DNS-rebinding protection is on; set `MCP_ALLOWED_HOSTS` to the host names clients use.
- `/healthz` is the only unauthenticated path.
- Restrict ingress to the MCP port to Vigil's backend and daemon with a NetworkPolicy, and
  restrict the server's egress to its one upstream. Vigil itself enforces no egress for a source.

## 7. Containers

Non-root fixed uid (10001), read-only root filesystem friendly (write only to a mounted state
directory), no added capabilities, pinned base image tags, `uv sync --frozen` from `uv.lock`.
