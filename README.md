# vigil-mcp-servers

MCP servers that let [Vigil SOC](https://github.com/Vigil-SOC/vigil) (or any MCP client) take
**narrow, auditable, mostly reversible response actions** on self-hosted infrastructure: SSH
remediation with short-lived [step-ca](https://smallstep.com/docs/step-ca/) certificates, UniFi
containment, Grafana alert intake, and Wazuh 5.

> **Status: scaffold.** The shared guard-rail library and a template server work and are tested.
> The servers in the [roadmap](docs/ROADMAP.md) are planned, not built yet.

## Why a separate repo

Vigil decides *whether* an action may run (approvals, autonomy ceiling, crown jewels). These
servers decide *what an action can possibly do*. They hold the credentials and enforce their own
limits, so a mistake, a prompt injection, or a caller that bypasses Vigil still can't exceed them.
See [docs/DESIGN.md](docs/DESIGN.md).

## What's here

| Path | What | Status |
|---|---|---|
| [`packages/vigil_mcp_common`](packages/vigil_mcp_common) | Bearer auth, target allow/deny lists, per-tool rate limits, JSON audit log, expiring (TTL) actions, effect-class annotations, the streamable HTTP app | Working, tested |
| [`servers/_template`](servers/_template) | A minimal server to copy: read tools plus a harmless "rehearsal" action for drilling Vigil's approval and undo flow | Working, tested |
| [`servers/wazuh5-bridge`](servers/wazuh5-bridge) | Forwards Wazuh 5 findings (`wazuh-findings-v5-*`) to Vigil, with reviewed, narrow suppressions for normal-operation noise. Nothing is deleted in Wazuh. A worker, not an MCP server | Working, tested |
| [`servers/wazuh5`](servers/wazuh5) | Read-only MCP tools on Wazuh 5 for investigations: search findings and events, follow a finding to its triggering event, top values, host inventory. Bounded, term-only queries | Working, tested |
| [`servers/stepca-ssh-responder`](servers/stepca-ssh-responder) | Reversible response: block an IP on one host for a fixed time, over SSH with a short-lived step-ca certificate per call. Host kit included: forced command, one sudo rule, nftables sets that expire blocks by themselves | Working, tested end to end |
| [`servers/host-enroller`](servers/host-enroller) | Enrolls Proxmox VMs with step-ca without a person: a VM proves itself through the Proxmox API (tag, guest-agent address, SMBIOS UUID) and gets a one-time host token, the host kit and a daily report. Keeps the responder's host list. A one-line bootstrap and a template first-boot unit | Working, tested end to end |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | `stepca-ssh-responder`, `unifi-containment`, `grafana-alerts-bridge`, `wazuh5`, `security-onion` | Planned |

## Quick start

```sh
uv sync
uv run pytest
MCP_TOKEN="$(openssl rand -base64 32)" TARGET_ALLOW=192.0.2.0/24 uv run vigil-mcp-template
# streamable HTTP on http://127.0.0.1:8000/mcp, health on /healthz
```

Container:

```sh
docker build -f servers/_template/Dockerfile -t vigil-mcp-template .
```

To connect a server to Vigil, see [docs/REGISTERING-WITH-VIGIL.md](docs/REGISTERING-WITH-VIGIL.md).

## Built on

- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) v2 (`mcp.server.MCPServer`)
- Vigil v1.2.0's [remote MCP sources](https://github.com/Vigil-SOC/vigil/blob/v1.2.0/INTENT.md)
  and per-tool effect classes

Not affiliated with the Vigil project or DeepTempo.

## License

[Apache-2.0](LICENSE). Contributions need a DCO sign-off, see [CONTRIBUTING.md](CONTRIBUTING.md).
