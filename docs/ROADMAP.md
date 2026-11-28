# Roadmap

Every server below is **planned**: none is implemented yet. Tool names, arguments and classes are
proposals; they settle when each server is built. Each server will copy `servers/_template` and
use `vigil_mcp_common` for auth, allowlists, rate limits, audit and TTLs.

## stepca-ssh-responder: planned

Runs pre-defined remediation commands over SSH. For each action, the server gets a fresh
**short-lived SSH user certificate** from step-ca for one scoped principal, uses it once, and
forgets it. The model never sees the certificate, the key, or a shell.

- **Credentials:** a step-ca provisioner that can only issue SSH user certificates for the
  responder's principals; certificate lifetime in minutes.
- **Commands:** named in server config, each with typed arguments, e.g.
  `kill_session(host, user)`, `restart_service(host, unit)`, `quarantine_file(host, path)` where
  `path` must match a configured prefix. No free-form command.
- **Hosts:** allow list plus deny list. Known host keys pinned; no trust on first use.
- **Force-command friendly:** each command maps to one principal, so the target host can pin
  `force-command` (or an `AuthorizedPrincipalsCommand`) per principal. A stolen certificate can
  then run only its one script.

| Tool | Class | Undo |
|---|---|---|
| `list_commands` | read | n/a |
| `describe_policy` | read | n/a |
| `run_remediation(host, command, args)` | per command: reversible (`kill_session`) or irreversible (`quarantine_file` without a restore) | per command |

## unifi-containment: planned

Contains a client on a UniFi Network controller for a bounded time.

| Tool | Class | Undo |
|---|---|---|
| `find_client(ip_or_mac)` | read | n/a |
| `list_blocks` | read | n/a |
| `block_client(mac, ttl_seconds, reason)` | reversible | `unblock_client` (also on TTL) |
| `block_ip(ip, ttl_seconds, reason)` (firewall group) | reversible | `unblock_ip` (also on TTL) |
| `unblock_client(mac)`, `unblock_ip(ip)` | reversible | re-block |

A dedicated controller user with only the rights these calls need. Infrastructure devices
(gateways, switches, APs) are on the deny list by default.

## grafana-alerts-bridge: planned

Two parts in one service:

1. **Webhook intake:** a Grafana Alertmanager webhook contact point posts here; the bridge
   checks a shared secret, maps each alert to a Vigil finding, and submits it to Vigil's ingest
   API. (Vigil v1.2.0 has no push receiver for Grafana.)
2. **MCP tools** for alert context and silences:

| Tool | Class | Undo |
|---|---|---|
| `get_alert(fingerprint)`, `list_firing_alerts` | read | n/a |
| `create_silence(matchers, ttl_seconds, reason)` | reversible (Grafana's own `endsAt`) | `expire_silence` |
| `expire_silence(silence_id)` | reversible | re-create |

## wazuh5-bridge: implemented

[`servers/wazuh5-bridge`](../servers/wazuh5-bridge): Wazuh 5 findings into Vigil, with
suppressions. Wazuh 5.0 writes Sigma findings to `wazuh-findings-v5-*` in an ECS shape that
Vigil's OpenSearch integration does not read, and 5.0 cannot tune a single standard rule
([wazuh-indexer-plugins#1772](https://github.com/wazuh/wazuh-indexer-plugins/issues/1772)).
When Wazuh ships per-rule exceptions, move each suppression into Wazuh as an exception.

## wazuh5: read tools implemented

[`servers/wazuh5`](../servers/wazuh5): `search_findings`, `search_events`, `get_finding` (with its
triggering event), `get_event`, `top_values` and `host_inventory`, all `read`, on a read-only
indexer login. (Upstream Vigil's Wazuh integration reads only the manager API, and its alerts
path targets the 4.x `wazuh-alerts-4.x-*` index pattern.)

Planned next, through the manager API, as a separate opt-in:

| Tool | Class | Undo |
|---|---|---|
| `list_agents`, `get_agent(id)` | read | n/a |
| `active_response_firewall_drop(agent_id, srcip, ttl_seconds)` | reversible (Wazuh's own timeout) | Wazuh's timeout |
| `active_response_disable_account(agent_id, user)` | irreversible until re-enabled by hand | n/a |

Candidate for upstreaming into Vigil as Wazuh 5 support for its existing integration.

## security-onion: later

Read tools over the Security Onion Connect API (alerts, cases, PCAP metadata), and possibly
acknowledge/escalate. The official
[securityonion-mcp](https://github.com/Security-Onion-Solutions/securityonion-mcp) server may be
the better fit; this entry exists to decide that.
