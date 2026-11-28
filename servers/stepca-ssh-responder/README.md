# stepca-ssh-responder

Reversible response actions for [Vigil](https://github.com/Vigil-SOC/vigil): **block an IP address on one host, for a fixed time**, over SSH with a short-lived [step-ca](https://smallstep.com/docs/step-ca/) certificate per call.

**Status:** implemented and tested, including end to end against a real `sshd` with the host kit, real `nft`, and certificates with `force-command` (see "Tests"). Every action needs Vigil's approval unless a person raises Vigil's autonomy.

## Tools

| Tool | Class | Undo |
|---|---|---|
| `describe_policy` | read | n/a |
| `check_host(host)` | read | n/a |
| `list_blocks(host)` | read | n/a |
| `block_ip(host, address, ttl_seconds, reason)` | reversible | `unblock_ip`, and the host lifts it by itself after `ttl_seconds` |
| `unblock_ip(host, address)` | reversible | `block_ip` |

## Layers

The server is the first layer, not the only one. A bug in it, a stolen bearer token, or a model that a log line steered can't do more than the next layers allow:

1. **This server:** a host allowlist (`RESPONDER_HOSTS`), a never-block list (`NEVER_BLOCK`, plus loopback), TTL bounds, rate limits (20 blocks an hour), and an audit line for each call.
2. **The certificate** (step-ca template, see below): only the account's own principal, `force-command /usr/local/sbin/vigil-respond`, no PTY, no forwarding, a `source-address` and a lifetime of minutes. The server asks for a certificate; it can't widen what the template gives.
3. **The host:** the principals file adds `restrict,command=` (so a certificate without force-command still gets only `vigil-respond`). `vigil-respond` accepts only its verbs with checked arguments, and one sudo rule allows only its root helper, which checks every argument again and keeps its own never-block list (the host's own addresses are on it).
4. **nftables** expires each block (`set ... flags timeout`), even if the responder never comes back. Blocks don't survive a reboot.

Every request is logged on the host with `logger -t vigil-respond`, so your log collector sends it to the SIEM.

## step-ca setup

A dedicated OIDC provisioner for the responder's service account, with a template like this (Go template; the provisioner's `claims` should cap user certificates at minutes, e.g. default `5m`, max `10m`):

```
{{- $user := .Token.preferred_username | default "" -}}
{{- if ne $user "sa-vigil-responder" }}{{ fail "not the responder account" }}{{ end -}}
{
  "type": {{ toJson .Type }},
  "keyId": {{ toJson $user }},
  "principals": [{{ toJson $user }}],
  "extensions": {},
  "criticalOptions": {
    "force-command": "/usr/local/sbin/vigil-respond",
    "source-address": "192.0.2.10/32,192.0.2.11/32"
  }
}
```

`extensions: {}` grants no PTY and no forwarding. `source-address` is the addresses the responder connects from.

## Host setup

On a host that already trusts the step-ca user CA (`TrustedUserCAKeys`) and reads `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u`:

```sh
sudo sh host/install.sh --principal sa-vigil-responder --never-block 192.0.2.1,198.51.100.0/24
```

The installer refuses a host without that enrollment, and it never opens SSH by itself. `--uninstall` removes everything, including the nftables table. Then add the host's name (as in its host certificate) to `RESPONDER_HOSTS`.

## Configuration

| Variable | Default | |
|---|---|---|
| `STEPCA_URL`, `STEPCA_FINGERPRINT` | required | The CA, and its root's SHA-256 (pinned, as `step ca bootstrap`) |
| `AUTHENTIK_TOKEN_URL`, `STEPCA_CLIENT_ID` | required | The OIDC provider the provisioner trusts (`client_credentials`) |
| `SA_USERNAME`, `SA_TOKEN` | required | The service account and its app password |
| `CERT_LIFETIME` | `5m` | Asked for; the provisioner caps it |
| `RESPONDER_HOSTS` | none | Comma-separated host names. Empty: every action is refused |
| `NEVER_BLOCK` | none | Comma-separated addresses or CIDRs, never blocked from here (loopback always) |
| `SSH_USER`, `SSH_PORT` | `vigil-responder`, `22` | |
| `MIN_TTL_SECONDS`, `MAX_TTL_SECONDS` | `60`, `86400` | The host helper enforces the same bounds |
| `MCP_TOKEN`, `MCP_ALLOWED_HOSTS`, `MCP_PORT` | | As in the other servers |

Host keys must carry a certificate from the step-ca host CA (`/ssh/roots`): no trust-on-first-use.

## Tests

- Unit tests: the server's guard rails over streamable HTTP, the step-ca client against a mock CA (a real asyncssh CA key), and the host scripts run with `sh` against a fake `nft` and `sudo`, including shell-injection attempts.
- End to end (by hand, `docker`): a Debian container with `sshd`, the host kit installed by `install.sh`, real `nft`, and this server's `SSHRunner`. Results: `check`, `block-ip`, `list-blocks` and `unblock-ip` work. Injection, a shell, a never-block address, and `id` with a certificate that has no force-command are all refused (exit 2). A wrong principal, a wrong source address and an untrusted host CA are refused by SSH.

## Image

```sh
docker build -f servers/stepca-ssh-responder/Dockerfile -t vigil-mcp-stepca-responder .
```
