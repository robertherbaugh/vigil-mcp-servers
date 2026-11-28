# host-enroller

This service enrolls Proxmox VMs with [step-ca](https://smallstep.com/docs/step-ca/) without a person. It also makes each VM a host for [`stepca-ssh-responder`](../stepca-ssh-responder). A new clone of a prepared template enrolls itself at first boot. An existing VM enrolls with one command:

```sh
curl -fsSL https://enroll.example.net/bootstrap.sh | sudo sh
```

The service does not take MCP calls. It mints step-ca one-time host tokens, and it keeps the list of hosts that the responder acts on.

## How a VM proves itself

The VM sends only its SMBIOS UUID. The enroller then reads Proxmox with a read-only API token and checks three facts:

1. **The tag.** Exactly one running QEMU VM has the opt-in tag (`ENROLL_TAG`, default `step-enroll`). Only a Proxmox admin sets tags. A clone gets the tags of its template.
2. **The address.** The QEMU guest agent of that VM reports the TCP source address of the request. The enroller serves on its own LoadBalancer address with `externalTrafficPolicy: Local`. It never reads `X-Forwarded-For`, so no proxy can speak for a host.
3. **The UUID.** The SMBIOS UUID in the VM's Proxmox configuration is the UUID that the request sends. Only root can read it in the guest.

The source address must also be in `ENROLL_ALLOW` and not in `ENROLL_DENY`. Each address gets 10 requests an hour, and the service gets 120 an hour in total.

These checks are not a cryptographic identity. A device on the same VLAN can take a tagged VM's address when it also knows the VM's UUID. The certificate policy limits what such a token can do (next section).

## What the token allows

The enroller signs a token for the step-ca JWK provisioner `hosts-enroll` (`PROVISIONER`). The private key comes from `ENROLL_KEY_SEED`, and it never leaves the process. Only the public key is in step-ca's `ca.json` (`GET /v1/jwk` on the internal port). The token:

- is for an SSH **host** certificate only, and lasts 5 minutes, for one use.
- has the source address as its subject and first principal.
- also has `<VM name>.<domain>` for each domain in `DNS_DOMAINS`, but only if DNS gives that same address.

In step-ca, put a policy on the provisioner. It must allow only the VM subnets and refuse the cluster's own addresses. Also give the provisioner a template that refuses user certificates. The step-ca configuration of the homelab is an example: `kubernetes/apps/step-ca` in homelab-docker-k8s.

## The hosts list

Each host reports each day, and at boot, that its kit is ready (`vigil-enroll-report.timer`). Each report goes through the same Proxmox check. `GET /v1/inventory` (internal port, bearer `INVENTORY_TOKEN`) lists the hosts that reported a ready kit in the last `STALE_DAYS` days (default 3). The responder reads that list (`INVENTORY_URL`). A deleted or stopped VM thus leaves the list by itself. The list is in `STATE_FILE`. When that file is lost, the reports fill it again within a day.

## Endpoints

| Port | Path | Does |
|---|---|---|
| public (TLS, `PUBLIC_PORT` 8443) | `GET /bootstrap.sh` | The host script, with this service's values in it |
| public | `GET /template.sh` | Prepares a VM template: installs qemu-guest-agent and the first-boot unit |
| public | `GET /files/<name>` | `step` (x86_64), `kit.tar.gz`, `enroll-host.sh` and the report units. `bootstrap.sh` checks the SHA-256 of each one |
| public | `POST /v1/enroll` | `{"uuid": ...}` → line 1 the token, line 2 the principals |
| public | `POST /v1/report` | `{"uuid": ..., "kit": <version or "">}` → `ok` |
| both | `GET /healthz` | Version, and whether step-ca has this key as the provisioner (`registered`) |
| internal (HTTP, `INTERNAL_PORT` 8080) | `GET /v1/jwk` | The provisioner's public key, for `ca.json` |
| internal | `GET /v1/inventory` | The hosts for the responder (bearer token) |

## What bootstrap.sh does

1. It installs what is missing: bash, sudo, nftables, openssh-server, qemu-guest-agent (apt or dnf), and the step CLI.
2. It gets a token. It tries 6 times in one minute, because Proxmox can be slow to see a new VM's address.
3. It runs `enroll-host.sh`. That script trusts the SSH user CA, gets the host certificate, and adds a weekly renewal. `ENROLL_HOST_ARGS` adds the operator's options, for example `--admin-user root`.
4. It installs the responder kit of the same release, with the default gateway and `KIT_NEVER_BLOCK` on the never-block list.
5. It installs the report timer and reports once. Then it writes `/etc/vigil-enroll/enrolled`.

You can run it again. Each step is idempotent.

## A template

In the template VM, run `curl -fsSL https://enroll.example.net/template.sh | sudo sh`. Then run `cloud-init clean --machine-id --seed --logs`, shut it down, and convert it. In Proxmox, give the template the tag and turn on "QEMU Guest Agent". Each clone then runs `bootstrap.sh` one time, after cloud-init makes its own SSH host keys (`vigil-enroll-firstboot.service`). If the enroller refuses, the unit tries again every 2 minutes.

Every clone of a tagged template can enroll itself. Tag only templates that you trust.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PUBLIC_URL` | (required) | The URL that hosts use, for example `https://enroll.example.net` |
| `STEPCA_URL` | (required) | step-ca as hosts reach it. It is also the token's audience |
| `STEPCA_INTERNAL_URL` | `STEPCA_URL` | step-ca as this service reaches it, for the `registered` check |
| `STEPCA_FINGERPRINT` | (required) | The root's SHA-256 |
| `PROVISIONER` | `hosts-enroll` | The JWK provisioner's name |
| `ENROLL_KEY_SEED` | (required) | At least 32 characters. A new seed is a new key: register it again |
| `ENROLL_ALLOW`, `ENROLL_DENY` | (required), empty | CIDRs, comma-separated |
| `ENROLL_TAG` | `step-enroll` | The Proxmox tag |
| `DNS_DOMAINS` | empty | Domains for the name principal |
| `ENROLL_HOST_ARGS` | `--admin-user root` | Options for `enroll-host.sh` |
| `KIT_PRINCIPAL`, `KIT_NEVER_BLOCK` | `sa-vigil-responder`, empty | The kit's `install.sh` options |
| `PVE_URL` | (required) | One or more Proxmox API URLs, comma-separated |
| `PVE_TOKEN_ID`, `PVE_TOKEN_SECRET`, `PVE_CA_FILE` | (required), (required), system CAs | The API token, and the CA file for Proxmox's TLS certificate |
| `PVE_SOURCE_ADDRESS` | empty | Connect to Proxmox from this local address. Use it with a second interface whose routes apply only to its own source address (CNI `sbr`), so that replies to hosts on that network still leave through the pod's main interface |
| `INVENTORY_TOKEN` | (required) | At least 32 characters |
| `STATE_FILE`, `STALE_DAYS` | `/var/lib/host-enroller/inventory.json`, `3` | The hosts list |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | (required in production) | The public listener's certificate. The service loads a renewed file within 5 minutes |

### The Proxmox token

```sh
pveum role add StepEnroll --privs "VM.Audit,VM.GuestAgent.Audit"
pveum user add step-enroll@pve --comment "vigil host-enroller (read-only)"
pveum acl modify /vms --users step-enroll@pve --roles StepEnroll
pveum user token add step-enroll@pve enroller --privsep 1
pveum acl modify /vms --tokens 'step-enroll@pve!enroller' --roles StepEnroll
```

On Proxmox VE 8, use `VM.Monitor` in place of `VM.GuestAgent.Audit`.
