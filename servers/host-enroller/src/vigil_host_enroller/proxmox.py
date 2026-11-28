"""Find the Proxmox VM behind a source address, with a read-only API token.

A VM proves itself with three facts that it cannot set from inside:

1. Proxmox has the VM, it runs, and it carries the opt-in tag (an admin sets tags; a clone
   gets the tags of its template).
2. The QEMU guest agent of exactly that one VM reports the TCP source address.
3. The SMBIOS UUID in the VM's Proxmox configuration equals the UUID that the request
   sends. Only root can read it in the guest (/sys/class/dmi/id/product_uuid is 0400).

The token needs VM.Audit (resources, config) and VM.GuestAgent.Audit (the agent's
addresses) on the VMs. Nothing here changes Proxmox.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx

UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class NotVerified(Exception):
    """The request does not match exactly one tagged VM. The message is safe to return."""


class ProxmoxError(Exception):
    """Proxmox could not answer. Not the caller's fault."""


@dataclass(frozen=True)
class VM:
    vmid: int
    node: str
    name: str
    uuid: str
    addresses: frozenset[str]


def _tags(text: str | None) -> set[str]:
    return {t.strip().lower() for t in re.split(r"[;,\s]+", text or "") if t.strip()}


def _agent_addresses(result: Any) -> set[str]:
    out: set[str] = set()
    for iface in result if isinstance(result, list) else []:
        if not isinstance(iface, dict) or iface.get("name") == "lo":
            continue
        for a in iface.get("ip-addresses") or []:
            try:
                ip = ipaddress.ip_address(str(a.get("ip-address", "")).split("%")[0])
            except ValueError:
                continue
            if not (ip.is_loopback or ip.is_link_local):
                out.add(str(ip))
    return out


def _smbios_uuid(smbios1: str | None) -> str:
    for part in (smbios1 or "").split(","):
        key, _, value = part.partition("=")
        if key.strip() == "uuid":
            return value.strip().lower()
    return ""


class Proxmox:
    def __init__(
        self,
        *,
        urls: list[str],
        token_id: str,
        token_secret: str,
        tag: str = "step-enroll",
        verify: str | bool = True,
        timeout: float = 10.0,
        source_address: str | None = None,
        cache_seconds: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ):
        if not urls:
            raise ValueError("PVE_URL is required")
        self.urls = [u.rstrip("/") for u in urls]
        self.tag = tag.lower()
        self.cache_seconds = cache_seconds
        # source_address: connect from this local address, for example a second interface whose
        # routes apply only to its own source address (CNI sbr). None: the kernel picks.
        self._client = client or httpx.AsyncClient(
            timeout=timeout,
            transport=httpx.AsyncHTTPTransport(verify=verify, local_address=source_address),
        )
        self._headers = {"Authorization": f"PVEAPIToken={token_id}={token_secret}"}
        self._cache: tuple[float, list[VM]] | None = None
        self._lock = asyncio.Lock()

    async def _get(self, path: str, params: dict[str, str] | None = None) -> Any:
        last: Exception | None = None
        for base in self.urls:  # the API of any cluster node answers for the whole cluster
            try:
                r = await self._client.get(
                    f"{base}/api2/json{path}", params=params, headers=self._headers
                )
            except httpx.HTTPError as exc:
                last = exc
                continue
            if r.status_code in (401, 403):
                raise ProxmoxError(f"Proxmox refused the token ({r.status_code}) on {path}")
            if r.status_code >= 500 and "agent" in path:
                return None  # no agent, or it does not answer: this VM cannot match
            if r.status_code != 200:
                last = ProxmoxError(f"Proxmox {r.status_code} on {path}")
                continue
            return r.json().get("data")
        raise ProxmoxError(f"no Proxmox node answered: {type(last).__name__}: {last}")

    async def tagged_vms(self) -> list[VM]:
        """Running QEMU VMs with the tag, with their agent addresses. Cached briefly."""
        async with self._lock:
            now = time.monotonic()
            if self._cache and now - self._cache[0] < self.cache_seconds:
                return self._cache[1]
            resources = await self._get("/cluster/resources", {"type": "vm"}) or []
            picked = [
                r
                for r in resources
                if r.get("type") == "qemu"
                and r.get("status") == "running"
                and not r.get("template")
                and self.tag in _tags(r.get("tags"))
            ]

            async def one(r: dict[str, Any]) -> VM:
                node, vmid = str(r["node"]), int(r["vmid"])
                base = f"/nodes/{node}/qemu/{vmid}"
                agent, config = await asyncio.gather(
                    self._get(f"{base}/agent/network-get-interfaces"), self._get(f"{base}/config")
                )
                return VM(
                    vmid=vmid,
                    node=node,
                    name=str(r.get("name") or (config or {}).get("name") or vmid),
                    uuid=_smbios_uuid((config or {}).get("smbios1")),
                    addresses=frozenset(_agent_addresses((agent or {}).get("result"))),
                )

            vms = list(await asyncio.gather(*(one(r) for r in picked)))
            self._cache = (now, vms)
            return vms

    async def verify(self, address: str, uuid: str) -> VM:
        """The one tagged VM that has this address and this SMBIOS UUID, or NotVerified."""
        if not UUID.match(uuid or ""):
            raise NotVerified("send the SMBIOS UUID (/sys/class/dmi/id/product_uuid)")
        ip = str(ipaddress.ip_address(address))
        vms = await self.tagged_vms()
        matches = [vm for vm in vms if ip in vm.addresses]
        if not matches:
            self._cache = None  # a VM that just booted: look again next time
            raise NotVerified(
                f"no running VM with the tag {self.tag!r} reports {ip} through the QEMU guest "
                "agent. Check the tag, the agent option, and qemu-guest-agent in the VM"
            )
        if len(matches) > 1:
            ids = ", ".join(str(vm.vmid) for vm in matches)
            raise NotVerified(f"more than one tagged VM reports {ip} (VMs {ids}): refused")
        vm = matches[0]
        if not vm.uuid or vm.uuid != uuid.lower():
            raise NotVerified(f"the SMBIOS UUID does not match VM {vm.vmid}")
        return vm
