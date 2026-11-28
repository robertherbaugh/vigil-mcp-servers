"""The enrolled hosts, in one JSON file on a volume.

A host gets an entry when it enrolls, and its kit fields when it reports. Each host's
timer reports again every day and at boot, so an entry that stops reporting goes stale
and leaves the responder's list by itself (a deleted or stopped VM). The file is only
a cache of that: when it is lost, the reports fill it again within a day.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Host:
    address: str
    vmid: int
    node: str
    name: str
    principals: list[str]
    enrolled_at: float = 0.0
    reported_at: float = 0.0
    kit: str = ""  # the responder kit version that the host reported, "" before a report
    extra: dict[str, Any] = field(default_factory=dict)


class Inventory:
    def __init__(self, path: str | None, *, stale_seconds: float = 3 * 86400):
        self.path = Path(path) if path else None
        self.stale_seconds = stale_seconds
        self._lock = threading.Lock()
        self._hosts: dict[str, Host] = {}
        if self.path and self.path.exists():
            raw = json.loads(self.path.read_text() or "{}")
            for h in raw.get("hosts", []):
                host = Host(**{k: v for k, v in h.items() if k in Host.__dataclass_fields__})
                self._hosts[host.address] = host

    def _save(self) -> None:
        if not self.path:
            return
        data = json.dumps({"hosts": [asdict(h) for h in self._hosts.values()]}, indent=1)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".inventory.")
        with os.fdopen(fd, "w") as fh:
            fh.write(data)
        os.replace(tmp, self.path)

    def _upsert(self, address: str, vmid: int, node: str, name: str, principals: list[str]) -> Host:
        # One entry per VM: a VM with a new address replaces its old entry.
        for addr in [a for a, h in self._hosts.items() if h.vmid == vmid and a != address]:
            del self._hosts[addr]
        host = self._hosts.get(address)
        if host is None or host.vmid != vmid:
            host = Host(address=address, vmid=vmid, node=node, name=name, principals=principals)
            self._hosts[address] = host
        host.node, host.name = node, name
        if principals:
            host.principals = principals
        return host

    def enrolled(
        self, address: str, *, vmid: int, node: str, name: str, principals: list[str]
    ) -> Host:
        with self._lock:
            host = self._upsert(address, vmid, node, name, principals)
            host.enrolled_at = time.time()
            self._save()
            return host

    def reported(self, address: str, *, vmid: int, node: str, name: str, kit: str) -> Host:
        with self._lock:
            host = self._upsert(address, vmid, node, name, [])
            host.reported_at = time.time()
            host.kit = kit
            self._save()
            return host

    def responder_hosts(self, now: float | None = None) -> list[Host]:
        """Hosts with the kit that reported within stale_seconds."""
        now = time.time() if now is None else now
        with self._lock:
            return sorted(
                (
                    h
                    for h in self._hosts.values()
                    if h.kit and now - h.reported_at <= self.stale_seconds
                ),
                key=lambda h: h.address,
            )

    def all(self) -> list[Host]:
        with self._lock:
            return sorted(self._hosts.values(), key=lambda h: h.address)
