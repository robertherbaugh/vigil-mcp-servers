"""Which targets a server may act on.

A target is an IP address or a host name. The deny list wins over the allow list,
so "everything in 192.0.2.0/24 except the hypervisor" is one allow and one deny.
An empty allow list allows nothing: a server must be told what it may touch.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class TargetNotAllowed(PermissionError):
    """The target is outside the allow list, or on the deny list."""


def _normalize_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host or any(c.isspace() for c in host) or "/" in host:
        raise ValueError(f"invalid host name {value!r}")
    return host


def _as_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


@dataclass(frozen=True)
class _Patterns:
    networks: tuple[IPNetwork, ...] = ()
    hosts: frozenset[str] = frozenset()
    suffixes: tuple[str, ...] = ()  # ".example.com" for "*.example.com"

    @classmethod
    def parse(cls, patterns: Iterable[str]) -> _Patterns:
        networks: list[IPNetwork] = []
        hosts: set[str] = set()
        suffixes: list[str] = []
        for raw in patterns:
            item = raw.strip()
            if not item:
                continue
            if _as_ip(item.split("/")[0]) is not None:
                networks.append(ipaddress.ip_network(item, strict=False))
            elif item.startswith("*."):
                suffixes.append("." + _normalize_host(item[2:]))
            elif "*" in item:
                raise ValueError(f"only a leading '*.' wildcard is supported: {raw!r}")
            else:
                hosts.add(_normalize_host(item))
        return cls(tuple(networks), frozenset(hosts), tuple(suffixes))

    def matches(self, target: str) -> bool:
        ip = _as_ip(target)
        if ip is not None:
            return any(ip in net for net in self.networks)
        host = _normalize_host(target)
        return host in self.hosts or any(host.endswith(s) for s in self.suffixes)

    def describe(self) -> list[str]:
        return [
            *(str(n) for n in self.networks),
            *sorted(self.hosts),
            *("*" + s for s in self.suffixes),
        ]


@dataclass(frozen=True)
class TargetPolicy:
    """Allow and deny patterns: IPs, CIDRs, exact host names, ``*.domain`` suffixes."""

    allow: _Patterns = field(default_factory=_Patterns)
    deny: _Patterns = field(default_factory=_Patterns)

    @classmethod
    def from_patterns(cls, allow: Iterable[str], deny: Iterable[str] = ()) -> TargetPolicy:
        return cls(_Patterns.parse(allow), _Patterns.parse(deny))

    @classmethod
    def from_csv(cls, allow: str | None, deny: str | None = None) -> TargetPolicy:
        return cls.from_patterns((allow or "").split(","), (deny or "").split(","))

    def check(self, target: str) -> str:
        """Return the normalized target, or raise ``TargetNotAllowed``."""
        normalized = str(_as_ip(target) or _normalize_host(target))
        if self.deny.matches(normalized):
            raise TargetNotAllowed(f"{normalized} is on the deny list")
        if not self.allow.matches(normalized):
            raise TargetNotAllowed(f"{normalized} is not on the allow list")
        return normalized

    def describe(self) -> dict[str, list[str]]:
        return {"allow": self.allow.describe(), "deny": self.deny.describe()}
