"""Wazuh 5 findings in the shapes the indexer returns (5.0.0-rc2), anonymized."""

from __future__ import annotations

import copy
from typing import Any

PROMISC_RULE = "698ba849-5c22-5503-907f-4c74d3a2bb34"
CONFIG_RULE = "1316fa20-b8b8-5362-8201-a65b6fc50c2c"
VM_TERMINATED_RULE = "d1a226e6-6056-53e5-af04-ef74f4997cf4"
VM_STARTED_RULE = "37258b8d-acd0-560e-a506-b71d5940e027"

_AGENT = {"name": "node-a", "id": "007", "host": {"hostname": "node-a.example.com"}}


def promisc(dev: str = "vethb8342594", auid: str = "4294967295", **over: Any) -> dict[str, Any]:
    src = {
        "@timestamp": "2026-11-27T22:35:26.656908856Z",
        "wazuh": {
            "agent": copy.deepcopy(_AGENT),
            "integration": {"name": "auditd", "category": "system-activity"},
            "rule": {
                "id": PROMISC_RULE,
                "level": "high",
                "title": "Network interface entered promiscuous mode",
                "tags": ["high", "auditd", "attack.discovery", "attack.t1040"],
                "mitre": {"technique": {"id": ["T1040"], "name": ["Network Sniffing"]}},
            },
            "event": {"id": "389a6bdc-0cb5-4cfe-840a-90c944b165e1"},
            "space": {"name": "standard"},
        },
        "event": {
            "original": (
                "type=ANOM_PROMISCUOUS msg=audit(1795818922.370:8610955): "
                f"dev={dev} prom=256 old_prom=0 auid={auid} uid=0 gid=0 ses=4294967295"
            ),
            "code": "ANOM_PROMISCUOUS",
            "action": "config-modified",
            "outcome": "unknown",
        },
        "user": {"id": "0"},
    }
    src.update(over)
    return src


def k8s_pod(user: str, rule: str = VM_TERMINATED_RULE, resource: str = "pods") -> dict[str, Any]:
    started = rule == VM_STARTED_RULE
    return {
        "@timestamp": "2026-11-27T19:10:24.665Z",
        "wazuh": {
            "agent": copy.deepcopy(_AGENT),
            "integration": {"name": "kubernetes", "category": "cloud-services"},
            "rule": {
                "id": rule,
                "level": "low" if started else "high",
                "title": "Cloud VM instance started" if started else "Cloud VM instance terminated",
                "tags": ["cloud-detection", "attack.t1578.002" if started else "attack.t1578.003"],
                "mitre": {"technique": {"id": ["T1578.002" if started else "T1578.003"]}},
            },
            "event": {"id": "9cc44263-d33c-48e0-ba51-2bdcd4a6c304"},
        },
        "orchestrator": {
            "resource": {"type": resource, "name": "job-1-abcde"},
            "namespace": "batch",
            "type": "kubernetes",
        },
        "user": {"name": user},
        "source": {"ip": "192.0.2.10"},
        "event": {
            "action": "instance-started" if started else "instance-terminated",
            "outcome": "success",
        },
    }


def hit(
    src: dict[str, Any],
    hid: str = "QbALwpc_9acw0000000001",
    index: str = ".ds-wazuh-findings-v5-system-activity-000001",
) -> dict[str, Any]:
    return {"_id": hid, "_index": index, "_source": src}
