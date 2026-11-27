"""A Wazuh 5 finding (wazuh-findings-v5-*) as a Vigil finding.

Wazuh 5 findings are ECS documents with the matched Sigma rule under
``wazuh.rule``. Vigil's OpenSearch integration reads Security Analytics findings
(``queries[]``, ``related_doc_ids``), a different shape, so this maps the fields
itself. The finding id is stable (``wazuh5-<document _id>``), and Vigil skips an
id it already has, so sending a finding twice is harmless.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .suppressions import field_values

DATA_SOURCE = "wazuh"
ID_PREFIX = "wazuh5-"
FINDING_ID_MAX = 50  # Vigil: findings.finding_id String(50)
TITLE_MAX = 500
DESCRIPTION_MAX = 500

_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def finding_id(hit_id: str) -> str:
    fid = f"{ID_PREFIX}{hit_id}"
    if len(fid) > FINDING_ID_MAX:
        raise ValueError(f"finding id longer than {FINDING_ID_MAX} characters: {fid!r}")
    return fid


def _first(doc: Mapping[str, Any], *paths: str) -> str | None:
    for path in paths:
        for value in field_values(doc, path):
            if value not in (None, "", [], {}):
                return str(value)
    return None


def _all(doc: Mapping[str, Any], *paths: str) -> list[str]:
    out: list[str] = []
    for path in paths:
        for value in field_values(doc, path):
            text = str(value) if value not in (None, "") else ""
            if text and text not in out:
                out.append(text)
    return out


def severity(doc: Mapping[str, Any]) -> str:
    level = (_first(doc, "wazuh.rule.level") or "").lower()
    return _SEVERITY.get(level, "medium")


def to_vigil(hit: Mapping[str, Any]) -> dict[str, Any]:
    """One search hit (``_id``, ``_index``, ``_source``) as a Vigil finding."""
    src: Mapping[str, Any] = hit["_source"]
    rule_id = _first(src, "wazuh.rule.id") or ""
    title = _first(src, "wazuh.rule.title") or "Wazuh finding"
    agent = _first(src, "wazuh.agent.name")
    integration = _first(src, "wazuh.integration.name")
    action = _first(src, "event.action")
    outcome = _first(src, "event.outcome")

    parts = [title]
    if agent:
        parts.append(f"Agent: {agent}")
    if integration:
        parts.append(f"Integration: {integration}")
    if action:
        parts.append(f"Action: {action}" + (f" ({outcome})" if outcome else ""))
    if rule_id:
        parts.append(f"Rule: {rule_id}")

    techniques = _all(src, "wazuh.rule.mitre.technique.id")
    return {
        "finding_id": finding_id(str(hit["_id"])),
        "external_id": str(hit["_id"]),
        "data_source": DATA_SOURCE,
        "timestamp": _first(src, "@timestamp"),
        "severity": severity(src),
        "title": title[:TITLE_MAX],
        "description": ". ".join(parts)[:DESCRIPTION_MAX],
        "entity_context": {
            "src_ips": _all(src, "source.ip"),
            "dest_ips": _all(src, "destination.ip"),
            "hostnames": _all(
                src, "host.hostname", "host.name", "wazuh.agent.host.hostname", "wazuh.agent.name"
            ),
            "usernames": _all(src, "user.name"),
        },
        "raw_data": dict(src),
        "anomaly_score": None,
        # Sigma gives the technique, not a confidence.
        "mitre_predictions": {t: None for t in techniques},
        "metadata": {
            "wazuh_finding_id": str(hit["_id"]),
            "index": str(hit.get("_index", "")),
            "rule_id": rule_id,
            "rule_level": _first(src, "wazuh.rule.level"),
            "rule_tags": _all(src, "wazuh.rule.tags"),
            "integration": integration,
            "category": _first(src, "wazuh.integration.category"),
            "agent_id": _first(src, "wazuh.agent.id"),
            "agent_name": agent,
            "event_id": _first(src, "wazuh.event.id", "event.id"),
            "event_index": _first(src, "event.index"),
            "event_doc_id": _first(src, "event.doc_id"),
            "space": _first(src, "wazuh.space.name"),
        },
    }
