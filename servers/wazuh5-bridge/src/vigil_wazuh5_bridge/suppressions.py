"""Suppressions: which Wazuh findings the bridge does not forward to Vigil.

A suppression is deliberately narrow, and every check fails toward forwarding:

- It names one or more Wazuh rule ids. A rule id alone is never enough: it also
  needs at least one field condition, so the same rule on an unexpected field
  value still reaches Vigil.
- Every condition must hold (AND). A missing field fails its condition.
- It has a reason and a review date at most a year ahead. After that date it
  stops suppressing (the findings reach Vigil again) until someone reviews it.

Nothing here touches Wazuh: suppressed findings stay in the indexer for its
normal retention, and the bridge counts them per suppression.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import yaml

MAX_REVIEW_HORIZON = dt.timedelta(days=366)
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_OPS = ("equals", "in", "prefix", "regex")


class SuppressionError(ValueError):
    """The suppression file is not valid. The message names the entry and the problem."""


def field_values(doc: Mapping[str, Any], path: str) -> list[Any]:
    """The values at a dotted path. A list anywhere on the path fans out.

    Wazuh documents nest ("user": {"name": ...}), but a flattened key
    ("user.name": ...) is accepted too.
    """
    if path in doc:
        value = doc[path]
        return list(value) if isinstance(value, list) else [value]
    head, _, rest = path.partition(".")
    if head not in doc:
        return []
    node = doc[head]
    if not rest:
        return list(node) if isinstance(node, list) else [node]
    items = node if isinstance(node, list) else [node]
    out: list[Any] = []
    for item in items:
        if isinstance(item, Mapping):
            out.extend(field_values(item, rest))
    return out


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    values: tuple[str, ...]
    pattern: re.Pattern[str] | None = None

    def holds(self, doc: Mapping[str, Any]) -> bool:
        for value in field_values(doc, self.field):
            if isinstance(value, (dict, list)) or value is None:
                continue
            text = str(value)
            if self.op == "equals" and text == self.values[0]:
                return True
            if self.op == "in" and text in self.values:
                return True
            if self.op == "prefix" and text.startswith(self.values[0]):
                return True
            if self.op == "regex" and self.pattern is not None and self.pattern.search(text):
                return True
        return False


@dataclass(frozen=True)
class Suppression:
    id: str
    reason: str
    review_by: dt.date
    rule_ids: frozenset[str]
    conditions: tuple[Condition, ...]

    def expired(self, today: dt.date) -> bool:
        return today > self.review_by

    def matches(self, doc: Mapping[str, Any]) -> bool:
        rule_ids = field_values(doc, "wazuh.rule.id")
        if not any(str(r) in self.rule_ids for r in rule_ids):
            return False
        return all(c.holds(doc) for c in self.conditions)


@dataclass(frozen=True)
class Suppressions:
    entries: tuple[Suppression, ...]

    def active(self, today: dt.date) -> tuple[Suppression, ...]:
        return tuple(s for s in self.entries if not s.expired(today))

    def expired(self, today: dt.date) -> tuple[Suppression, ...]:
        return tuple(s for s in self.entries if s.expired(today))

    def match(self, doc: Mapping[str, Any], today: dt.date) -> Suppression | None:
        """The first active suppression that matches the finding, or None (forward it)."""
        for s in self.entries:
            if not s.expired(today) and s.matches(doc):
                return s
        return None


def _condition(where: str, raw: Any) -> Condition:
    if not isinstance(raw, Mapping):
        raise SuppressionError(f"{where}: a condition is a mapping with 'field' and one operator")
    field = raw.get("field")
    if not isinstance(field, str) or not field.strip():
        raise SuppressionError(f"{where}: 'field' is required")
    ops = [op for op in _OPS if op in raw]
    extra = set(raw) - {"field", *_OPS}
    if extra:
        raise SuppressionError(f"{where}: unknown key(s) {sorted(extra)}")
    if len(ops) != 1:
        raise SuppressionError(f"{where}: give exactly one of {', '.join(_OPS)}")
    op = ops[0]
    value = raw[op]
    if op == "in":
        if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
            raise SuppressionError(f"{where}: 'in' takes a non-empty list of strings")
        return Condition(field, op, tuple(value))
    if not isinstance(value, str) or not value:
        raise SuppressionError(f"{where}: '{op}' takes a non-empty string")
    if op == "prefix" and len(value) < 3:
        raise SuppressionError(f"{where}: a prefix shorter than 3 characters is too broad")
    if op == "regex":
        if value in (".*", ".+", "^", "$", ""):
            raise SuppressionError(f"{where}: the regex matches everything")
        try:
            pattern = re.compile(value)
        except re.error as exc:
            raise SuppressionError(f"{where}: bad regex: {exc}") from None
        if pattern.search("") is not None:
            raise SuppressionError(
                f"{where}: the regex matches an empty string, so it is too broad"
            )
        return Condition(field, op, (value,), pattern)
    return Condition(field, op, (value,))


def _entry(index: int, raw: Any, today: dt.date) -> Suppression:
    where = f"suppressions[{index}]"
    if not isinstance(raw, Mapping):
        raise SuppressionError(f"{where}: an entry is a mapping")
    sid = raw.get("id")
    if not isinstance(sid, str) or not _ID.match(sid):
        raise SuppressionError(f"{where}: 'id' must be lowercase letters, digits and '-'")
    where = f"suppression {sid!r}"
    allowed = {"id", "description", "reason", "owner", "review_by", "rule_ids", "match"}
    extra = set(raw) - allowed
    if extra:
        raise SuppressionError(f"{where}: unknown key(s) {sorted(extra)}")
    reason = raw.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < 10:
        raise SuppressionError(f"{where}: 'reason' is required (why this is normal operation)")
    review = raw.get("review_by")
    if isinstance(review, str):
        try:
            review = dt.date.fromisoformat(review)
        except ValueError:
            raise SuppressionError(f"{where}: 'review_by' must be a date (YYYY-MM-DD)") from None
    if not isinstance(review, dt.date) or isinstance(review, dt.datetime):
        raise SuppressionError(f"{where}: 'review_by' must be a date (YYYY-MM-DD)")
    if review - today > MAX_REVIEW_HORIZON:
        raise SuppressionError(f"{where}: 'review_by' is more than a year ahead")
    rule_ids = raw.get("rule_ids")
    if (
        not isinstance(rule_ids, list)
        or not rule_ids
        or not all(isinstance(r, str) and r for r in rule_ids)
    ):
        raise SuppressionError(f"{where}: 'rule_ids' is a non-empty list of Wazuh rule ids")
    match = raw.get("match")
    if not isinstance(match, list) or not match:
        raise SuppressionError(
            f"{where}: 'match' needs at least one condition: a rule id alone is too broad"
        )
    conditions = tuple(_condition(f"{where} match[{i}]", c) for i, c in enumerate(match))
    return Suppression(sid, reason.strip(), review, frozenset(rule_ids), conditions)


def parse(doc: Any, today: dt.date | None = None) -> Suppressions:
    today = today or dt.date.today()
    if doc is None:
        return Suppressions(())
    if not isinstance(doc, Mapping) or doc.get("version") != 1:
        raise SuppressionError("the file must be a mapping with 'version: 1'")
    extra = set(doc) - {"version", "suppressions"}
    if extra:
        raise SuppressionError(f"unknown top-level key(s) {sorted(extra)}")
    raw = doc.get("suppressions") or []
    if not isinstance(raw, list):
        raise SuppressionError("'suppressions' is a list")
    entries = tuple(_entry(i, r, today) for i, r in enumerate(raw))
    seen: set[str] = set()
    for e in entries:
        if e.id in seen:
            raise SuppressionError(f"suppression {e.id!r}: duplicate id")
        seen.add(e.id)
    return Suppressions(entries)


def load(path: str, today: dt.date | None = None) -> Suppressions:
    with open(path, encoding="utf-8") as fh:
        return parse(yaml.safe_load(fh), today)


def ids(entries: Iterable[Suppression]) -> list[str]:
    return [e.id for e in entries]
