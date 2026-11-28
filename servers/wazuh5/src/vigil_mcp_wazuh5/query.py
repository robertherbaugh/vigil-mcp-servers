"""Safe, bounded OpenSearch queries from tool arguments.

A model writes the arguments, and log content can steer the model, so every
argument is treated as untrusted:

- Time: a window ending now or earlier, at most ``max_window`` long.
- Size: at most ``max_limit`` documents, at most ``max_buckets`` buckets.
- Filters: exact ``term``/``terms`` on field names that look like field names.
  No raw query DSL, no scripts, no regex, no wildcard.
- Text: ``simple_query_string`` on a fixed set of fields, with prefix, fuzzy,
  slop and near operators off, and a length cap.
- Documents come back trimmed: long strings are cut, and the output keeps a
  fixed set of fields.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

FIELD = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_.@-]{0,100}$")
RELATIVE = re.compile(r"^(\d{1,4})([mhd])$")
TEXT_FIELDS = ["event.original", "message", "wazuh.rule.title"]
# simple_query_string: AND, OR, NOT, phrases, precedence, whitespace and escapes.
# Not PREFIX (a*), FUZZY (~), SLOP or NEAR: cheap and predictable only.
TEXT_FLAGS = "AND|OR|NOT|PHRASE|PRECEDENCE|WHITESPACE|ESCAPE"
MAX_TEXT = 200
MAX_VALUES = 20
MAX_VALUE_LEN = 256
MAX_STRING = 1000


class QueryError(ValueError):
    """An argument is outside what the server allows. The message says which and why."""


@dataclass(frozen=True)
class Limits:
    max_window: dt.timedelta = dt.timedelta(days=7)
    max_limit: int = 100
    max_buckets: int = 50


def parse_time(value: str | None, now: dt.datetime, *, default: dt.datetime) -> dt.datetime:
    """'15m', '24h', '7d' (before now), or an ISO 8601 time. None: the default."""
    if value is None or value == "":
        return default
    text = value.strip()
    m = RELATIVE.match(text)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = {
            "m": dt.timedelta(minutes=n),
            "h": dt.timedelta(hours=n),
            "d": dt.timedelta(days=n),
        }
        return now - delta[unit]
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise QueryError(f"time {value!r}: use 15m, 24h, 7d or an ISO 8601 time") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def window(
    since: str | None, until: str | None, limits: Limits, now: dt.datetime
) -> tuple[dt.datetime, dt.datetime]:
    end = min(parse_time(until, now, default=now), now)
    start = parse_time(since, now, default=end - dt.timedelta(hours=24))
    if start >= end:
        raise QueryError("since must be before until")
    if end - start > limits.max_window:
        days = limits.max_window.total_seconds() / 86400
        raise QueryError(f"the time window is longer than {days:g} days; narrow it")
    return start, end


def field_name(name: str) -> str:
    if not isinstance(name, str) or not FIELD.match(name):
        raise QueryError(f"field {name!r} is not a field name")
    return name


def filter_clauses(filters: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Exact matches: {"user.name": "admin", "wazuh.agent.name": ["a", "b"]}."""
    if not filters:
        return []
    if not isinstance(filters, Mapping) or len(filters) > 10:
        raise QueryError("filters is an object of at most 10 fields")
    out: list[dict[str, Any]] = []
    for name, value in filters.items():
        field_name(name)
        values = value if isinstance(value, list) else [value]
        if not values or len(values) > MAX_VALUES:
            raise QueryError(f"filter {name}: 1 to {MAX_VALUES} values")
        clean: list[str] = []
        for v in values:
            if isinstance(v, bool) or not isinstance(v, (str, int, float)):
                raise QueryError(f"filter {name}: values are strings or numbers")
            s = str(v)
            if not s or len(s) > MAX_VALUE_LEN:
                raise QueryError(f"filter {name}: a value is empty or longer than {MAX_VALUE_LEN}")
            clean.append(s)
        out.append({"terms": {name: clean}} if len(clean) > 1 else {"term": {name: clean[0]}})
    return out


def text_clause(text: str | None) -> list[dict[str, Any]]:
    if text is None or not text.strip():
        return []
    if len(text) > MAX_TEXT:
        raise QueryError(f"text is longer than {MAX_TEXT} characters")
    return [
        {
            "simple_query_string": {
                "query": text,
                "fields": TEXT_FIELDS,
                "flags": TEXT_FLAGS,
                "default_operator": "and",
                "lenient": True,
            }
        }
    ]


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def search_body(
    *,
    start: dt.datetime,
    end: dt.datetime,
    filters: Mapping[str, Any] | None,
    text: str | None,
    limit: int,
    limits: Limits,
) -> dict[str, Any]:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= limits.max_limit:
        raise QueryError(f"limit is 1 to {limits.max_limit}")
    return {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc", "numeric_type": "date_nanos"}}],
        "track_total_hits": 10_000,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": iso(start), "lte": iso(end)}}},
                    *filter_clauses(filters),
                ],
                "must": text_clause(text),
            }
        },
    }


def terms_body(
    *,
    field: str,
    start: dt.datetime,
    end: dt.datetime,
    filters: Mapping[str, Any] | None,
    size: int,
    limits: Limits,
) -> dict[str, Any]:
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= limits.max_buckets:
        raise QueryError(f"size is 1 to {limits.max_buckets}")
    return {
        "size": 0,
        "track_total_hits": 10_000,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": iso(start), "lte": iso(end)}}},
                    *filter_clauses(filters),
                ]
            }
        },
        "aggs": {"top": {"terms": {"field": field_name(field), "size": size}}},
    }


def trim(value: Any, max_string: int = MAX_STRING) -> Any:
    """Cut long strings and long lists, so one document can't flood the context."""
    if isinstance(value, str):
        return value if len(value) <= max_string else value[:max_string] + "…[cut]"
    if isinstance(value, list):
        items = [trim(v, max_string) for v in value[:50]]
        return items + (["…[cut]"] if len(value) > 50 else [])
    if isinstance(value, Mapping):
        return {k: trim(v, max_string) for k, v in value.items()}
    return value


def pick(src: Mapping[str, Any], paths: list[str]) -> dict[str, Any]:
    """A flat dict of the dotted paths that exist in the document."""
    out: dict[str, Any] = {}
    for path in paths:
        node: Any = src
        for part in path.split("."):
            if isinstance(node, Mapping) and part in node:
                node = node[part]
            else:
                node = None
                break
        if node not in (None, "", [], {}):
            out[path] = trim(node)
    return out
