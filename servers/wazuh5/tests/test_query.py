import datetime as dt

import pytest
from vigil_mcp_wazuh5 import query as q

NOW = dt.datetime(2026, 11, 28, 12, 0, tzinfo=dt.UTC)
L = q.Limits()


def test_relative_and_iso_times():
    assert q.parse_time("15m", NOW, default=NOW) == NOW - dt.timedelta(minutes=15)
    assert q.parse_time("2d", NOW, default=NOW) == NOW - dt.timedelta(days=2)
    assert q.parse_time("2026-11-28T10:00:00Z", NOW, default=NOW).hour == 10
    assert q.parse_time(None, NOW, default=NOW) == NOW
    with pytest.raises(q.QueryError):
        q.parse_time("yesterday", NOW, default=NOW)


def test_window_is_bounded_and_ends_now():
    start, end = q.window("24h", None, L, NOW)
    assert end == NOW and start == NOW - dt.timedelta(hours=24)
    _, end = q.window("1h", "2030-01-01T00:00:00Z", L, NOW)
    assert end == NOW  # never in the future
    with pytest.raises(q.QueryError, match="longer than 7"):
        q.window("8d", None, L, NOW)
    with pytest.raises(q.QueryError, match="before"):
        q.window("2026-11-28T11:00:00Z", "2026-11-28T10:00:00Z", L, NOW)


def test_filters_are_exact_terms_only():
    assert q.filter_clauses({"user.name": "root"}) == [{"term": {"user.name": "root"}}]
    assert q.filter_clauses({"wazuh.agent.name": ["a", "b"]}) == [
        {"terms": {"wazuh.agent.name": ["a", "b"]}}
    ]
    for bad in (
        {"user.name*": "x"},
        {"a b": "x"},
        {"user.name": {"regexp": ".*"}},
        {"user.name": []},
        {"user.name": True},
        {"x": "y" * 300},
    ):
        with pytest.raises(q.QueryError):
            q.filter_clauses(bad)
    with pytest.raises(q.QueryError):
        q.filter_clauses({f"f{i}": "x" for i in range(11)})


def test_text_uses_a_restricted_simple_query():
    [clause] = q.text_clause("sshd AND failure")
    sqs = clause["simple_query_string"]
    assert "PREFIX" not in sqs["flags"] and "FUZZY" not in sqs["flags"]
    assert sqs["fields"] == q.TEXT_FIELDS
    assert q.text_clause("  ") == []
    with pytest.raises(q.QueryError):
        q.text_clause("x" * 201)


def test_search_body_bounds():
    s, e = q.window("1h", None, L, NOW)
    body = q.search_body(
        start=s, end=e, filters={"user.name": "root"}, text=None, limit=5, limits=L
    )
    assert body["size"] == 5
    assert (
        body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["lte"] == "2026-11-28T12:00:00Z"
    )
    for bad in (0, 101, True, "5"):
        with pytest.raises(q.QueryError):
            q.search_body(start=s, end=e, filters=None, text=None, limit=bad, limits=L)
    with pytest.raises(q.QueryError):
        q.terms_body(field="user.name", start=s, end=e, filters=None, size=51, limits=L)


def test_trim_cuts_long_strings_and_lists():
    assert q.trim("x" * 2000).endswith("…[cut]")
    assert len(q.trim(list(range(80)))) == 51
    assert q.pick({"a": {"b": "c"}, "d": ""}, ["a.b", "d", "missing.x"]) == {"a.b": "c"}
