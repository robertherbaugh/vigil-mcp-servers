"""End to end over streamable HTTP: auth, tools/list, and the guarded rehearsal tools."""

import io
import json

import pytest
from starlette.testclient import TestClient
from vigil_mcp_common import (
    AuditLog,
    HttpSettings,
    Limit,
    RateLimiter,
    TargetPolicy,
    TokenSet,
    build_app,
)
from vigil_mcp_template.server import EFFECTS, create_server

TOKEN = "v" * 40
PROTOCOL = "2025-11-25"
ACCEPT = "application/json, text/event-stream"


@pytest.fixture
def harness():
    tokens = TokenSet({"vigil": TOKEN})
    audit_stream = io.StringIO()
    server, actions = create_server(
        tokens=tokens,
        policy=TargetPolicy.from_patterns(["192.0.2.0/24"], ["192.0.2.1"]),
        limiter=RateLimiter({}, default=Limit(2, 3600)),
        audit=AuditLog("test", audit_stream),
    )
    app = build_app(server, tokens, HttpSettings(allowed_hosts=("testserver",)))
    with TestClient(app) as client:
        yield client, audit_stream, actions


def rpc(client, method, params=None, *, token=TOKEN, rid=1):
    headers = {
        "Accept": ACCEPT,
        "Content-Type": "application/json",
        "MCP-Protocol-Version": PROTOCOL,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
    return client.post("/mcp", headers=headers, json=body)


def initialize(client):
    response = rpc(
        client,
        "initialize",
        {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["result"]


def call(client, name, arguments):
    response = rpc(client, "tools/call", {"name": name, "arguments": arguments}, rid=3)
    assert response.status_code == 200, response.text
    return response.json()["result"]


def test_refuses_without_or_with_wrong_token(harness):
    client, _, _ = harness
    assert rpc(client, "initialize", token=None).status_code == 401
    assert rpc(client, "initialize", token="x" * 40).status_code == 401


def test_health_needs_no_token(harness):
    client, _, _ = harness
    assert client.get("/healthz").json() == {"status": "ok"}


def test_initialize_and_list_tools(harness):
    client, _, _ = harness
    assert initialize(client)["serverInfo"]["name"] == "vigil-mcp-template"
    tools = rpc(client, "tools/list", rid=2).json()["result"]["tools"]
    assert {t["name"] for t in tools} == set(EFFECTS)
    hold = next(t for t in tools if t["name"] == "rehearsal_hold")
    assert hold["annotations"]["readOnlyHint"] is False
    assert hold["annotations"]["destructiveHint"] is False
    assert set(hold["inputSchema"]["properties"]) == {"target", "ttl_seconds", "reason"}


def test_hold_allowed_target_then_release(harness):
    client, audit_stream, actions = harness
    initialize(client)
    result = call(
        client, "rehearsal_hold", {"target": "192.0.2.10", "ttl_seconds": 600, "reason": "drill"}
    )
    assert not result.get("isError"), result
    assert result["structuredContent"]["target"] == "192.0.2.10"
    assert actions.find("rehearsal_hold", "192.0.2.10") is not None

    released = call(client, "rehearsal_release", {"target": "192.0.2.10"})
    assert not released.get("isError"), released
    assert actions.active() == []

    events = [json.loads(line) for line in audit_stream.getvalue().splitlines()]
    assert [(e["tool"], e["outcome"], e["principal"]) for e in events] == [
        ("rehearsal_hold", "ok", "vigil"),
        ("rehearsal_release", "ok", "vigil"),
    ]


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        ({"target": "192.0.2.1", "ttl_seconds": 600, "reason": "x"}, "deny list"),
        ({"target": "198.51.100.7", "ttl_seconds": 600, "reason": "x"}, "allow list"),
        ({"target": "192.0.2.10", "ttl_seconds": 5, "reason": "x"}, "ttl_seconds"),
    ],
)
def test_hold_refusals_are_tool_errors(harness, arguments, reason):
    client, audit_stream, actions = harness
    initialize(client)
    result = call(client, "rehearsal_hold", arguments)
    assert result["isError"] is True
    assert reason in result["content"][0]["text"]
    assert actions.active() == []
    assert json.loads(audit_stream.getvalue().splitlines()[-1])["outcome"] == "refused"


def test_rate_limit_applies_to_actions(harness):
    client, _, _ = harness
    initialize(client)
    for host in ("192.0.2.10", "192.0.2.11"):
        assert not call(
            client, "rehearsal_hold", {"target": host, "ttl_seconds": 600, "reason": "x"}
        ).get("isError")
    third = call(
        client, "rehearsal_hold", {"target": "192.0.2.12", "ttl_seconds": 600, "reason": "x"}
    )
    assert third["isError"] is True and "rate limit" in third["content"][0]["text"]


def test_wrong_host_header_is_refused(harness):
    client, _, _ = harness
    response = client.post(
        "/mcp",
        headers={
            "Host": "evil.example.com",
            "Authorization": f"Bearer {TOKEN}",
            "Accept": ACCEPT,
            "Content-Type": "application/json",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert response.status_code in (400, 421)
