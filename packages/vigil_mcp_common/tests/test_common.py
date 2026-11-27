import io
import json

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from vigil_mcp_common import (
    AuditLog,
    BearerAuthMiddleware,
    EffectClass,
    ExpiringActions,
    HttpSettings,
    Limit,
    RateLimited,
    RateLimiter,
    TargetNotAllowed,
    TargetPolicy,
    TokenConfigError,
    TokenSet,
    TtlBounds,
    TtlOutOfRange,
    redact,
    tool_annotations,
)

TOKEN = "t" * 40
OTHER = "o" * 40


# --- auth -------------------------------------------------------------------------------------


def test_token_set_matches_named_principal():
    tokens = TokenSet({"vigil": TOKEN, "claude": OTHER})
    assert tokens.principal_for(TOKEN) == "vigil"
    assert tokens.principal_for_header(f"Bearer {OTHER}") == "claude"
    assert tokens.principal_for_header(f"bearer {OTHER}") == "claude"
    assert tokens.principal_for_header("Bearer nope") is None
    assert tokens.principal_for_header(f"Basic {TOKEN}") is None
    assert tokens.principal_for_header(None) is None


@pytest.mark.parametrize("tokens", [{}, {"vigil": "short"}, {"bad name": TOKEN}])
def test_token_set_refuses_unsafe_config(tokens):
    with pytest.raises(TokenConfigError):
        TokenSet(tokens)


def test_token_set_from_env_file(tmp_path):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"vigil": TOKEN}))
    assert TokenSet.from_env({"MCP_TOKENS_FILE": str(path)}).principals == ["vigil"]
    assert TokenSet.from_env({"MCP_TOKEN": TOKEN}).principals == ["vigil"]
    with pytest.raises(TokenConfigError):
        TokenSet.from_env({})


def _client() -> TestClient:
    async def hello(request):
        return PlainTextResponse(request.scope["state"].get("principal", "-"))

    async def health(_):
        return PlainTextResponse("ok")

    inner = Starlette(routes=[Route("/mcp", hello), Route("/healthz", health)])
    return TestClient(BearerAuthMiddleware(inner, TokenSet({"vigil": TOKEN})))


def test_middleware_refuses_without_token_and_allows_health():
    client = _client()
    response = client.get("/mcp")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    assert client.get("/mcp", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/healthz").status_code == 200
    ok = client.get("/mcp", headers={"Authorization": f"Bearer {TOKEN}"})
    assert ok.status_code == 200 and ok.text == "vigil"


# --- allowlist --------------------------------------------------------------------------------


def test_policy_allow_and_deny():
    policy = TargetPolicy.from_patterns(
        ["192.0.2.0/24", "*.example.com", "db.example.net"], ["192.0.2.1", "vault.example.com"]
    )
    assert policy.check("192.0.2.10") == "192.0.2.10"
    assert policy.check("Web.Example.com.") == "web.example.com"
    assert policy.check("db.example.net") == "db.example.net"
    refused = ["192.0.2.1", "vault.example.com", "198.51.100.1", "example.com", "x.example.org"]
    for target in refused:
        with pytest.raises(TargetNotAllowed):
            policy.check(target)


def test_empty_policy_allows_nothing():
    with pytest.raises(TargetNotAllowed):
        TargetPolicy.from_csv(None).check("192.0.2.1")


@pytest.mark.parametrize("pattern", ["foo*.example.com", "a b"])
def test_policy_refuses_bad_patterns(pattern):
    with pytest.raises(ValueError):
        TargetPolicy.from_patterns([pattern])


# --- rate limit -------------------------------------------------------------------------------


def test_rate_limiter_window():
    now = [0.0]
    limiter = RateLimiter({"block": Limit(2, 60)}, clock=lambda: now[0])
    limiter.acquire("block")
    limiter.acquire("block")
    with pytest.raises(RateLimited) as err:
        limiter.acquire("block")
    assert err.value.retry_after == pytest.approx(60)
    limiter.acquire("unlimited")  # no default limit
    now[0] = 61
    limiter.acquire("block")


def test_rate_limiter_zero_calls_refuses_everything():
    with pytest.raises(RateLimited):
        RateLimiter({}, default=Limit(0, 60)).acquire("anything")


# --- audit ------------------------------------------------------------------------------------


def test_audit_writes_json_and_redacts():
    stream = io.StringIO()
    AuditLog("srv", stream).record(
        tool="t",
        principal="vigil",
        outcome="ok",
        effect="read",
        target="192.0.2.1",
        api_token="s3cret",
        nested={"Password": "x", "ok": 1},
    )
    event = json.loads(stream.getvalue())
    assert event["server"] == "srv" and event["outcome"] == "ok"
    assert event["api_token"] == "[redacted]"
    assert event["nested"] == {"Password": "[redacted]", "ok": 1}
    assert "s3cret" not in stream.getvalue()


def test_redact_lists():
    assert redact([{"secret": 1}, 2]) == [{"secret": "[redacted]"}, 2]


# --- expiring actions -------------------------------------------------------------------------


def test_expiring_actions_undo_and_persist(tmp_path):
    now = [1000.0]
    undone = []
    state = tmp_path / "state.json"
    actions = ExpiringActions(state, clock=lambda: now[0])
    actions.on_expiry("hold", lambda a: undone.append(a.target))
    action = actions.add("hold", "192.0.2.5", 60, reason="test")
    assert actions.find("hold", "192.0.2.5") == action

    # A restart reloads what was applied.
    reloaded = ExpiringActions(state, clock=lambda: now[0])
    reloaded.on_expiry("hold", lambda a: undone.append(a.target))
    assert [a.action_id for a in reloaded.active()] == [action.action_id]

    assert reloaded.sweep().undone == []
    now[0] = 1061
    assert reloaded.sweep().undone == [action.action_id]
    assert undone == ["192.0.2.5"] and reloaded.active() == []


def test_expiring_actions_retry_failed_undo():
    now = [0.0]
    calls = []

    def flaky(action):
        calls.append(action.action_id)
        if len(calls) == 1:
            raise ConnectionError("vendor down")

    actions = ExpiringActions(clock=lambda: now[0])
    actions.on_expiry("hold", flaky)
    action = actions.add("hold", "192.0.2.5", 1)
    now[0] = 2
    first = actions.sweep()
    assert first.failed == {action.action_id: "ConnectionError"}
    assert actions.sweep().undone == [action.action_id]


def test_expiring_actions_need_a_handler():
    with pytest.raises(KeyError):
        ExpiringActions().add("unknown", "x", 60)


def test_ttl_bounds_refuse_instead_of_clamping():
    bounds = TtlBounds(60, 3600)
    assert bounds.clamp_check(600) == 600
    for value in (0, 59, 3601):
        with pytest.raises(TtlOutOfRange):
            bounds.clamp_check(value)


# --- effects and settings ---------------------------------------------------------------------


def test_annotations_follow_effect_class():
    assert tool_annotations(EffectClass.READ).read_only_hint is True
    reversible = tool_annotations(EffectClass.REVERSIBLE)
    assert reversible.read_only_hint is False and reversible.destructive_hint is False
    assert tool_annotations(EffectClass.IRREVERSIBLE).destructive_hint is True


def test_http_settings_from_env():
    settings = HttpSettings.from_env(
        {
            "MCP_HOST": "192.0.2.80",
            "MCP_PORT": "9000",
            "MCP_ALLOWED_HOSTS": "mcp.example.com, mcp.example.com:*",
        }
    )
    assert (settings.host, settings.port) == ("192.0.2.80", 9000)
    assert settings.allowed_hosts == ("mcp.example.com", "mcp.example.com:*")
    assert HttpSettings.from_env({}).allowed_hosts == ("127.0.0.1:*", "localhost:*")
