"""The step-ca client against a mock CA (a real asyncssh CA key), and the server's guard rails."""

import base64
import hashlib
import io
import json
import ssl
import time

import asyncssh
import httpx
import pytest
from starlette.testclient import TestClient
from vigil_mcp_common import AuditLog, HttpSettings, TokenSet, build_app
from vigil_mcp_stepca_responder import stepca as sc
from vigil_mcp_stepca_responder.server import EFFECTS, Hosts, InventorySource, create_server
from vigil_mcp_stepca_responder.ssh import HostUnreachable, Result

CA_KEY = asyncssh.generate_private_key("ssh-ed25519")
HOST_CA = asyncssh.generate_private_key("ssh-ed25519")


def mock_ca(seen):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/application/o/token/":
            form = dict(httpx.QueryParams(request.content.decode()))
            seen["token_form"] = form
            return httpx.Response(200, json={"id_token": "header.payload.sig"})
        if request.url.path == "/ssh/sign":
            body = json.loads(request.content)
            seen["sign"] = body
            user_key = asyncssh.import_public_key(sc.openssh_line(body["publicKey"]))
            cert = CA_KEY.generate_user_certificate(
                user_key, body["keyID"], principals=["sa-vigil-responder"], valid_before="5m"
            )
            wire = base64.b64encode(cert.public_data).decode()
            return httpx.Response(201, json={"crt": wire})
        if request.url.path == "/ssh/roots":
            return httpx.Response(
                200,
                json={
                    "hostKey": [base64.b64encode(HOST_CA.convert_to_public().public_data).decode()]
                },
            )
        return httpx.Response(404)

    return httpx.Client(base_url="https://ca.example", transport=httpx.MockTransport(handler))


def make_ca(seen):
    return sc.StepCA(
        url="https://ca.example",
        fingerprint="00",
        token_url="https://ca.example/application/o/token/",
        client_id="step-ca-responder",
        username="sa-vigil-responder",
        password="app-password",
        http=mock_ca(seen),
    )


def test_sign_flow_and_cache():
    seen = {}
    ca = make_ca(seen)
    cred = ca.credential()
    assert seen["token_form"]["grant_type"] == "client_credentials"
    assert seen["token_form"]["client_id"] == "step-ca-responder"
    assert seen["sign"]["ott"] == "header.payload.sig"
    assert seen["sign"]["certType"] == "user" and seen["sign"]["validBefore"] == "5m"
    assert cred.principals == ("sa-vigil-responder",)
    assert cred.expires_at - time.time() <= 300
    seen.clear()
    assert ca.credential() is cred and not seen  # cached until near expiry
    assert len(ca.host_ca_keys()) == 1


def test_root_fingerprint_is_enforced(monkeypatch):
    # A real self-signed root PEM is not needed: the check is on the DER bytes.
    pem = ssl.DER_cert_to_PEM_cert(b"not-a-real-cert")
    der = ssl.PEM_cert_to_DER_cert(pem)

    class Bare:
        def __init__(self, *a, **k):
            pass

        def get(self, url):
            return httpx.Response(200, json={"ca": pem})

    monkeypatch.setattr(sc.httpx, "Client", Bare)
    good = sc.StepCA(
        url="https://ca.example",
        fingerprint=hashlib.sha256(der).hexdigest(),
        token_url="x",
        client_id="c",
        username="sa-x",
        password="p",
    )
    bad = sc.StepCA(
        url="https://ca.example",
        fingerprint="ab" * 32,
        token_url="x",
        client_id="c",
        username="sa-x",
        password="p",
    )
    with pytest.raises(sc.CAError, match="does not match"):
        bad.client()
    with pytest.raises(Exception):  # noqa: B017 - the fake PEM can't be loaded as a CA; fine
        good.client()


TOKEN = "r" * 40


class FakeCA:
    username, lifetime = "sa-vigil-responder", "5m"

    def credential(self):
        return "cred"

    def host_ca_keys(self):
        return ["host-ca"]


class FakeRunner:
    def __init__(self):
        self.requests = []

    def run(self, host, request, cred, host_ca):
        self.requests.append((host, request))
        if request.startswith("block-ip"):
            ip, s = request.split()[1:]
            return Result(0, f"blocked {ip} for {s}s\n", "")
        if request == "list-blocks":
            # Real nft -j output (nftables 1.1.3), one document per set.
            v4 = json.dumps(
                {
                    "nftables": [
                        {"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
                        {
                            "set": {
                                "family": "inet",
                                "name": "blocked4",
                                "table": "vigil_respond",
                                "type": "ipv4_addr",
                                "handle": 3,
                                "flags": ["timeout"],
                                "elem": [
                                    {
                                        "elem": {
                                            "val": "198.51.100.7",
                                            "timeout": 600,
                                            "expires": 587,
                                        }
                                    }
                                ],
                            }
                        },
                    ]
                }
            )
            v6 = '{"nftables": [{"metainfo": {"version": "1.1.3"}}, {"set": {"name": "blocked6"}}]}'
            return Result(0, v4 + "\n" + v6 + "\n", "")
        if request.startswith("unblock-ip"):
            return Result(0, f"unblocked {request.split()[1]}\n", "")
        if request == "check":
            return Result(0, "ok\n", "")
        return Result(2, "", "refused: unknown verb")


@pytest.fixture
def harness():
    tokens = TokenSet({"vigil": TOKEN})
    runner = FakeRunner()
    audit = io.StringIO()
    server = create_server(
        tokens=tokens,
        ca=FakeCA(),
        runner=runner,
        hosts=Hosts(["host-a.example.com"]),
        never_block=["192.0.2.0/24"],
        audit=AuditLog("t", audit),
    )
    app = build_app(server, tokens, HttpSettings(allowed_hosts=("testserver",)))
    with TestClient(app) as client:
        rpc(
            client,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"},
            },
        )
        yield client, runner, audit


def rpc(client, method, params=None, token=TOKEN):
    h = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-11-25",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    r = client.post(
        "/mcp",
        headers=h,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
    )
    t = r.text
    if "data:" in t:
        t = next(line[5:] for line in t.splitlines() if line.startswith("data:"))
    return json.loads(t) if t.strip().startswith("{") else r.status_code


def call(client, tool, **args):
    res = rpc(client, "tools/call", {"name": tool, "arguments": args})["result"]
    if res.get("isError"):
        return None, res["content"][0]["text"]
    return res.get("structuredContent") or json.loads(res["content"][0]["text"]), None


def test_classes_and_annotations(harness):
    client, _, _ = harness
    tools = {t["name"]: t for t in rpc(client, "tools/list")["result"]["tools"]}
    assert set(tools) == set(EFFECTS)
    assert tools["list_blocks"]["annotations"]["readOnlyHint"]
    assert not tools["block_ip"]["annotations"]["readOnlyHint"]


def test_block_ip_happy_path(harness):
    client, runner, audit = harness
    out, err = call(
        client,
        "block_ip",
        host="host-a.example.com",
        address="198.51.100.7",
        ttl_seconds=3600,
        reason="brute force from this address",
    )
    assert err is None
    assert runner.requests[-1] == ("host-a.example.com", "block-ip 198.51.100.7 3600")
    assert out["undo"]["tool"] == "unblock_ip"
    assert '"outcome": "ok"' in audit.getvalue()


@pytest.mark.parametrize(
    ("args", "why"),
    [
        (
            {"host": "other.example.com", "address": "198.51.100.7", "ttl_seconds": 600},
            "allow list",
        ),
        ({"host": "host-a.example.com", "address": "192.0.2.5", "ttl_seconds": 600}, "deny list"),
        ({"host": "host-a.example.com", "address": "127.0.0.1", "ttl_seconds": 600}, "deny"),
        (
            {"host": "host-a.example.com", "address": "198.51.100.7", "ttl_seconds": 30},
            "ttl_seconds",
        ),
        (
            {"host": "host-a.example.com", "address": "not-an-ip; id", "ttl_seconds": 600},
            "IP address",
        ),
    ],
)
def test_refusals_never_reach_the_host(harness, args, why):
    client, runner, _ = harness
    before = len(runner.requests)
    _, err = call(client, "block_ip", reason="r", **args)
    assert err and why in err
    assert len(runner.requests) == before


def test_list_check_unblock(harness):
    client, runner, _ = harness
    out, _ = call(client, "list_blocks", host="host-a.example.com")
    assert out["blocks"] == [
        {"address": "198.51.100.7", "expires_in_seconds": 587, "timeout_seconds": 600}
    ]
    assert call(client, "check_host", host="host-a.example.com")[0]["status"] == "ok"
    call(client, "unblock_ip", host="host-a.example.com", address="198.51.100.7")
    assert runner.requests[-1] == ("host-a.example.com", "unblock-ip 198.51.100.7")


def test_block_rate_limit(harness):
    client, _, _ = harness
    for _ in range(20):
        assert (
            call(
                client,
                "block_ip",
                host="host-a.example.com",
                address="198.51.100.9",
                ttl_seconds=600,
                reason="r",
            )[1]
            is None
        )
    _, err = call(
        client,
        "block_ip",
        host="host-a.example.com",
        address="198.51.100.9",
        ttl_seconds=600,
        reason="r",
    )
    assert err and "rate" in err.lower()


def test_no_token(harness):
    client, _, _ = harness
    h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    assert client.post("/mcp", headers=h, json=body).status_code == 401


# --- the Vigil act carrier ----------------------------------------------------------


class TwoHostRunner(FakeRunner):
    def __init__(self, failing=()):
        super().__init__()
        self.failing = set(failing)

    def run(self, host, request, cred, host_ca):
        if host in self.failing and request.startswith("block-ip"):
            self.requests.append((host, request))
            return Result(2, "", "refused: nft failed")
        return super().run(host, request, cred, host_ca)


def carrier_harness(failing=()):
    tokens = TokenSet({"vigil": TOKEN})
    runner = TwoHostRunner(failing)
    server = create_server(
        tokens=tokens,
        ca=FakeCA(),
        runner=runner,
        hosts=Hosts(["a.example.com", "b.example.com"]),
        never_block=["192.0.2.0/24"],
        carrier_ttl=900,
        audit=AuditLog("t", io.StringIO()),
    )
    client = TestClient(build_app(server, tokens, HttpSettings(allowed_hosts=("testserver",))))
    client.__enter__()
    rpc(
        client,
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    )
    return client, runner


def test_carrier_takes_exactly_vigils_two_arguments():
    client, runner = carrier_harness()
    # Vigil calls {id_arg: target, note_arg: "Vigil <id>: <title>"} and nothing else.
    out, err = call(
        client, "block_address", address="198.51.100.7", note="Vigil act-123: Block 198.51.100.7"
    )
    assert err is None
    assert out["state"] == "blocked" and out["ttl_seconds"] == 900
    assert sorted(h for h, _ in runner.requests) == ["a.example.com", "b.example.com"]
    assert {r for _, r in runner.requests} == {"block-ip 198.51.100.7 900"}
    out, _ = call(client, "unblock_address", address="198.51.100.7", note="Vigil: Unblock")
    assert out["state"] == "unblocked"
    client.__exit__(None, None, None)


def test_carrier_is_all_or_nothing():
    client, runner = carrier_harness(failing={"b.example.com"})
    out, err = call(client, "block_address", address="198.51.100.7", note="n")
    assert err is None
    assert out["state"] == "failed"
    assert "b.example.com" in out["failed"]
    assert out["rolled_back"] == ["a.example.com"]
    assert ("a.example.com", "unblock-ip 198.51.100.7") in runner.requests
    client.__exit__(None, None, None)


def test_carrier_respects_never_block():
    client, runner = carrier_harness()
    _, err = call(client, "block_address", address="192.0.2.9", note="n")
    assert err and "deny list" in err
    assert runner.requests == []
    client.__exit__(None, None, None)


# --- 0.3.0: hosts from the enroller, unreachable hosts -----------------------------------


class UnreachableRunner(TwoHostRunner):
    def __init__(self, failing=(), down=()):
        super().__init__(failing)
        self.down = set(down)

    def run(self, host, request, cred, host_ca):
        if host in self.down:
            self.requests.append((host, request))
            raise HostUnreachable("OSError: [Errno 113] No route to host")
        return super().run(host, request, cred, host_ca)


def inventory_source(hosts, status=200, seen=None):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer inv-token"
        if seen is not None:
            seen.append(1)
        if status != 200:
            return httpx.Response(status)
        return httpx.Response(200, json={"hosts": [{"address": h} for h in hosts]})

    return InventorySource(
        url="http://enroller/v1/inventory",
        token="inv-token",
        subnets=["10.30.50.0/24"],
        refresh_seconds=0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


def harness_with(runner, hosts, **kw):
    tokens = TokenSet({"vigil": TOKEN})
    server = create_server(
        tokens=tokens,
        ca=FakeCA(),
        runner=runner,
        hosts=hosts,
        never_block=["192.0.2.0/24"],
        carrier_ttl=900,
        audit=AuditLog("t", io.StringIO()),
        **kw,
    )
    client = TestClient(build_app(server, tokens, HttpSettings(allowed_hosts=("testserver",))))
    client.__enter__()
    rpc(
        client,
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    )
    return client


@pytest.mark.anyio
async def test_inventory_takes_only_addresses_in_its_subnets():
    src = inventory_source(["10.30.50.223", "10.30.51.9", "evil.example.com", "10.30.50.7"])
    assert await src.addresses() == ["10.30.50.223", "10.30.50.7"]
    hosts = Hosts(["static.example.com"], inventory=src)
    assert await hosts.current() == ["10.30.50.223", "10.30.50.7", "static.example.com"]
    assert await hosts.check("10.30.50.7") == "10.30.50.7"


@pytest.mark.anyio
async def test_inventory_keeps_last_list_when_enroller_fails():
    src = inventory_source(["10.30.50.223"])
    assert await src.addresses() == ["10.30.50.223"]
    src._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    assert await src.addresses() == ["10.30.50.223"]
    assert "503" in src.error or "HTTPStatusError" in src.error


def test_carrier_uses_inventory_hosts_and_skips_unreachable():
    runner = UnreachableRunner(down={"10.30.50.9"})
    client = harness_with(
        runner, Hosts([], inventory=inventory_source(["10.30.50.8", "10.30.50.9"]))
    )
    out, err = call(client, "block_address", address="198.51.100.7", note="n")
    assert err is None, err
    assert out["state"] == "blocked"
    assert out["hosts"] == ["10.30.50.8"]
    assert list(out["unreachable"]) == ["10.30.50.9"]
    out, _ = call(client, "describe_policy")
    assert out["hosts"] == ["10.30.50.8", "10.30.50.9"]
    assert out["inventory"]["subnets"] == ["10.30.50.0/24"]
    client.__exit__(None, None, None)


def test_carrier_fails_when_no_host_is_reachable_or_skip_is_off():
    client = harness_with(UnreachableRunner(down={"a.example.com"}), Hosts(["a.example.com"]))
    out, _ = call(client, "block_address", address="198.51.100.7", note="n")
    assert out["state"] == "failed"
    client.__exit__(None, None, None)
    runner = UnreachableRunner(down={"b.example.com"})
    client = harness_with(runner, Hosts(["a.example.com", "b.example.com"]), skip_unreachable=False)
    out, _ = call(client, "block_address", address="198.51.100.7", note="n")
    assert out["state"] == "failed" and "b.example.com" in out["failed"]
    assert out["rolled_back"] == ["a.example.com"]
    client.__exit__(None, None, None)


def test_refusing_host_still_fails_the_act_with_inventory():
    runner = UnreachableRunner(failing={"10.30.50.8"}, down={"10.30.50.9"})
    client = harness_with(
        runner, Hosts(["a.example.com"], inventory=inventory_source(["10.30.50.8", "10.30.50.9"]))
    )
    out, _ = call(client, "block_address", address="198.51.100.7", note="n")
    assert out["state"] == "failed"
    assert out["rolled_back"] == ["a.example.com"]
    client.__exit__(None, None, None)
