from __future__ import annotations

import base64
import json
import subprocess
import time

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from starlette.testclient import TestClient
from vigil_host_enroller.app import Enroller, Files, RateLimit, Settings
from vigil_host_enroller.inventory import Inventory
from vigil_host_enroller.ott import SigningKey, host_token
from vigil_host_enroller.proxmox import NotVerified, Proxmox, ProxmoxError

SEED = "s" * 40
FP = "f142519a9b37af2fb41cdd36222a2401a5d7313a015bd988730356362caadf33"
UUID_A = "0d6c2f43-9d1e-4b7e-8f53-6a8d6e2b1c01"
UUID_B = "0d6c2f43-9d1e-4b7e-8f53-6a8d6e2b1c02"


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode(token: str, key: SigningKey) -> tuple[dict, dict]:
    h, c, sig = token.split(".")
    jwk = key.public_jwk()
    pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64d(jwk["x"]), "big"), int.from_bytes(b64d(jwk["y"]), "big"), ec.SECP256R1()
    ).public_key()
    raw = b64d(sig)
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    pub.verify(der, f"{h}.{c}".encode(), ec.ECDSA(hashes.SHA256()))  # raises if wrong
    return json.loads(b64d(h)), json.loads(b64d(c))


# --- ott ------------------------------------------------------------------------------


def test_key_from_seed_is_stable_and_seed_dependent():
    a, b = SigningKey.from_seed(SEED), SigningKey.from_seed(SEED)
    assert a.public_jwk() == b.public_jwk()
    assert SigningKey.from_seed("t" * 40).kid() != a.kid()
    with pytest.raises(ValueError):
        SigningKey.from_seed("short")


def test_host_token_shape_and_signature():
    key = SigningKey.from_seed(SEED)
    tok = host_token(
        key,
        provisioner="hosts-enroll",
        ca_url="https://ca.example.net/",
        fingerprint=FP.upper(),
        subject="10.30.50.223",
        principals=["10.30.50.223", "vm.example.net"],
        now=1000,
    )
    header, claims = decode(tok, key)
    assert header == {"alg": "ES256", "kid": key.kid(), "typ": "JWT"}
    assert claims["iss"] == "hosts-enroll"
    assert claims["sub"] == "10.30.50.223"
    assert claims["aud"] == "https://ca.example.net/1.0/ssh/sign"
    assert claims["exp"] - claims["nbf"] == 300
    assert claims["sha"] == FP
    assert claims["step"]["ssh"]["certType"] == "host"
    assert claims["step"]["ssh"]["principals"] == ["10.30.50.223", "vm.example.net"]
    assert len(claims["jti"]) == 64
    other = host_token(
        key, provisioner="p", ca_url="https://c", fingerprint=FP, subject="x", principals=["x"]
    )
    assert decode(other, key)[1]["jti"] != claims["jti"]


# --- proxmox --------------------------------------------------------------------------

RESOURCES = [
    {
        "type": "qemu",
        "vmid": 101,
        "node": "pve1",
        "name": "good",
        "status": "running",
        "tags": "linux;step-enroll",
    },
    {
        "type": "qemu",
        "vmid": 102,
        "node": "pve2",
        "name": "untagged",
        "status": "running",
        "tags": "linux",
    },
    {
        "type": "qemu",
        "vmid": 103,
        "node": "pve1",
        "name": "stopped",
        "status": "stopped",
        "tags": "step-enroll",
    },
    {
        "type": "qemu",
        "vmid": 9000,
        "node": "pve1",
        "name": "tmpl",
        "status": "stopped",
        "tags": "step-enroll",
        "template": 1,
    },
    {
        "type": "lxc",
        "vmid": 200,
        "node": "pve1",
        "name": "ct",
        "status": "running",
        "tags": "step-enroll",
    },
    {
        "type": "qemu",
        "vmid": 104,
        "node": "pve3",
        "name": "noagent",
        "status": "running",
        "tags": "step-enroll",
    },
]


def agent(*ips):
    return {
        "result": [
            {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1"}]},
            {
                "name": "ens18",
                "ip-addresses": [{"ip-address": ip} for ip in ips]
                + [{"ip-address": "fe80::1%ens18"}],
            },
        ]
    }


def pve_transport(resources=None, agents=None, configs=None, seen=None, status=200):
    resources = RESOURCES if resources is None else resources
    agents = {101: agent("10.30.50.223", "2001:db8::5")} if agents is None else agents
    configs = configs or {101: {"smbios1": f"uuid={UUID_A.upper()},base64=0"}, 104: {}}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "PVEAPIToken=u@pve!t=secret"
        path = request.url.path.removeprefix("/api2/json")
        if seen is not None:
            seen.append(path)
        if status != 200:
            return httpx.Response(status)
        if path == "/cluster/resources":
            return httpx.Response(200, json={"data": resources})
        parts = path.split("/")
        vmid = int(parts[4])
        if path.endswith("/agent/network-get-interfaces"):
            if vmid not in agents:
                return httpx.Response(500, json={"data": None})
            return httpx.Response(200, json={"data": agents[vmid]})
        if path.endswith("/config"):
            return httpx.Response(200, json={"data": configs.get(vmid, {})})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def pve(**kw) -> Proxmox:
    return Proxmox(
        urls=["https://pve.example:8006"],
        token_id="u@pve!t",
        token_secret="secret",
        client=httpx.AsyncClient(transport=pve_transport(**kw)),
    )


@pytest.mark.anyio
async def test_verify_matches_tag_address_and_uuid():
    seen: list[str] = []
    p = pve(seen=seen)
    vm = await p.verify("10.30.50.223", UUID_A)
    assert (vm.vmid, vm.node, vm.name) == (101, "pve1", "good")
    assert "fe80::1" not in vm.addresses and "127.0.0.1" not in vm.addresses
    # Only tagged, running QEMU VMs are read: not 102 (no tag), 103 (stopped), 9000, 200.
    assert {s.split("/")[4] for s in seen if s.startswith("/nodes")} == {"101", "104"}
    assert (await p.verify("2001:db8::5", UUID_A)).vmid == 101


@pytest.mark.anyio
async def test_verify_refusals():
    p = pve()
    with pytest.raises(NotVerified, match="SMBIOS UUID does not match"):
        await p.verify("10.30.50.223", UUID_B)
    with pytest.raises(NotVerified, match="no running VM"):
        await p.verify("10.30.50.224", UUID_A)
    with pytest.raises(NotVerified, match="send the SMBIOS UUID"):
        await p.verify("10.30.50.223", "not-a-uuid")
    two = pve(agents={101: agent("10.30.50.9"), 104: agent("10.30.50.9")})
    with pytest.raises(NotVerified, match="more than one"):
        await two.verify("10.30.50.9", UUID_A)
    # The untagged VM's address never matches, even with its agent up.
    untagged = pve(agents={102: agent("10.30.50.50")})
    with pytest.raises(NotVerified):
        await untagged.verify("10.30.50.50", UUID_A)


@pytest.mark.anyio
async def test_token_refused_is_an_error_not_a_refusal():
    with pytest.raises(ProxmoxError, match="refused the token"):
        await pve(status=401).verify("10.30.50.223", UUID_A)


# --- inventory ------------------------------------------------------------------------


def test_inventory_persists_moves_and_goes_stale(tmp_path):
    path = tmp_path / "inv.json"
    inv = Inventory(str(path), stale_seconds=100)
    inv.enrolled("10.0.0.5", vmid=1, node="n", name="a", principals=["10.0.0.5"])
    assert inv.responder_hosts() == []  # no kit yet
    inv.reported("10.0.0.5", vmid=1, node="n", name="a", kit="0.3.0")
    assert [h.address for h in inv.responder_hosts()] == ["10.0.0.5"]
    again = Inventory(str(path), stale_seconds=100)
    assert again.all()[0].principals == ["10.0.0.5"]
    # The same VM with a new address replaces its entry.
    again.reported("10.0.0.6", vmid=1, node="n", name="a", kit="0.3.0")
    assert [h.address for h in again.all()] == ["10.0.0.6"]
    assert again.responder_hosts(now=time.time() + 101) == []
    # A report without a ready kit takes the host off the list.
    again.reported("10.0.0.6", vmid=1, node="n", name="a", kit="")
    assert again.responder_hosts() == []


# --- app ------------------------------------------------------------------------------


def settings(**kw) -> Settings:
    env = {
        "PUBLIC_URL": "https://enroll.example.net/",
        "STEPCA_URL": "https://ca.example.net",
        "STEPCA_FINGERPRINT": FP,
        "ENROLL_ALLOW": "10.30.50.0/24",
        "ENROLL_DENY": "10.30.50.80/28",
        "DNS_DOMAINS": "example.net",
        "INVENTORY_TOKEN": "i" * 40,
        "KIT_NEVER_BLOCK": "10.30.10.5",
        "ENROLL_HOST_ARGS": "--admin-user root --map robert:robert",
        "FILES_DIR": "/nonexistent",
        **kw,
    }
    return Settings.from_env(env)


class Registered:
    registered, detail = True, "registered"


def enroller(tmp_path, **kw) -> Enroller:
    s = settings()

    async def resolver(name: str) -> set[str]:
        return {"10.30.50.223"} if name == "good.example.net" else set()

    return Enroller(
        settings=s,
        key=SigningKey.from_seed(SEED),
        proxmox=pve(**kw),
        inventory=Inventory(str(tmp_path / "inv.json")),
        files=Files(s),
        stepca=Registered(),  # type: ignore[arg-type]
        resolver=resolver,
    )


def client(app, ip="10.30.50.223") -> TestClient:
    return TestClient(app, base_url="https://enroll.example.net", client=(ip, 40000))


def test_enroll_gives_token_and_principals(tmp_path):
    e = enroller(tmp_path)
    r = client(e.public_app()).post("/v1/enroll", json={"uuid": UUID_A})
    assert r.status_code == 200, r.text
    token, principals = r.text.splitlines()
    assert principals == "10.30.50.223 good.example.net"
    _, claims = decode(token, e.key)
    assert claims["sub"] == "10.30.50.223"
    assert claims["aud"] == "https://ca.example.net/1.0/ssh/sign"
    assert e.inv.all()[0].vmid == 101


def test_enroll_refusals(tmp_path):
    e = enroller(tmp_path)
    app = e.public_app()
    assert client(app, "10.30.50.85").post("/v1/enroll", json={"uuid": UUID_A}).status_code == 403
    assert client(app, "192.168.1.5").post("/v1/enroll", json={"uuid": UUID_A}).status_code == 403
    r = client(app).post("/v1/enroll", json={"uuid": UUID_B})
    assert r.status_code == 403 and "UUID" in r.text
    assert client(app).post("/v1/enroll", content=b"[1]").status_code == 400
    # X-Forwarded-For changes nothing: the TCP source is the evidence.
    r = client(app, "10.30.50.224").post(
        "/v1/enroll", json={"uuid": UUID_A}, headers={"X-Forwarded-For": "10.30.50.223"}
    )
    assert r.status_code == 403
    assert e.inv.all() == []


def test_enroll_rate_limit_and_unregistered(tmp_path):
    e = enroller(tmp_path)
    e.limit = RateLimit(per_address=2, total=100)
    c = client(e.public_app())
    codes = [c.post("/v1/enroll", json={"uuid": UUID_A}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    e.stepca.registered, e.stepca.detail = False, "step-ca has no provisioner"
    assert client(e.public_app(), "10.30.50.9").post("/v1/enroll", json={}).status_code == 503


def test_proxmox_down_is_503(tmp_path):
    e = enroller(tmp_path, status=401)
    assert client(e.public_app()).post("/v1/enroll", json={"uuid": UUID_A}).status_code == 503


def test_report_and_inventory(tmp_path):
    e = enroller(tmp_path)
    pub, internal = client(e.public_app()), client(e.internal_app(), "172.16.1.1")
    assert pub.post("/v1/report", json={"uuid": UUID_A, "kit": "0.3.0"}).text == "ok\n"
    assert pub.post("/v1/report", json={"uuid": UUID_A, "kit": "$(id)"}).status_code == 400
    assert internal.get("/v1/inventory").status_code == 401
    r = internal.get("/v1/inventory", headers={"Authorization": "Bearer " + "i" * 40})
    assert [h["address"] for h in r.json()["hosts"]] == ["10.30.50.223"]
    # The public listener has no inventory and no key.
    assert pub.get("/v1/inventory").status_code == 404
    assert internal.get("/v1/jwk").json()["kid"] == e.key.kid()


def test_bootstrap_renders_quoted_values_and_parses(tmp_path):
    e = enroller(tmp_path)
    r = client(e.public_app()).get("/bootstrap.sh")
    assert r.status_code == 200
    text = r.text
    assert "@@" not in text
    assert "ENROLLER='https://enroll.example.net'" in text
    assert "ENROLL_ARGS='--admin-user root --map robert:robert'" in text
    assert f"FINGERPRINT='{FP}'" in text
    subprocess.run(["sh", "-n"], input=text.encode(), check=True)
    t = client(e.public_app()).get("/template.sh").text
    assert "@@" not in t
    subprocess.run(["sh", "-n"], input=t.encode(), check=True)
    assert client(e.public_app()).get("/files/enroll-host.sh").status_code == 200
    assert client(e.public_app()).get("/files/../app.py").status_code == 404
    assert client(e.public_app()).get("/files/step").status_code == 404  # none in tests


def test_settings_refuse_bad_values():
    with pytest.raises(SystemExit):
        settings(STEPCA_FINGERPRINT="abc")
    with pytest.raises(SystemExit):
        settings(INVENTORY_TOKEN="short")
    with pytest.raises(SystemExit):
        settings(KIT_PRINCIPAL="root")
    with pytest.raises(ValueError):
        settings(KIT_NEVER_BLOCK="not-an-address")


def test_source_address_reaches_the_transport():
    p = Proxmox(
        urls=["https://pve"], token_id="u@pve!t", token_secret="x", source_address="10.30.10.93"
    )
    pool = p._client._transport._pool
    assert pool._local_address == "10.30.10.93"


def test_every_curl_in_the_host_scripts_has_a_connect_timeout():
    from importlib import resources

    files = resources.files("vigil_host_enroller") / "files"
    for name in (
        "bootstrap.sh",
        "template.sh",
        "vigil-enroll-report",
        "vigil-enroll-firstboot.service",
    ):
        for line in (files / name).read_text().splitlines():
            if "curl " in line and not line.lstrip().startswith("#"):
                assert "--connect-timeout" in line, (name, line)
