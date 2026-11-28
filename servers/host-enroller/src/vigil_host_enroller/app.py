"""The enroller: a VM proves itself through Proxmox and gets a one-time step-ca host token.

Two listeners:

- public (TLS, PUBLIC_PORT): /bootstrap.sh, /template.sh, /files/*, POST /v1/enroll and
  POST /v1/report. Serve it on its own LoadBalancer address with externalTrafficPolicy
  Local and never behind a proxy: the TCP source address is the evidence, so a proxy (or
  any X-Forwarded-For) would let one host speak for another.
- internal (plain HTTP, INTERNAL_PORT, cluster only): /healthz, /v1/jwk and, with the
  bearer token, /v1/inventory for the responder.

The answers of /v1/enroll and /v1/report are text/plain, so the host scripts need only
sh and curl.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import tarfile
import time
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from . import __version__
from .inventory import Inventory
from .ott import SigningKey, host_token
from .proxmox import VM, NotVerified, Proxmox, ProxmoxError

log = logging.getLogger("vigil-host-enroller")
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
KIT_VERSION = re.compile(r"^[0-9A-Za-z.+_-]{1,40}$")


def _nets(text: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [
        ipaddress.ip_network(p.strip(), strict=False) for p in (text or "").split(",") if p.strip()
    ]


def _csv(text: str | None) -> list[str]:
    return [p.strip() for p in (text or "").split(",") if p.strip()]


def _sh(value: str) -> str:
    """One shell word in single quotes."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def audit(event: str, **fields: Any) -> None:
    print(json.dumps({"ts": round(time.time(), 3), "event": event, **fields}), flush=True)


class RateLimit:
    def __init__(self, per_address: int, total: int, window: float = 3600.0):
        self.per_address, self.total, self.window = per_address, total, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._all: deque[float] = deque()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        for q in (self._hits[key], self._all):
            while q and now - q[0] > self.window:
                q.popleft()
        if len(self._hits[key]) >= self.per_address or len(self._all) >= self.total:
            return False
        self._hits[key].append(now)
        self._all.append(now)
        return True


@dataclass
class Settings:
    public_url: str
    stepca_url: str  # as the hosts reach it; it is also the token's audience
    fingerprint: str
    provisioner: str
    allow: list[Any]
    deny: list[Any]
    dns_domains: list[str]
    enroll_args: str  # extra enroll-host.sh options, from the operator
    kit_principal: str
    kit_never_block: list[str]
    inventory_token: str
    stepca_internal_url: str = ""
    files_dir: str = "/app/files"

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Settings:
        for name in (
            "PUBLIC_URL",
            "STEPCA_URL",
            "STEPCA_FINGERPRINT",
            "ENROLL_ALLOW",
            "INVENTORY_TOKEN",
        ):
            if not env.get(name):
                raise SystemExit(f"{name} is required")
        if len(env["INVENTORY_TOKEN"]) < 32:
            raise SystemExit("INVENTORY_TOKEN must have at least 32 characters")
        fp = env["STEPCA_FINGERPRINT"].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", fp):
            raise SystemExit("STEPCA_FINGERPRINT must be the 64 hex digits of the root's SHA-256")
        never = _csv(env.get("KIT_NEVER_BLOCK"))
        for n in never:
            ipaddress.ip_network(n, strict=False)
        principal = env.get("KIT_PRINCIPAL", "sa-vigil-responder")
        if not re.fullmatch(r"sa-[a-z0-9-]{1,60}", principal):
            raise SystemExit("KIT_PRINCIPAL must be the responder's sa-... account")
        return cls(
            public_url=env["PUBLIC_URL"].rstrip("/"),
            stepca_url=env["STEPCA_URL"].rstrip("/"),
            fingerprint=fp,
            provisioner=env.get("PROVISIONER", "hosts-enroll"),
            allow=_nets(env["ENROLL_ALLOW"]),
            deny=_nets(env.get("ENROLL_DENY")),
            dns_domains=[d.lower().strip(".") for d in _csv(env.get("DNS_DOMAINS"))],
            enroll_args=env.get("ENROLL_HOST_ARGS", "--admin-user root"),
            kit_principal=principal,
            kit_never_block=never,
            inventory_token=env["INVENTORY_TOKEN"],
            stepca_internal_url=(env.get("STEPCA_INTERNAL_URL") or env["STEPCA_URL"]).rstrip("/"),
            files_dir=env.get("FILES_DIR", "/app/files"),
        )

    def source_ok(self, ip: str) -> bool:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in self.allow) and not any(a in n for n in self.deny)


class Files:
    """What the host scripts download: built-in scripts, the responder kit, the step CLI."""

    def __init__(self, settings: Settings):
        self.settings = settings
        pkg = resources.files("vigil_host_enroller") / "files"
        self.builtin = {p.name: p.read_bytes() for p in pkg.iterdir() if p.is_file()}
        base = Path(settings.files_dir)
        self.step = (base / "step").read_bytes() if (base / "step").exists() else b""
        self.kit = self._tar(base / "kit") if (base / "kit").is_dir() else b""
        self.kit_version = (
            (base / "kit" / "VERSION").read_text().strip()
            if (base / "kit" / "VERSION").exists()
            else ""
        )

    @staticmethod
    def _tar(directory: Path) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
            for p in sorted(directory.iterdir()):
                info = tar.gettarinfo(str(p), arcname=f"kit/{p.name}")
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                with p.open("rb") as fh:
                    tar.addfile(info, fh)
        return buf.getvalue()

    def get(self, name: str) -> bytes | None:
        if name == "step":
            return self.step or None
        if name == "kit.tar.gz":
            return self.kit or None
        if name in (
            "enroll-host.sh",
            "vigil-enroll-report",
            "vigil-enroll-firstboot.service",
            "vigil-enroll-report.service",
            "vigil-enroll-report.timer",
        ):
            return self.builtin.get(name)
        return None

    def sha256(self, name: str) -> str:
        data = self.get(name)
        return hashlib.sha256(data).hexdigest() if data else ""

    def render(self, name: str) -> str:
        s = self.settings
        values = {
            "ENROLLER": s.public_url,
            "CA_URL": s.stepca_url,
            "FINGERPRINT": s.fingerprint,
            "ENROLL_ARGS": s.enroll_args,
            "KIT_PRINCIPAL": s.kit_principal,
            "KIT_NEVER_BLOCK": ",".join(s.kit_never_block),
            "KIT_VERSION": self.kit_version,
            "SHA_STEP": self.sha256("step"),
            "SHA_KIT": self.sha256("kit.tar.gz"),
            "SHA_ENROLL": self.sha256("enroll-host.sh"),
            "SHA_REPORT": self.sha256("vigil-enroll-report"),
            "SHA_FIRSTBOOT": self.sha256("vigil-enroll-firstboot.service"),
            "SHA_REPORT_SERVICE": self.sha256("vigil-enroll-report.service"),
            "SHA_REPORT_TIMER": self.sha256("vigil-enroll-report.timer"),
        }
        text = self.builtin[name].decode()
        for k, v in values.items():
            text = text.replace(f"@@{k}@@", _sh(v))
        return text


class StepCAStatus:
    """Is our key registered as the provisioner? Read from step-ca, root pinned."""

    def __init__(self, settings: Settings, key: SigningKey):
        self.settings, self.key = settings, key
        self.registered: bool | None = None
        self.detail = "not checked yet"
        self.checked_at = 0.0

    async def check(self) -> None:
        s = self.settings
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as raw:  # noqa: S501 - pinned below
                r = await raw.get(f"{s.stepca_internal_url}/root/{s.fingerprint}")
                r.raise_for_status()
            pem = r.json()["ca"]
            der = ssl.PEM_cert_to_DER_cert(pem)
            if hashlib.sha256(der).hexdigest() != s.fingerprint:
                raise RuntimeError("the CA's root does not match STEPCA_FINGERPRINT")
            ctx = ssl.create_default_context(cadata=pem)
            async with httpx.AsyncClient(verify=ctx, timeout=10) as client:
                cursor, found = "", None
                for _ in range(20):
                    r = await client.get(
                        f"{s.stepca_internal_url}/provisioners",
                        params={"cursor": cursor, "limit": 100},
                    )
                    r.raise_for_status()
                    body = r.json()
                    for p in body.get("provisioners", []):
                        if p.get("name") == s.provisioner:
                            found = p
                    cursor = body.get("nextCursor") or ""
                    if not cursor:
                        break
            if not found:
                self.registered, self.detail = (
                    False,
                    f"step-ca has no provisioner {s.provisioner!r}",
                )
            elif (found.get("key") or {}).get("kid") != self.key.kid():
                self.registered = False
                self.detail = f"{s.provisioner!r} in step-ca has another key: register /v1/jwk"
            else:
                self.registered, self.detail = True, "registered"
        except Exception as exc:
            self.registered, self.detail = None, f"cannot read step-ca: {type(exc).__name__}: {exc}"
        self.checked_at = time.time()


class Enroller:
    def __init__(
        self,
        *,
        settings: Settings,
        key: SigningKey,
        proxmox: Proxmox,
        inventory: Inventory,
        files: Files,
        stepca: StepCAStatus | None = None,
        limit: RateLimit | None = None,
        resolver: Any = None,
    ):
        self.s, self.key, self.pve, self.inv, self.files = settings, key, proxmox, inventory, files
        self.stepca = stepca or StepCAStatus(settings, key)
        self.limit = limit or RateLimit(per_address=10, total=120)
        self.resolver = resolver or self._resolve

    @staticmethod
    async def _resolve(name: str) -> set[str]:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                name, None, type=socket.SOCK_STREAM
            )
        except OSError:
            return set()
        return {str(i[4][0]) for i in infos}

    async def principals(self, ip: str, vm: VM) -> list[str]:
        """The source address, and <vm name>.<domain> only if DNS gives that same address."""
        out = [ip]
        label = vm.name.lower()
        if LABEL.match(label):
            for domain in self.s.dns_domains:
                fqdn = f"{label}.{domain}"
                if ip in await self.resolver(fqdn):
                    out.append(fqdn)
        return out

    # --- handlers --------------------------------------------------------------------

    def _source(self, request: Request) -> str:
        return request.client.host if request.client else ""

    async def _verify(
        self, request: Request, event: str
    ) -> tuple[str, VM, dict[str, Any]] | Response:
        ip = self._source(request)
        if not ip or not self.s.source_ok(ip):
            audit(event, source=ip, outcome="refused", reason="source not allowed")
            return PlainTextResponse(f"{ip} may not enroll here\n", status_code=403)
        if not self.limit.allow(ip):
            audit(event, source=ip, outcome="refused", reason="rate limit")
            return PlainTextResponse("too many requests, try again later\n", status_code=429)
        try:
            body = json.loads(await request.body() or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return PlainTextResponse("send a JSON object\n", status_code=400)
        try:
            vm = await self.pve.verify(ip, str(body.get("uuid", "")))
        except NotVerified as exc:
            audit(event, source=ip, outcome="refused", reason=str(exc))
            return PlainTextResponse(f"{exc}\n", status_code=403)
        except ProxmoxError as exc:
            log.error("proxmox: %s", exc)
            audit(event, source=ip, outcome="error", reason="proxmox")
            return PlainTextResponse("the enroller cannot read Proxmox now\n", status_code=503)
        return ip, vm, body

    async def enroll(self, request: Request) -> Response:
        if self.stepca.registered is False:
            return PlainTextResponse(f"{self.stepca.detail}\n", status_code=503)
        got = await self._verify(request, "enroll")
        if isinstance(got, Response):
            return got
        ip, vm, _ = got
        principals = await self.principals(ip, vm)
        token = host_token(
            self.key,
            provisioner=self.s.provisioner,
            ca_url=self.s.stepca_url,
            fingerprint=self.s.fingerprint,
            subject=ip,
            principals=principals,
        )
        self.inv.enrolled(ip, vmid=vm.vmid, node=vm.node, name=vm.name, principals=principals)
        audit(
            "enroll",
            source=ip,
            outcome="token",
            vmid=vm.vmid,
            node=vm.node,
            name=vm.name,
            principals=principals,
        )
        # Line 1 the token, line 2 the principals (bootstrap.sh passes them to enroll-host.sh).
        return PlainTextResponse(f"{token}\n{' '.join(principals)}\n")

    async def report(self, request: Request) -> Response:
        got = await self._verify(request, "report")
        if isinstance(got, Response):
            return got
        ip, vm, body = got
        kit = str(body.get("kit", ""))
        if kit and not KIT_VERSION.match(kit):
            return PlainTextResponse("bad kit version\n", status_code=400)
        self.inv.reported(ip, vmid=vm.vmid, node=vm.node, name=vm.name, kit=kit)
        audit("report", source=ip, outcome="ok", vmid=vm.vmid, name=vm.name, kit=kit)
        return PlainTextResponse("ok\n")

    async def script(self, request: Request) -> Response:
        name = request.path_params["name"]
        if name not in ("bootstrap.sh", "template.sh"):
            return PlainTextResponse("not found\n", status_code=404)
        return PlainTextResponse(self.files.render(name), media_type="text/x-shellscript")

    async def file(self, request: Request) -> Response:
        data = self.files.get(request.path_params["name"])
        if data is None:
            return PlainTextResponse("not found\n", status_code=404)
        return Response(data, media_type="application/octet-stream")

    async def healthz(self, request: Request) -> Response:
        return JSONResponse(
            {
                "ok": True,
                "version": __version__,
                "provisioner": self.s.provisioner,
                "registered": self.stepca.registered,
                "detail": self.stepca.detail,
                "kit": self.files.kit_version,
                "step_cli": bool(self.files.step),
            }
        )

    async def jwk(self, request: Request) -> Response:
        return JSONResponse(self.key.public_jwk())

    async def inventory(self, request: Request) -> Response:
        auth = request.headers.get("authorization", "")
        want = f"Bearer {self.s.inventory_token}"
        if not hmac.compare_digest(auth.encode(), want.encode()):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        hosts = self.inv.responder_hosts()
        return JSONResponse(
            {
                "hosts": [
                    {
                        "address": h.address,
                        "name": h.name,
                        "vmid": h.vmid,
                        "kit": h.kit,
                        "reported_at": h.reported_at,
                    }
                    for h in hosts
                ],
                "stale_seconds": self.inv.stale_seconds,
            }
        )

    def public_app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/healthz", self.healthz),
                Route("/{name:str}", self.script),
                Route("/files/{name:str}", self.file),
                Route("/v1/enroll", self.enroll, methods=["POST"]),
                Route("/v1/report", self.report, methods=["POST"]),
            ]
        )

    def internal_app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/healthz", self.healthz),
                Route("/v1/jwk", self.jwk),
                Route("/v1/inventory", self.inventory),
            ]
        )


class _Server(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self):  # main() handles the signals for both servers
        yield


async def _run(enroller: Enroller, env: Mapping[str, str]) -> None:
    cert, keyfile = env.get("TLS_CERT_FILE", ""), env.get("TLS_KEY_FILE", "")
    pub = uvicorn.Config(
        enroller.public_app(),
        host="0.0.0.0",  # noqa: S104 - a pod: the Service decides who reaches it
        port=int(env.get("PUBLIC_PORT", "8443")),
        ssl_certfile=cert or None,
        ssl_keyfile=keyfile or None,
        proxy_headers=False,
        server_header=False,
        access_log=False,
    )
    internal = uvicorn.Config(
        enroller.internal_app(),
        host="0.0.0.0",  # noqa: S104
        port=int(env.get("INTERNAL_PORT", "8080")),
        proxy_headers=False,
        server_header=False,
        access_log=False,
    )
    servers = [_Server(pub), _Server(internal)]

    def stop() -> None:
        for s in servers:
            s.should_exit = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop)

    async def background() -> None:
        mtime = 0.0
        while not servers[0].should_exit:
            await enroller.stepca.check()
            # cert-manager renews the certificate in place: load it again for new connections.
            if cert and pub.ssl is not None:
                with contextlib.suppress(OSError):
                    m = os.stat(cert).st_mtime
                    if mtime and m != mtime:
                        pub.ssl.load_cert_chain(cert, keyfile)
                        log.info("loaded the renewed TLS certificate")
                    mtime = m
            await asyncio.sleep(300)

    task = asyncio.create_task(background())
    try:
        await asyncio.gather(*(s.serve() for s in servers))
    finally:
        task.cancel()


def main(environ: Mapping[str, str] | None = None) -> None:
    env = os.environ if environ is None else environ
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    settings = Settings.from_env(env)
    if not env.get("ENROLL_KEY_SEED"):
        raise SystemExit("ENROLL_KEY_SEED is required")
    for name in ("PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET"):
        if not env.get(name):
            raise SystemExit(f"{name} is required")
    ca_file = env.get("PVE_CA_FILE", "")
    verify: Any = ssl.create_default_context(cafile=ca_file) if ca_file else True
    enroller = Enroller(
        settings=settings,
        key=SigningKey.from_seed(env["ENROLL_KEY_SEED"]),
        proxmox=Proxmox(
            urls=_csv(env["PVE_URL"]),
            token_id=env["PVE_TOKEN_ID"],
            token_secret=env["PVE_TOKEN_SECRET"],
            tag=env.get("ENROLL_TAG", "step-enroll"),
            verify=verify,
            source_address=env.get("PVE_SOURCE_ADDRESS") or None,
        ),
        inventory=Inventory(
            env.get("STATE_FILE", "/var/lib/host-enroller/inventory.json"),
            stale_seconds=float(env.get("STALE_DAYS", "3")) * 86400,
        ),
        files=Files(settings),
    )
    log.info("provisioner %s, key %s", settings.provisioner, enroller.key.kid())
    asyncio.run(_run(enroller, env))
