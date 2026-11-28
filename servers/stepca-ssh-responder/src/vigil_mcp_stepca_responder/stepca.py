"""Short-lived SSH user certificates from step-ca, for one service account.

1. Bootstrap: fetch the CA root once and check its SHA-256 against the pinned
   fingerprint (as ``step ca bootstrap --fingerprint`` does). Every later call
   verifies TLS against that root.
2. Token: the service account logs in to its Authentik provider with
   ``client_credentials`` (username and app password). The ID token is the
   one-time token for step-ca's OIDC provisioner.
3. Sign: a fresh ed25519 key per certificate. ``POST /ssh/sign`` with the public
   key in SSH wire format (base64). The provisioner's template decides the
   principals, the force-command and the lifetime cap, not this client.

The certificate is kept until shortly before it expires, never written to disk.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import ssl
import struct
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any

import asyncssh
import httpx


class CAError(RuntimeError):
    """step-ca or Authentik refused, or answered something unexpected. Never holds a secret."""


def _wire_type(blob: bytes) -> str:
    (n,) = struct.unpack(">I", blob[:4])
    return blob[4 : 4 + n].decode()


def cert_validity(wire: bytes) -> tuple[int, int]:
    """(valid_after, valid_before) of an ssh-ed25519-cert-v01 certificate in wire format.

    Layout (OpenSSH PROTOCOL.certkeys): string type, string nonce, string pk,
    uint64 serial, uint32 type, string key id, string principals, uint64
    valid_after, uint64 valid_before. asyncssh keeps these private, so read them.
    """
    pos = 0

    def string() -> bytes:
        nonlocal pos
        (n,) = struct.unpack(">I", wire[pos : pos + 4])
        pos += 4 + n
        return wire[pos - n : pos]

    if string() != b"ssh-ed25519-cert-v01@openssh.com":
        raise CAError("step-ca returned a certificate that is not ed25519")
    string()  # nonce
    string()  # public key
    pos += 8 + 4  # serial, type
    string()  # key id
    string()  # principals
    after, before = struct.unpack(">QQ", wire[pos : pos + 16])
    return after, before


def openssh_line(wire_b64: str) -> str:
    """'<type> <base64>' from base64 SSH wire bytes, for asyncssh's importers."""
    return f"{_wire_type(base64.b64decode(wire_b64))} {wire_b64}"


@dataclass
class Credential:
    key: asyncssh.SSHKey
    cert: asyncssh.SSHCertificate
    expires_at: float  # Unix time
    principals: tuple[str, ...]


class StepCA:
    def __init__(
        self,
        *,
        url: str,
        fingerprint: str,
        token_url: str,
        client_id: str,
        username: str,
        password: str,
        lifetime: str = "5m",
        http: httpx.Client | None = None,
        clock=time.time,
    ):
        self.url = url.rstrip("/")
        self.fingerprint = fingerprint.lower()
        self.token_url = token_url
        self.client_id = client_id
        self.username = username
        self._password = password
        self.lifetime = lifetime
        self._http = http
        self._verified: httpx.Client | None = None
        self.clock = clock
        self._cred: Credential | None = None
        self._lock = threading.Lock()

    # --- TLS ------------------------------------------------------------------------

    def client(self) -> httpx.Client:
        if self._http is not None:  # tests
            return self._http
        if self._verified is None:
            bare = httpx.Client(verify=False, timeout=15.0)  # noqa: S501 - root is checked below
            r = bare.get(f"{self.url}/root/{self.fingerprint}")
            if r.status_code != 200:
                raise CAError(f"step-ca root: HTTP {r.status_code}")
            pem = r.json()["ca"]
            der = ssl.PEM_cert_to_DER_cert(pem)
            if hashlib.sha256(der).hexdigest() != self.fingerprint:
                raise CAError("step-ca root does not match the pinned fingerprint")
            ca_file = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)  # noqa: SIM115
            ca_file.write(pem)
            ca_file.close()
            self._verified = httpx.Client(
                verify=ssl.create_default_context(cafile=ca_file.name), timeout=15.0
            )
        return self._verified

    # --- the host CA, for host key checks ------------------------------------------

    def host_ca_keys(self) -> list[asyncssh.SSHKey]:
        r = self.client().get(f"{self.url}/ssh/roots")
        if r.status_code != 200:
            raise CAError(f"step-ca /ssh/roots: HTTP {r.status_code}")
        keys = r.json().get("hostKey") or []
        if not keys:
            raise CAError("step-ca has no SSH host CA key")
        return [asyncssh.import_public_key(openssh_line(k)) for k in keys]

    # --- the user certificate ------------------------------------------------------

    def _token(self) -> str:
        form = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "username": self.username,
            "password": self._password,
            "scope": "openid profile",
        }
        http = self._http or httpx.Client(timeout=15.0)  # Authentik: a public certificate
        try:
            r = http.post(self.token_url, data=form)
        except httpx.HTTPError as exc:
            raise CAError(f"Authentik token: {type(exc).__name__}") from exc
        if r.status_code != 200:
            raise CAError(f"Authentik token: HTTP {r.status_code}")
        token = r.json().get("id_token")
        if not token:
            raise CAError("Authentik answered without an id_token")
        return token

    def _sign(self) -> Credential:
        key = asyncssh.generate_private_key("ssh-ed25519")
        body: dict[str, Any] = {
            "publicKey": base64.b64encode(key.public_data).decode(),
            "ott": self._token(),
            "certType": "user",
            "keyID": self.username,
            "validBefore": self.lifetime,
        }
        r = self.client().post(
            f"{self.url}/ssh/sign",
            content=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )
        if r.status_code not in (200, 201):
            # step-ca's message, without the token (its log may hold it; ours does not).
            msg = ""
            with contextlib.suppress(ValueError):
                msg = str(r.json().get("message", ""))[:200]
            raise CAError(f"step-ca /ssh/sign: HTTP {r.status_code} {msg}".strip())
        wire_b64 = r.json()["crt"]
        cert = asyncssh.import_certificate(openssh_line(wire_b64))
        _, before = cert_validity(base64.b64decode(wire_b64))
        return Credential(
            key=key, cert=cert, expires_at=float(before), principals=tuple(cert.principals)
        )

    def credential(self, margin: float = 60.0) -> Credential:
        """A key and certificate valid for at least ``margin`` more seconds."""
        with self._lock:
            if self._cred is None or self._cred.expires_at - self.clock() < margin:
                self._cred = self._sign()
            return self._cred
