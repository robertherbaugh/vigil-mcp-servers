"""Run one vigil-respond request on a host, with the step-ca certificate.

The host key must carry a certificate from the step-ca host CA: no
trust-on-first-use, no known_hosts file. The request is the SSH command
string; the host's forced command (vigil-respond) reads it from
SSH_ORIGINAL_COMMAND and checks it again.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import asyncssh

from .stepca import Credential


class HostUnreachable(Exception):
    """No TCP connection to the host (down, no route, or connect timeout). The host never
    saw the request. An SSH-level failure (host key, login, command) is not this."""


@dataclass
class Result:
    exit_status: int | None
    stdout: str
    stderr: str


class SSHRunner:
    def __init__(self, *, user: str = "vigil-responder", port: int = 22, timeout: float = 20.0):
        self.user = user
        self.port = port
        self.timeout = timeout

    async def _run(
        self, host: str, request: str, cred: Credential, host_ca: list[asyncssh.SSHKey]
    ) -> Result:
        try:
            conn = await asyncssh.connect(
                host,
                port=self.port,
                username=self.user,
                client_keys=[(cred.key, cred.cert)],
                known_hosts=([], host_ca, []),  # trust only host certs from the step-ca host CA
                agent_path=None,
                agent_forwarding=False,
                x11_forwarding=False,
                config=[],
                connect_timeout=self.timeout,
            )
        except OSError as exc:  # asyncssh's own errors are not OSError
            raise HostUnreachable(f"{type(exc).__name__}: {exc}") from exc
        async with conn:
            r = await asyncio.wait_for(conn.run(request, check=False), self.timeout)
            return Result(r.exit_status, str(r.stdout or "")[:20000], str(r.stderr or "")[:2000])

    def run(
        self, host: str, request: str, cred: Credential, host_ca: list[asyncssh.SSHKey]
    ) -> Result:
        return asyncio.run(self._run(host, request, cred, host_ca))
