"""Turn an ``MCPServer`` into the ASGI app every server in this repo serves.

- streamable HTTP at ``/mcp``, stateless with JSON responses, so any replica can
  answer any request and no session state is lost on a restart;
- bearer auth on everything except ``/healthz``;
- DNS-rebinding protection with an explicit list of allowed ``Host`` values.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

import uvicorn
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from .auth import BearerAuthMiddleware, TokenSet

HEALTH_PATH = "/healthz"


@dataclass(frozen=True)
class HttpSettings:
    host: str = "127.0.0.1"
    port: int = 8000
    path: str = "/mcp"
    # Host header values to accept, e.g. "mcp.example.com" or "mcp.example.com:*".
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:*", "localhost:*")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> HttpSettings:
        env = os.environ if environ is None else environ
        hosts = tuple(h.strip() for h in env.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip())
        return cls(
            host=env.get("MCP_HOST", cls.host),
            port=int(env.get("MCP_PORT", cls.port)),
            path=env.get("MCP_PATH", cls.path),
            allowed_hosts=hosts or cls.allowed_hosts,
        )


def build_app(server: MCPServer, tokens: TokenSet, settings: HttpSettings) -> ASGIApp:
    @server.custom_route(HEALTH_PATH, methods=["GET"], include_in_schema=False)
    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    app = server.streamable_http_app(
        streamable_http_path=settings.path,
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(settings.allowed_hosts),
            allowed_origins=[],
        ),
        host=settings.host,
    )
    return BearerAuthMiddleware(app, tokens, public_paths=(HEALTH_PATH,))


def serve(app: ASGIApp, settings: HttpSettings) -> None:
    # Plain HTTP: terminate TLS in front (Vigil accepts only https source URLs).
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
        proxy_headers=False,
        server_header=False,
    )
