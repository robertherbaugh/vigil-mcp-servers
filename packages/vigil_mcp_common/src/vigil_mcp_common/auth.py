"""Static bearer tokens for streamable HTTP.

Vigil's remote MCP sources send fixed headers (``Authorization: "Bearer {{token}}"``),
so each caller gets its own named token. The server keeps only SHA-256 digests in
memory and compares digests in constant time, so a token's length doesn't leak.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path

from starlette.types import ASGIApp, Receive, Scope, Send

MIN_TOKEN_LENGTH = 32


class TokenConfigError(ValueError):
    """The token configuration is missing or unsafe."""


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


class TokenSet:
    """Named callers and their token digests."""

    def __init__(self, tokens: Mapping[str, str]):
        if not tokens:
            raise TokenConfigError("no bearer tokens configured")
        digests: dict[str, bytes] = {}
        for principal, token in tokens.items():
            if not principal or not principal.replace("-", "").replace("_", "").isalnum():
                raise TokenConfigError(f"invalid principal name {principal!r}")
            if len(token) < MIN_TOKEN_LENGTH:
                raise TokenConfigError(
                    f"token for {principal!r} is shorter than {MIN_TOKEN_LENGTH} characters"
                )
            digests[principal] = _digest(token)
        self._digests = digests

    @property
    def principals(self) -> list[str]:
        return sorted(self._digests)

    def principal_for(self, token: str) -> str | None:
        """The caller that ``token`` belongs to, or None. Checks every entry."""
        presented = _digest(token)
        found: str | None = None
        for principal, digest in self._digests.items():
            if hmac.compare_digest(presented, digest):
                found = principal
        return found

    def principal_for_header(self, value: str | None) -> str | None:
        """The caller for an ``Authorization`` header value, or None."""
        if not value:
            return None
        scheme, _, token = value.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return None
        return self.principal_for(token.strip())

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> TokenSet:
        """Load tokens from the environment.

        ``MCP_TOKENS_FILE`` names a JSON file ``{"<principal>": "<token>", ...}``
        (a mounted Secret). ``MCP_TOKEN`` is a single token for the principal
        ``MCP_TOKEN_PRINCIPAL`` (default ``vigil``). The file wins if both are set.
        """
        env = os.environ if environ is None else environ
        path = env.get("MCP_TOKENS_FILE")
        if path:
            try:
                loaded = json.loads(Path(path).read_text())
            except (OSError, json.JSONDecodeError) as exc:
                reason = type(exc).__name__
                raise TokenConfigError(f"cannot read MCP_TOKENS_FILE: {reason}") from exc
            if not isinstance(loaded, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in loaded.items()
            ):
                raise TokenConfigError("MCP_TOKENS_FILE must be a JSON object of strings")
            return cls(loaded)
        token = env.get("MCP_TOKEN")
        if token:
            return cls({env.get("MCP_TOKEN_PRINCIPAL", "vigil"): token})
        raise TokenConfigError("set MCP_TOKENS_FILE or MCP_TOKEN")


class BearerAuthMiddleware:
    """Refuse HTTP requests without a known bearer token, except ``public_paths``."""

    def __init__(self, app: ASGIApp, tokens: TokenSet, public_paths: Iterable[str] = ("/healthz",)):
        self.app = app
        self.tokens = tokens
        self.public_paths = frozenset(public_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in self.public_paths:
            await self.app(scope, receive, send)
            return
        header = None
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                header = value.decode("latin-1")
                break
        principal = self.tokens.principal_for_header(header)
        if principal is None:
            await _unauthorized(send)
            return
        scope.setdefault("state", {})["principal"] = principal
        await self.app(scope, receive, send)


async def _unauthorized(send: Send) -> None:
    body = b'{"error":"unauthorized"}'
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", b'Bearer realm="mcp"'),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
