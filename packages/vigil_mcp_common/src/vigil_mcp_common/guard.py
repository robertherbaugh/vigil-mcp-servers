"""One place where a tool call meets every limit: caller, target, rate, audit.

Use it around the body of every tool::

    with guard.call(ctx, "block_ip", EffectClass.REVERSIBLE, target=ip) as target:
        ...  # act on the normalized target

A refusal becomes a ``ToolError`` with a short reason, which the model sees as a
failed tool call. Every outcome (ok, refused, error) writes one audit line.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError

from .allowlist import TargetNotAllowed, TargetPolicy
from .audit import AuditLog
from .auth import TokenSet
from .effects import EffectClass
from .expiring import TtlOutOfRange
from .ratelimit import RateLimited, RateLimiter

_REFUSALS = (TargetNotAllowed, RateLimited, TtlOutOfRange)


class Guard:
    def __init__(
        self, *, tokens: TokenSet, policy: TargetPolicy, limiter: RateLimiter, audit: AuditLog
    ):
        self.tokens = tokens
        self.policy = policy
        self.limiter = limiter
        self.audit = audit

    def principal(self, ctx: Context | None) -> str | None:
        headers = ctx.headers if ctx is not None else None
        if not headers:
            return None
        return self.tokens.principal_for_header(headers.get("authorization"))

    @contextmanager
    def call(
        self,
        ctx: Context | None,
        tool: str,
        effect: EffectClass,
        *,
        target: str | None = None,
        **audit_fields: Any,
    ) -> Iterator[str | None]:
        principal = self.principal(ctx)
        record = {"tool": tool, "principal": principal, "effect": effect.value, **audit_fields}
        try:
            if principal is None:
                # The HTTP middleware already refuses unauthenticated requests; this
                # catches a transport that carries no headers (stdio, tests).
                raise PermissionError("caller is not identified")
            normalized = self.policy.check(target) if target is not None else None
            record["target"] = normalized
            if effect is not EffectClass.READ:
                self.limiter.acquire(tool)
        except (*_REFUSALS, PermissionError, ValueError) as exc:
            record.setdefault("target", target)
            self.audit.record(outcome="refused", detail=str(exc), **record)
            raise ToolError(str(exc)) from exc
        try:
            yield normalized
        except (ToolError, *_REFUSALS) as exc:
            self.audit.record(outcome="refused", detail=str(exc), **record)
            if isinstance(exc, ToolError):
                raise
            raise ToolError(str(exc)) from exc
        except Exception as exc:
            self.audit.record(outcome="error", detail=type(exc).__name__, **record)
            raise
        self.audit.record(outcome="ok", **record)
