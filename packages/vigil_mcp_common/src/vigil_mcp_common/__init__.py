"""Shared guard rails for vigil-mcp-servers. See docs/DESIGN.md."""

from .allowlist import TargetNotAllowed, TargetPolicy
from .app import HttpSettings, build_app, serve
from .audit import AuditLog, redact
from .auth import BearerAuthMiddleware, TokenConfigError, TokenSet
from .effects import EFFECT_META_KEY, EffectClass, tool_annotations, tool_meta
from .expiring import ExpiringAction, ExpiringActions, TtlBounds, TtlOutOfRange
from .guard import Guard
from .ratelimit import Limit, RateLimited, RateLimiter

__all__ = [
    "EFFECT_META_KEY",
    "AuditLog",
    "BearerAuthMiddleware",
    "EffectClass",
    "ExpiringAction",
    "ExpiringActions",
    "Guard",
    "HttpSettings",
    "Limit",
    "RateLimited",
    "RateLimiter",
    "TargetNotAllowed",
    "TargetPolicy",
    "TokenConfigError",
    "TokenSet",
    "TtlBounds",
    "TtlOutOfRange",
    "build_app",
    "redact",
    "serve",
    "tool_annotations",
    "tool_meta",
]
