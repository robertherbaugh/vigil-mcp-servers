"""Vigil effect classes and the MCP tool annotations that go with them.

Vigil decides by a person's classification of each outside tool, never by what a
server says about itself. These annotations are hints for the person doing that
classification (and for other MCP clients). See docs/DESIGN.md.
"""

from __future__ import annotations

from enum import StrEnum

from mcp.types import ToolAnnotations

# A namespaced _meta key, so the declared class shows up in tools/list.
EFFECT_META_KEY = "io.github.robertherbaugh.vigil-mcp-servers/effect-class"


class EffectClass(StrEnum):
    """The effect classes Vigil stores per outside tool (core/response/ceiling.py)."""

    READ = "read"
    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"


def tool_annotations(
    effect: EffectClass, *, title: str | None = None, idempotent: bool | None = None
) -> ToolAnnotations:
    """MCP annotations that agree with ``effect``."""
    if effect is EffectClass.READ:
        return ToolAnnotations(title=title, read_only_hint=True, open_world_hint=True)
    return ToolAnnotations(
        title=title,
        read_only_hint=False,
        destructive_hint=effect is EffectClass.IRREVERSIBLE,
        idempotent_hint=idempotent,
        open_world_hint=True,
    )


def tool_meta(effect: EffectClass) -> dict[str, str]:
    """The ``_meta`` entry that declares ``effect`` in tools/list."""
    return {EFFECT_META_KEY: effect.value}
