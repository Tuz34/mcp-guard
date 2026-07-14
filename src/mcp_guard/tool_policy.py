from __future__ import annotations

from typing import Any

from .matching import name_matches, text_matches
from .models import Reason


def tool_name_is_allowed(name: str, rules: dict[str, Any]) -> bool:
    allowed = rules.get("allow_names", [])
    return bool(allowed) and any(name_matches(name, pattern) for pattern in allowed)


def tool_name_reasons(name: str, rules: dict[str, Any]) -> list[Reason]:
    reasons: list[Reason] = []

    for pattern in rules.get("deny_names", []):
        if name_matches(name, pattern):
            reasons.append(
                Reason(
                    "mcp_tools.deny_names",
                    "deny",
                    pattern,
                    "MCP tool name is blocked by policy.",
                )
            )

    allowed = rules.get("allow_names", [])
    if allowed and not tool_name_is_allowed(name, rules):
        reasons.append(
            Reason(
                "mcp_tools.allow_names",
                "deny",
                name,
                "MCP tool name is not on the allow list.",
            )
        )

    for pattern in rules.get("warn_if_name_contains", []):
        if text_matches(name, pattern):
            reasons.append(
                Reason(
                    "mcp_tools.warn_if_name_contains",
                    "warn",
                    pattern,
                    "Tool name indicates a powerful capability.",
                )
            )

    return reasons
