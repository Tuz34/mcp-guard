from __future__ import annotations

import math
from typing import Any


class InputError(ValueError):
    """Raised when an action or manifest does not match the documented shape."""


def _required_text(data: dict[str, Any], field: str, location: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{location}.{field} must be a non-empty string.")
    return value


def validate_action(action: dict[str, Any]) -> None:
    action_type = _required_text(action, "action_type", "action").lower()
    required_field = {
        "shell": "command",
        "file": "path",
        "filesystem": "path",
        "network": "url_or_domain",
    }.get(action_type)
    if required_field is None:
        supported = "file, filesystem, network, shell"
        raise InputError(f"Unsupported action.action_type '{action_type}'. Supported: {supported}.")
    if required_field == "url_or_domain":
        for field in ("url", "domain"):
            if field in action and not isinstance(action[field], str):
                raise InputError(f"action.{field} must be a string when provided.")
        network_fields = [
            field
            for field in ("url", "domain")
            if isinstance(action.get(field), str) and action[field].strip()
        ]
        if len(network_fields) != 1:
            raise InputError(
                "Network actions must provide exactly one of action.url or action.domain."
            )
    else:
        _required_text(action, required_field, "action")
    for optional in ("actor", "tool"):
        if optional in action and not isinstance(action[optional], str):
            raise InputError(f"action.{optional} must be a string when provided.")
    if "metadata" in action and not isinstance(action["metadata"], dict):
        raise InputError("action.metadata must be an object when provided.")
    if "budget" in action:
        budget = action["budget"]
        allowed = {"confirmation", "impact", "payload_bytes", "target_id"}
        if not isinstance(budget, dict) or set(budget) - allowed:
            raise InputError("action.budget must contain only supported budget fields.")
        if budget.get("confirmation") not in {"confirmed", "estimated", "unknown"}:
            raise InputError("action.budget.confirmation is invalid.")
        impact = budget.get("impact")
        if impact is not None and (
            isinstance(impact, bool)
            or not isinstance(impact, (int, float))
            or not math.isfinite(impact)
            or not 0 <= impact <= 1_000_000_000_000
        ):
            raise InputError("action.budget.impact must be a finite non-negative number.")
        payload_bytes = budget.get("payload_bytes")
        if payload_bytes is not None and (
            isinstance(payload_bytes, bool)
            or not isinstance(payload_bytes, int)
            or not 0 <= payload_bytes <= 1_000_000_000_000
        ):
            raise InputError("action.budget.payload_bytes must be a non-negative integer.")
        target_id = budget.get("target_id")
        if target_id is not None and (
            not isinstance(target_id, str) or not target_id.strip() or len(target_id) > 256
        ):
            raise InputError("action.budget.target_id must be a non-empty string up to 256 chars.")


def manifest_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    tools: Any = None
    if "tools" in manifest:
        tools = manifest["tools"]
    elif isinstance(manifest.get("server"), dict) and "tools" in manifest["server"]:
        tools = manifest["server"]["tools"]
    if tools is not None:
        if not isinstance(tools, list) or not tools:
            raise InputError("Manifest tools must be a non-empty array.")
        for index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                raise InputError(f"tools[{index}] must be an object.")
            name = _required_text(tool, "name", f"tools[{index}]")
            description = tool.get("description", "")
            if not isinstance(description, str):
                raise InputError(f"tools[{index}].description must be a string.")
            schema = tool.get("inputSchema", {})
            if not isinstance(schema, dict):
                raise InputError(f"tools[{index}].inputSchema must be an object.")
            entries.append({"name": name, "description": description, "inputSchema": schema})
        return entries

    servers = manifest.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        raise InputError("Expected tools, server.tools, or a non-empty mcpServers mapping.")
    for name, server in servers.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(server, dict):
            raise InputError("Each mcpServers entry must have a name and object value.")
        command = _required_text(server, "command", f"mcpServers.{name}")
        args = server.get("args", [])
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise InputError(f"mcpServers.{name}.args must be a list of strings.")
        description = server.get("description", "")
        if not isinstance(description, str):
            raise InputError(f"mcpServers.{name}.description must be a string.")
        entries.append(
            {
                "name": name,
                "description": description,
                "command": " ".join([command, *args]).strip(),
                "inputSchema": {},
            }
        )
    return entries
