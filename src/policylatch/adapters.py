from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Literal, cast

from .gateway import evaluate_mcp_request
from .policy import policy_provenance
from .receipts import attach_receipt, gateway_request_projection
from .validation import InputError

RuntimeName = Literal["claude-code", "codex"]
RUNTIMES: tuple[RuntimeName, ...] = ("claude-code", "codex")
_COMMON_TOOL_FIELDS = {"command", "path", "file_path", "url", "domain"}
_BASH_METADATA_FIELDS = {"description", "timeout", "run_in_background"}


def _runtime(value: str) -> RuntimeName:
    if value not in RUNTIMES:
        raise InputError(f"Unsupported adapter runtime '{value}'.")
    return cast(RuntimeName, value)


def normalize_hook_event(runtime: str, event: dict[str, Any]) -> dict[str, Any]:
    selected = _runtime(runtime)
    if event.get("hook_event_name") != "PreToolUse":
        raise InputError(f"{selected} adapter only accepts PreToolUse hook events.")
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise InputError(f"{selected} PreToolUse tool_name must be a non-empty string.")
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        raise InputError(f"{selected} PreToolUse tool_input must be an object.")

    arguments: dict[str, Any] = {}
    for field in ("command", "path", "url", "domain"):
        if field in tool_input:
            arguments[field] = tool_input[field]
    if "file_path" in tool_input:
        if "path" in arguments:
            raise InputError("Hook tool_input cannot contain both path and file_path.")
        arguments["path"] = tool_input["file_path"]

    known = set(_COMMON_TOOL_FIELDS)
    if tool_name == "Bash":
        known.update(_BASH_METADATA_FIELDS)
    if set(tool_input) - known:
        # Preserve only the fact that an unmapped field exists. Values such as
        # file content, prompts, credentials, or runtime metadata are never copied.
        arguments["__unclassified__"] = True

    document = {
        "jsonrpc": "2.0",
        "id": "policylatch-adapter",
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    return document


def adapter_decision_document(
    runtime: str,
    event: dict[str, Any],
    policy: dict[str, Any],
    policy_label: str,
) -> dict[str, Any]:
    selected = _runtime(runtime)
    request = normalize_hook_event(selected, event)
    result = evaluate_mcp_request(request, policy)
    document = {
        "schema_version": 1,
        "kind": "runtime_adapter_decision",
        "source": f"{selected}:PreToolUse",
        "policy": policy_label,
        "policy_provenance": policy_provenance(policy),
        "adapter": {
            "runtime": selected,
            "event": "PreToolUse",
            "mode": "blocking" if selected == "claude-code" else "advisory",
            "forwarded": False,
        },
        **result.to_entry(),
    }
    return attach_receipt(document, policy, gateway_request_projection(request))


def _reason_summary(document: dict[str, Any]) -> str:
    rules = [reason["rule"] for reason in document.get("reasons", [])]
    detail = ", ".join(rules[:4]) if rules else "resolved default policy"
    return f"PolicyLatch {document['decision'].upper()}: {detail}."


def hook_response(runtime: str, document: dict[str, Any]) -> dict[str, Any]:
    selected = _runtime(runtime)
    if selected == "claude-code":
        permission = {"allow": "allow", "warn": "ask", "deny": "deny"}[document["decision"]]
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission,
                "permissionDecisionReason": _reason_summary(document),
            }
        }
    return {
        "systemMessage": (
            f"{_reason_summary(document)} Current Codex command hooks expose this "
            "PreToolUse result as advisory context; they are not a PolicyLatch blocking boundary."
        )
    }


def _selector_args(*, policy: str | None, profile: str | None) -> list[str]:
    if bool(policy) == bool(profile):
        raise InputError("Adapter config requires exactly one policy or profile.")
    return ["--policy", str(policy)] if policy else ["--profile", str(profile)]


def adapter_config_document(
    runtime: str,
    *,
    policy: str | None = None,
    profile: str | None = None,
    platform: str | None = None,
) -> dict[str, Any]:
    selected = _runtime(runtime)
    arguments = [
        "adapter-hook",
        "--runtime",
        selected,
        *_selector_args(policy=policy, profile=profile),
    ]
    if platform not in {None, "posix", "windows"}:
        raise InputError("Adapter platform must be posix or windows.")
    if selected == "claude-code":
        command_parts = ["policylatch", *arguments]
        target_platform = platform or ("windows" if os.name == "nt" else "posix")
        handler: dict[str, Any] = {
            "type": "command",
            "command": (
                subprocess.list2cmdline(command_parts)
                if target_platform == "windows"
                else shlex.join(command_parts)
            ),
            "timeout": 30,
        }
        matcher = "*"
    else:
        command_parts = ["policylatch", *arguments]
        handler = {
            "type": "command",
            "command": shlex.join(command_parts),
            "commandWindows": subprocess.list2cmdline(command_parts),
            "timeout": 30,
            "statusMessage": "PolicyLatch pre-flight advisory",
        }
        matcher = ".*"
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": matcher,
                    "hooks": [handler],
                }
            ]
        }
    }


def validate_adapter_config(runtime: str, config: dict[str, Any]) -> dict[str, Any]:
    selected = _runtime(runtime)
    hooks = config.get("hooks")
    if not isinstance(hooks, dict) or set(hooks) != {"PreToolUse"}:
        raise InputError("Adapter config must contain only hooks.PreToolUse.")
    groups = hooks["PreToolUse"]
    if not isinstance(groups, list) or len(groups) != 1 or not isinstance(groups[0], dict):
        raise InputError("Adapter config requires exactly one PreToolUse matcher group.")
    handlers = groups[0].get("hooks")
    if not isinstance(handlers, list) or len(handlers) != 1 or not isinstance(handlers[0], dict):
        raise InputError("Adapter config requires exactly one command hook handler.")
    handler = handlers[0]
    if handler.get("type") != "command" or handler.get("async") is True:
        raise InputError("Adapter handler must be a synchronous command hook.")
    allowed_handler_fields = (
        {"type", "command", "timeout"}
        if selected == "claude-code"
        else {"type", "command", "commandWindows", "timeout", "statusMessage"}
    )
    if set(handler) - allowed_handler_fields:
        raise InputError("Adapter handler contains unsupported fields.")
    serialized = str(handler)
    if "http://" in serialized or "https://" in serialized:
        raise InputError("Adapter config cannot contain a remote hook URL.")
    required = ("policylatch", "adapter-hook", selected)
    if any(token not in serialized for token in required):
        raise InputError(
            "Adapter command does not invoke the selected PolicyLatch runtime adapter."
        )
    return {
        "schema_version": 1,
        "kind": "adapter_doctor",
        "status": "ok",
        "runtime": selected,
        "event": "PreToolUse",
        "mode": "blocking" if selected == "claude-code" else "advisory",
        "files_modified": False,
        "network_access": False,
    }


def config_target(runtime: str) -> str:
    return ".claude/settings.json" if _runtime(runtime) == "claude-code" else ".codex/hooks.json"


def safe_policy_label(path: str) -> str:
    return Path(path).name
