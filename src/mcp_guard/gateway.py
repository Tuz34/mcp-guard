from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .evaluator import evaluate_action
from .models import Evaluation, Reason, decision_for, risk_for
from .policy import default_decision
from .tool_policy import tool_name_is_allowed, tool_name_reasons
from .validation import InputError

MAX_GATEWAY_REQUEST_BYTES = 1024 * 1024
MAX_TOOL_NAME_CHARS = 256
MAX_REQUEST_ID_CHARS = 256


@dataclass(frozen=True)
class McpToolCall:
    request_id: str | int | None
    name: str
    arguments: dict[str, Any]
    task_augmented: bool = False


@dataclass(frozen=True)
class GatewayResult:
    call: McpToolCall
    evaluation: Evaluation
    capabilities: tuple[str, ...]

    def to_entry(self) -> dict[str, Any]:
        return {
            "request": {
                "jsonrpc": "2.0",
                "id": self.call.request_id,
                "method": "tools/call",
                "tool": self.call.name,
                "task_augmented": self.call.task_augmented,
            },
            "capabilities": list(self.capabilities),
            **self.evaluation.to_dict(),
        }

    def to_dict(self, *, source: str) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "mcp_gateway_decision",
            "source": source,
            "gateway": {"mode": "dry-run", "forwarded": False},
            **self.to_entry(),
        }


def parse_mcp_tool_call(request: dict[str, Any]) -> McpToolCall:
    if request.get("jsonrpc") != "2.0":
        raise InputError("MCP request jsonrpc must be '2.0'.")
    if request.get("method") != "tools/call":
        raise InputError("Gateway dry-run only supports MCP method 'tools/call'.")

    request_id = request.get("id")
    if isinstance(request_id, bool) or (
        request_id is not None and not isinstance(request_id, (str, int))
    ):
        raise InputError("MCP request id must be a string, integer, or null.")
    if isinstance(request_id, str) and len(request_id) > MAX_REQUEST_ID_CHARS:
        raise InputError(f"MCP request id cannot exceed {MAX_REQUEST_ID_CHARS} characters.")

    params = request.get("params")
    if not isinstance(params, dict):
        raise InputError("MCP tools/call params must be an object.")
    name = params.get("name")
    if not isinstance(name, str) or not name.strip():
        raise InputError("MCP tools/call params.name must be a non-empty string.")
    if len(name) > MAX_TOOL_NAME_CHARS:
        raise InputError(
            f"MCP tools/call params.name cannot exceed {MAX_TOOL_NAME_CHARS} characters."
        )
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise InputError("MCP tools/call params.arguments must be an object when provided.")
    task = params.get("task")
    if "task" in params and not isinstance(task, dict):
        raise InputError("MCP tools/call params.task must be an object when provided.")
    return McpToolCall(
        request_id=request_id,
        name=name,
        arguments=arguments,
        task_augmented="task" in params,
    )


def _capability_actions(call: McpToolCall) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    arguments = call.arguments

    command = arguments.get("command")
    if "command" in arguments and (not isinstance(command, str) or not command.strip()):
        raise InputError("MCP tools/call arguments.command must be a non-empty string.")
    if isinstance(command, str):
        actions.append({"action_type": "shell", "command": command, "tool": call.name})

    path = arguments.get("path")
    if "path" in arguments and (not isinstance(path, str) or not path.strip()):
        raise InputError("MCP tools/call arguments.path must be a non-empty string.")
    if isinstance(path, str):
        actions.append({"action_type": "file", "path": path, "tool": call.name})

    url = arguments.get("url")
    domain = arguments.get("domain")
    for field, value in (("url", url), ("domain", domain)):
        if field in arguments and not isinstance(value, str):
            raise InputError(f"MCP tools/call arguments.{field} must be a string.")
    if ("url" in arguments or "domain" in arguments) and not any(
        isinstance(value, str) and value.strip() for value in (url, domain)
    ):
        raise InputError("MCP tools/call network arguments require a non-empty url or domain.")
    if any(isinstance(value, str) and value.strip() for value in (url, domain)):
        action: dict[str, Any] = {"action_type": "network", "tool": call.name}
        if isinstance(url, str):
            action["url"] = url
        if isinstance(domain, str):
            action["domain"] = domain
        actions.append(action)

    return actions


def evaluate_mcp_request(request: dict[str, Any], policy: dict[str, Any]) -> GatewayResult:
    call = parse_mcp_tool_call(request)
    mcp_rules = policy["rules"].get("mcp_tools", {})
    reasons = tool_name_reasons(call.name, mcp_rules)
    actions = _capability_actions(call)
    if call.task_augmented:
        reasons.append(
            Reason(
                "gateway.tasks.unsupported",
                "warn",
                "task",
                "Task-augmented tool calls need an explicit lifecycle policy.",
            )
        )
    if call.arguments and not actions:
        reasons.append(
            Reason(
                "gateway.arguments.unclassified",
                "warn",
                "unclassified",
                "Tool arguments need an explicit capability mapping before enforcement.",
            )
        )

    # Argument projections contribute only their explicit findings. Gateway-level
    # allow-list/default handling is applied once after all projections are checked.
    for action in actions:
        reasons.extend(evaluate_action(action, policy).reasons)

    allowed_by_name = tool_name_is_allowed(call.name, mcp_rules)
    base_decision = "allow" if allowed_by_name else default_decision(policy)
    decision = decision_for(reasons, base_decision)
    evaluation = Evaluation(
        decision=decision,
        risk_level=risk_for(decision),
        reasons=reasons,
        subject=call.name,
    )
    capabilities = tuple(action["action_type"] for action in actions) or ("unclassified",)
    return GatewayResult(call=call, evaluation=evaluation, capabilities=capabilities)
