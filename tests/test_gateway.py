import json
from pathlib import Path

import pytest

from mcp_guard.gateway import (
    MAX_REQUEST_ID_CHARS,
    MAX_TOOL_NAME_CHARS,
    evaluate_mcp_request,
    parse_mcp_tool_call,
)
from mcp_guard.policy import load_policy
from mcp_guard.validation import InputError

ROOT = Path(__file__).parents[1]
POLICY = load_policy(ROOT / "examples/policies/gateway-strict.yaml")


def request(name, arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": "synthetic-request",
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def test_gateway_denies_dangerous_shell_argument_without_forwarding():
    result = evaluate_mcp_request(
        request("run_command", {"command": "Remove-Item -Recurse C:\\synthetic"}),
        POLICY,
    )
    payload = result.to_dict(source="synthetic.json")

    assert result.evaluation.decision == "deny"
    assert any(reason.rule == "shell.deny_patterns" for reason in result.evaluation.reasons)
    assert payload["gateway"] == {"mode": "dry-run", "forwarded": False}
    assert payload["capabilities"] == ["shell"]
    assert "arguments" not in json.dumps(payload)


def test_gateway_allows_allowlisted_safe_file_call():
    result = evaluate_mcp_request(request("read_file", {"path": "docs/README.md"}), POLICY)

    assert result.evaluation.decision == "allow"
    assert result.capabilities == ("file",)


def test_gateway_does_not_copy_raw_argument_values_to_output():
    marker = "SYNTHETIC_PRIVATE_ARGUMENT_VALUE"
    result = evaluate_mcp_request(request("run_command", {"command": f"echo {marker}"}), POLICY)

    assert marker not in json.dumps(result.to_dict(source="synthetic.json"))


def test_gateway_denies_tool_outside_allow_list():
    result = evaluate_mcp_request(request("unknown_tool"), POLICY)

    assert result.evaluation.decision == "deny"
    assert result.evaluation.reasons[0].rule == "mcp_tools.allow_names"


def test_gateway_denies_explicit_name_pattern():
    result = evaluate_mcp_request(request("admin_reset"), POLICY)

    assert result.evaluation.decision == "deny"
    assert any(reason.rule == "mcp_tools.deny_names" for reason in result.evaluation.reasons)


@pytest.mark.parametrize(
    "broken,match",
    [
        ({}, "jsonrpc"),
        ({"jsonrpc": "2.0", "method": "resources/read"}, "tools/call"),
        (
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": ""}},
            "params.name",
        ),
    ],
)
def test_gateway_rejects_unsupported_or_malformed_requests(broken, match):
    with pytest.raises(InputError, match=match):
        parse_mcp_tool_call(broken)


@pytest.mark.parametrize("field,value", [("command", {}), ("path", 3), ("url", [])])
def test_gateway_rejects_malformed_known_capability_arguments(field, value):
    with pytest.raises(InputError, match=field):
        evaluate_mcp_request(request("read_file", {field: value}), POLICY)


@pytest.mark.parametrize(
    "payload,match",
    [
        (request("x" * (MAX_TOOL_NAME_CHARS + 1)), "params.name"),
        (
            {
                **request("read_file"),
                "id": "x" * (MAX_REQUEST_ID_CHARS + 1),
            },
            "request id",
        ),
    ],
)
def test_gateway_bounds_identifiers_copied_to_output(payload, match):
    with pytest.raises(InputError, match=match):
        parse_mcp_tool_call(payload)
