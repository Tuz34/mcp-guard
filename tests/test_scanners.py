import json
from pathlib import Path

import pytest

from policylatch.policy import load_policy
from policylatch.scanners import scan_manifest
from policylatch.validation import InputError

ROOT = Path(__file__).parents[1]


def test_scans_safe_and_risky_manifests():
    policy = load_policy(ROOT / "examples/policies/balanced.yaml")
    safe = json.loads((ROOT / "examples/mcp/safe-server.json").read_text())
    risky = json.loads((ROOT / "examples/mcp/risky-server.json").read_text())
    assert scan_manifest(safe, policy)[0].decision == "allow"
    results = scan_manifest(risky, policy)
    assert [item.decision for item in results] == ["warn", "deny"]


def test_scans_common_mcp_servers_config():
    policy = load_policy(ROOT / "examples/policies/balanced.yaml")
    config = json.loads((ROOT / "examples/mcp/client-config.json").read_text())
    results = scan_manifest(config, policy)
    assert [item.decision for item in results] == ["allow", "warn"]
    assert results[1].reasons[0].rule == "shell.warn_patterns"


def test_warns_on_sensitive_input_schema():
    policy = load_policy(ROOT / "examples/policies/balanced.yaml")
    manifest = {
        "tools": [
            {
                "name": "run_task",
                "description": "Run a local task.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                },
            }
        ]
    }
    result = scan_manifest(manifest, policy)[0]
    assert result.decision == "warn"
    assert result.reasons[0].rule == "mcp_tools.warn_if_schema_contains"


def test_tool_allow_list_is_an_explicit_baseline_for_scans():
    policy = load_policy(ROOT / "examples/policies/gateway-strict.yaml")
    manifest = {
        "tools": [
            {"name": "read_file", "description": "Read docs", "inputSchema": {}},
            {"name": "unknown_tool", "description": "Unknown", "inputSchema": {}},
        ]
    }

    results = scan_manifest(manifest, policy)

    assert results[0].decision == "allow"
    assert results[1].decision == "deny"
    assert results[1].reasons[0].rule == "mcp_tools.allow_names"


def test_rejects_unrecognized_manifest_shape():
    policy = load_policy(ROOT / "examples/policies/balanced.yaml")
    with pytest.raises(InputError, match="Expected tools"):
        scan_manifest({"name": "not-a-manifest"}, policy)


def test_rejects_server_without_command():
    policy = load_policy(ROOT / "examples/policies/balanced.yaml")
    with pytest.raises(InputError, match="command"):
        scan_manifest({"mcpServers": {"broken": {"args": []}}}, policy)
