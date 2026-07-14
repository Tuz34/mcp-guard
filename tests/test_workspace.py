import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from policylatch.cli import main
from policylatch.policy import load_policy
from policylatch.reports import json_report, validate_report
from policylatch.validation import InputError
from policylatch.workspace import workspace_diff_document, workspace_scan_document

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "examples/policies/gateway-strict.yaml"
POLICY = load_policy(POLICY_PATH)


def write_manifest(path, *, risky=False, marker="SYNTHETIC_WORKSPACE_PRIVATE_VALUE"):
    path.parent.mkdir(parents=True, exist_ok=True)
    if risky:
        payload = {
            "mcpServers": {
                "synthetic-risky": {
                    "command": "rm",
                    "args": ["-rf", marker],
                    "description": marker,
                }
            }
        }
    else:
        payload = {
            "tools": [
                {
                    "name": "read_file",
                    "description": marker,
                    "inputSchema": {"type": "object"},
                }
            ]
        }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_workspace_inventory_is_deterministic_summary_only(tmp_path):
    marker = "SYNTHETIC_WORKSPACE_PRIVATE_VALUE"
    write_manifest(tmp_path / ".mcp.json", marker=marker)
    write_manifest(tmp_path / "config/mcp.json", risky=True, marker=marker)

    first = workspace_scan_document(tmp_path, POLICY, "gateway-strict")
    second = workspace_scan_document(tmp_path, POLICY, "gateway-strict")
    rendered = json_report(first)

    assert first["baseline_fingerprint"] == second["baseline_fingerprint"]
    assert first["summary"]["files"] == 2
    assert first["summary"]["tools"] == 2
    assert [entry["path"] for entry in first["inventory"]] == [
        ".mcp.json",
        "config/mcp.json",
    ]
    assert marker not in rendered
    assert str(tmp_path) not in rendered
    assert validate_report(first)


def test_workspace_scan_is_bounded_and_fail_closed(tmp_path, monkeypatch):
    write_manifest(tmp_path / "one/mcp.json")
    write_manifest(tmp_path / "two/mcp.json")
    with pytest.raises(InputError, match="file-count"):
        workspace_scan_document(tmp_path, POLICY, "strict", max_files=1)

    monkeypatch.setattr("policylatch.workspace.MAX_FILE_BYTES", 16)
    with pytest.raises(InputError, match="file byte"):
        workspace_scan_document(tmp_path, POLICY, "strict")


def test_workspace_total_bytes_depth_and_extra_pattern_are_explicit(tmp_path):
    custom = tmp_path / "custom/server-config.json"
    write_manifest(custom)
    with pytest.raises(InputError, match="no matching"):
        workspace_scan_document(tmp_path, POLICY, "strict")

    found = workspace_scan_document(tmp_path, POLICY, "strict", patterns=["custom/*.json"])
    assert found["inventory"][0]["path"] == "custom/server-config.json"
    with pytest.raises(InputError, match="total-byte"):
        workspace_scan_document(
            tmp_path,
            POLICY,
            "strict",
            patterns=["custom/*.json"],
            max_total_bytes=10,
        )

    nested = tmp_path / "a/b/mcp.json"
    write_manifest(nested)
    with pytest.raises(InputError, match="depth"):
        workspace_scan_document(tmp_path, POLICY, "strict", max_depth=1)


def test_workspace_rejects_malformed_json_and_unsafe_patterns(tmp_path):
    (tmp_path / "mcp.json").write_text('{"tools": [}', encoding="utf-8")
    with pytest.raises(InputError, match="strict bounded JSON"):
        workspace_scan_document(tmp_path, POLICY, "strict")
    with pytest.raises(InputError, match="relative"):
        workspace_scan_document(tmp_path, POLICY, "strict", patterns=["../*.json"])


def test_workspace_symlink_escape_is_rejected_when_supported(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.json"
    outside.write_text('{"tools":[{"name":"read_file"}]}', encoding="utf-8")
    link = tmp_path / "mcp.json"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("File symlinks are not available in this environment.")
    with pytest.raises(InputError, match="escapes"):
        workspace_scan_document(tmp_path, POLICY, "strict")


def test_workspace_diff_detects_value_change_and_risk_increase(tmp_path):
    config = tmp_path / "mcp.json"
    write_manifest(config)
    before = workspace_scan_document(tmp_path, POLICY, "strict")
    write_manifest(config, risky=True)
    after = workspace_scan_document(tmp_path, POLICY, "strict")

    diff = workspace_diff_document(before, after, fail_on="risk-increase")
    assert diff["changes"]["changed"] == ["mcp.json"]
    assert diff["changes"]["risk_increases"] == ["mcp.json"]
    assert diff["gate"]["failed"] is True
    assert diff["decision"] == "deny"
    assert validate_report(diff)

    relaxed = workspace_diff_document(before, after, fail_on="never")
    assert relaxed["gate"]["failed"] is False


def test_workspace_diff_rejects_tampered_baseline(tmp_path):
    write_manifest(tmp_path / "mcp.json")
    baseline = workspace_scan_document(tmp_path, POLICY, "strict")
    baseline["inventory"][0]["tool_count"] = 99
    with pytest.raises(InputError, match="values|fingerprint"):
        workspace_diff_document(baseline, baseline, fail_on="risk-increase")


def test_workspace_diff_surfaces_policy_only_change(tmp_path):
    write_manifest(tmp_path / "mcp.json")
    before = workspace_scan_document(tmp_path, POLICY, "strict")
    changed_policy = deepcopy(POLICY)
    changed_policy["rules"]["shell"]["warn_patterns"].append("synthetic-never-match")
    after = workspace_scan_document(tmp_path, changed_policy, "strict-modified")

    diff = workspace_diff_document(before, after, fail_on="risk-increase")
    assert diff["changes"]["policy_changed"] is True
    assert diff["changes"]["changed"] == []
    assert diff["decision"] == "warn"


@pytest.mark.parametrize(
    "format_name,extension", [("json", "json"), ("markdown", "md"), ("sarif", "sarif")]
)
def test_workspace_scan_cli_supports_reports(tmp_path, format_name, extension):
    write_manifest(tmp_path / "mcp.json")
    output = tmp_path / f"inventory.{extension}"
    code = main(
        [
            "workspace-scan",
            "--root",
            str(tmp_path),
            "--policy",
            str(POLICY_PATH),
            "--format",
            format_name,
            "--output",
            str(output),
        ]
    )

    assert code == 0
    assert output.exists()


def test_workspace_diff_cli_risk_gate(tmp_path):
    workspace = tmp_path / "workspace"
    config = workspace / "mcp.json"
    write_manifest(config)
    before = workspace_scan_document(workspace, POLICY, "strict")
    write_manifest(config, risky=True)
    after = workspace_scan_document(workspace, POLICY, "strict")
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json_report(before), encoding="utf-8")
    after_path.write_text(json_report(after), encoding="utf-8")

    assert (
        main(
            [
                "workspace-diff",
                "--before",
                str(before_path),
                "--after",
                str(after_path),
            ]
        )
        == 2
    )
