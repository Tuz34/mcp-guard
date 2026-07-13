import json
from pathlib import Path

from mcp_guard.cli import main

ROOT = Path(__file__).parents[1]


def test_check_writes_json(tmp_path):
    output = tmp_path / "result.json"
    code = main(
        [
            "check",
            "--action",
            str(ROOT / "examples/actions/risky-shell-command.json"),
            "--policy",
            str(ROOT / "examples/policies/balanced.yaml"),
            "--output",
            str(output),
        ]
    )
    assert code == 2
    payload = json.loads(output.read_text())
    assert payload["schema_version"] == 1
    assert payload["kind"] == "action_evaluation"
    assert payload["decision"] == "deny"


def test_report_writes_markdown(tmp_path):
    source = tmp_path / "result.json"
    output = tmp_path / "report.md"
    source.write_text(json.dumps({"decision": "allow", "risk_level": "low", "reasons": []}))
    assert main(["report", "--input", str(source), "--output", str(output)]) == 0
    assert "# mcp-guard report" in output.read_text()


def test_scan_writes_aggregate_summary(tmp_path):
    output = tmp_path / "scan.json"
    code = main(
        [
            "scan",
            "--mcp-config",
            str(ROOT / "examples/mcp/risky-server.json"),
            "--policy",
            str(ROOT / "examples/policies/balanced.yaml"),
            "--output",
            str(output),
        ]
    )
    payload = json.loads(output.read_text())
    assert code == 2
    assert payload["decision"] == "deny"
    assert payload["summary"] == {"total": 2, "allow": 0, "warn": 1, "deny": 1}


def test_invalid_action_returns_input_error(tmp_path, capsys):
    action = tmp_path / "action.json"
    action.write_text('{"action_type": "unknown"}', encoding="utf-8")
    code = main(
        [
            "check",
            "--action",
            str(action),
            "--policy",
            str(ROOT / "examples/policies/balanced.yaml"),
        ]
    )
    assert code == 3
    assert "Unsupported action.action_type" in capsys.readouterr().err


def test_invalid_json_reports_line_and_column(tmp_path, capsys):
    action = tmp_path / "broken.json"
    action.write_text('{"action_type":', encoding="utf-8")
    code = main(
        [
            "check",
            "--action",
            str(action),
            "--policy",
            str(ROOT / "examples/policies/balanced.yaml"),
        ]
    )
    assert code == 3
    assert "line 1, column" in capsys.readouterr().err


def test_invalid_report_is_not_written(tmp_path, capsys):
    source = tmp_path / "invalid-report.json"
    output = tmp_path / "should-not-exist.md"
    source.write_text('{"decision": "allow"}', encoding="utf-8")
    code = main(
        [
            "report",
            "--input",
            str(source),
            "--output",
            str(output),
        ]
    )
    assert code == 3
    assert not output.exists()
    assert "risk_level" in capsys.readouterr().err


def test_report_writes_self_contained_html(tmp_path):
    source = tmp_path / "result.json"
    output = tmp_path / "report.html"
    source.write_text(
        json.dumps({"decision": "allow", "risk_level": "low", "reasons": []}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "report",
                "--input",
                str(source),
                "--format",
                "html",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    html = output.read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "No scripts, telemetry, or external assets." in html


def test_non_string_network_url_returns_clean_input_error(tmp_path, capsys):
    action = tmp_path / "invalid-network.json"
    action.write_text(
        json.dumps(
            {
                "action_type": "network",
                "url": 123,
                "domain": "example.com",
            }
        ),
        encoding="utf-8",
    )
    code = main(
        [
            "check",
            "--action",
            str(action),
            "--policy",
            str(ROOT / "examples/policies/balanced.yaml"),
        ]
    )
    captured = capsys.readouterr()
    assert code == 3
    assert "action.url must be a string" in captured.err
    assert "Traceback" not in captured.err


def test_audit_append_requires_explicit_history_flag(tmp_path, capsys):
    history = tmp_path / "audit.jsonl"
    code = main(
        [
            "audit-append",
            "--input",
            str(ROOT / "examples/windows-audit/verified-registry-change.json"),
            "--history",
            str(history),
        ]
    )
    assert code == 3
    assert not history.exists()
    assert "enabled=True" in capsys.readouterr().err


def test_audit_history_cli_append_filter_and_html_report(tmp_path):
    history = tmp_path / "audit.jsonl"
    output = tmp_path / "history.html"
    assert (
        main(
            [
                "audit-append",
                "--input",
                str(ROOT / "examples/windows-audit/verified-registry-change.json"),
                "--history",
                str(history),
                "--enable-history",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "audit-report",
                "--input",
                str(history),
                "--format",
                "html",
                "--category",
                "registry",
                "--state",
                "verified",
                "--from",
                "2026-01-15T09:00:00Z",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    report = output.read_text(encoding="utf-8")
    assert "Windows audit history" in report
    assert "verified" in report
    assert "<script" not in report
