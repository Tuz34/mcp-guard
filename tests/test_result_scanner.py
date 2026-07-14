import json
from pathlib import Path

import pytest

from policylatch.cli import main
from policylatch.html_report import html_report
from policylatch.receipts import validate_receipt
from policylatch.reports import json_report, markdown_report
from policylatch.result_scanner import scan_tool_result, validate_tool_result
from policylatch.sarif_report import sarif_report
from policylatch.schemas import export_schema
from policylatch.validation import InputError

ROOT = Path(__file__).parents[1]
CLEAN = ROOT / "examples/tool-results/clean.json"
MALICIOUS = ROOT / "examples/tool-results/malicious.json"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_clean_result_has_explicit_clean_outcome():
    report = scan_tool_result(load(CLEAN), str(CLEAN))
    assert report["postflight_outcome"] == "clean"
    assert report["decision"] == "allow"
    assert report["reasons"] == []
    assert validate_receipt(report["receipt"])


def test_malicious_result_blocks_next_step_with_fixed_categories():
    report = scan_tool_result(load(MALICIOUS), str(MALICIOUS))
    rules = {reason["rule"] for reason in report["reasons"]}
    assert report["postflight_outcome"] == "block-next-step"
    assert report["decision"] == "deny"
    assert rules == {
        "tool-result.exfiltration-direction",
        "tool-result.external-url",
        "tool-result.pii-field-name",
        "tool-result.prompt-injection",
        "tool-result.secret-like-content",
    }
    assert all(reason["matched"].startswith("redacted:sha256:") for reason in report["reasons"])


def test_declared_trust_never_bypasses_scanning():
    payload = load(MALICIOUS)
    payload["source_trust"] = "trusted-local"
    assert scan_tool_result(payload, "synthetic.json")["postflight_outcome"] == ("block-next-step")


def test_external_url_alone_requires_review_and_expected_domain_can_clear_it():
    payload = load(CLEAN)
    payload["content"] = "Reference: https://docs.example.invalid/guide"
    reviewed = scan_tool_result(payload, "synthetic.json")
    assert reviewed["postflight_outcome"] == "review"
    assert reviewed["decision"] == "warn"

    payload["expected_domains"] = ["docs.example.invalid"]
    clean = scan_tool_result(payload, "synthetic.json")
    assert clean["postflight_outcome"] == "clean"


def test_raw_sensitive_values_never_reach_any_report_format():
    payload = load(MALICIOUS)
    report = scan_tool_result(payload, str(MALICIOUS))
    raw_values = (
        "synthetic-not-a-real-key",
        "collector.example.invalid",
        "synthetic-person@example.invalid",
        payload["request_id"],
        payload["result_id"],
    )
    for rendered in (
        json_report(report),
        markdown_report(report),
        html_report(report),
        sarif_report(report),
    ):
        assert all(value not in rendered for value in raw_values)
    sarif = json.loads(sarif_report(report))
    assert sarif["runs"][0]["results"]
    assert sarif["runs"][0]["results"][0]["properties"]["postflightOutcome"] == ("block-next-step")


def test_tool_result_contract_rejects_unknown_and_oversized_fields(monkeypatch):
    unknown = load(CLEAN)
    unknown["raw_payload"] = "not accepted"
    with pytest.raises(InputError, match="unsupported"):
        validate_tool_result(unknown)

    oversized = load(CLEAN)
    oversized["content"] = "x" * 20
    monkeypatch.setattr("policylatch.result_scanner.MAX_LINE_BYTES", 16)
    with pytest.raises(InputError, match="line"):
        validate_tool_result(oversized)


def test_correlation_ids_are_fingerprinted_and_deterministic():
    first = scan_tool_result(load(CLEAN), "one.json")
    second = scan_tool_result(load(CLEAN), "two.json")
    assert first["correlation"] == second["correlation"]
    assert first["receipt"]["receipt_fingerprint"] == second["receipt"]["receipt_fingerprint"]


def test_tool_result_schema_is_versioned():
    schema = export_schema("tool-result")
    assert schema["$id"].endswith("tool-result-v1.json")
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "format_name,extension",
    [("json", "json"), ("markdown", "md"), ("html", "html"), ("sarif", "sarif")],
)
def test_result_scan_cli_supports_all_reports(tmp_path, format_name, extension):
    output = tmp_path / f"report.{extension}"
    code = main(
        [
            "result-scan",
            "--input",
            str(MALICIOUS),
            "--format",
            format_name,
            "--output",
            str(output),
        ]
    )
    assert code == 2
    assert output.exists()


def test_existing_action_evaluator_contract_is_unchanged(tmp_path):
    output = tmp_path / "action.json"
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
    assert json.loads(output.read_text(encoding="utf-8"))["kind"] == "action_evaluation"
