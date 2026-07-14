import json
from copy import deepcopy
from pathlib import Path

import pytest

from policylatch.cli import _action_document, main
from policylatch.html_report import html_report
from policylatch.policy import load_policy
from policylatch.receipts import (
    action_request_projection,
    decision_receipt,
    receipt_jsonl,
    validate_receipt,
)
from policylatch.reports import json_report, markdown_report
from policylatch.schemas import export_schema
from policylatch.validation import InputError

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "examples/policies/balanced.yaml"


def action(command="Remove-Item -Recurse D:\\Synthetic\\demo"):
    return {"action_type": "shell", "command": command, "tool": "synthetic-tool"}


def report_and_policy(command=None):
    policy = load_policy(POLICY_PATH)
    payload = action(command) if command else action()
    return _action_document("synthetic.json", policy, "balanced.yaml", payload), policy, payload


def test_same_redacted_input_and_policy_produce_same_receipt():
    first, _, _ = report_and_policy()
    second, _, _ = report_and_policy()
    assert first["receipt"] == second["receipt"]
    assert "timestamp" not in json.dumps(first["receipt"]).casefold()
    assert first["receipt"]["execution"] == {"claimed": False}


def test_policy_or_decision_change_changes_receipt_fingerprint():
    report, policy, projection_input = report_and_policy()
    changed_policy = deepcopy(policy)
    changed_policy["default_decision"] = "deny"
    policy_changed = decision_receipt(
        report, changed_policy, action_request_projection(projection_input)
    )

    changed_report = deepcopy(report)
    changed_report.pop("receipt")
    changed_report["decision"] = "warn"
    decision_changed = decision_receipt(
        changed_report, policy, action_request_projection(projection_input)
    )

    fingerprint = report["receipt"]["receipt_fingerprint"]
    assert policy_changed["receipt_fingerprint"] != fingerprint
    assert decision_changed["receipt_fingerprint"] != fingerprint


def test_receipt_and_all_report_formats_omit_sensitive_input():
    marker = "SYNTHETIC_PRIVATE_COMMAND_ARGUMENT"
    report, _, _ = report_and_policy(f"echo {marker}")
    receipt = report["receipt"]

    for rendered in (
        json_report(report),
        markdown_report(report),
        html_report(report),
        receipt_jsonl(receipt),
    ):
        assert marker not in rendered
        assert receipt["receipt_fingerprint"] in rendered


def test_receipt_validator_supports_v1_and_rejects_tamper_or_future_version():
    report, _, _ = report_and_policy()
    receipt = report["receipt"]
    assert validate_receipt(json.loads(json.dumps(receipt))) == receipt

    tampered = deepcopy(receipt)
    tampered["decision"] = "allow"
    with pytest.raises(InputError, match="fingerprint"):
        validate_receipt(tampered)

    future = deepcopy(receipt)
    future["schema_version"] = 2
    with pytest.raises(InputError, match="version 1"):
        validate_receipt(future)


def test_receipt_schema_is_versioned():
    schema = export_schema("receipt")
    assert schema["$id"].endswith("receipt-v1.json")
    assert schema["properties"]["execution"]["properties"]["claimed"] == {"const": False}


def test_cli_extracts_validated_receipt_as_jsonl(tmp_path):
    report_output = tmp_path / "report.json"
    receipt_output = tmp_path / "receipt.jsonl"
    assert (
        main(
            [
                "check",
                "--action",
                str(ROOT / "examples/actions/risky-shell-command.json"),
                "--policy",
                str(POLICY_PATH),
                "--output",
                str(report_output),
            ]
        )
        == 2
    )
    assert (
        main(
            [
                "receipt",
                "--input",
                str(report_output),
                "--format",
                "jsonl",
                "--output",
                str(receipt_output),
            ]
        )
        == 0
    )
    lines = receipt_output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert validate_receipt(json.loads(lines[0]))
