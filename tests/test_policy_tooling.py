import json
from pathlib import Path

import pytest

from policylatch.cli import main
from policylatch.policy import RULE_KEYS, VALID_DECISIONS, load_policy
from policylatch.policy_tooling import (
    lint_policy_document,
    load_policy_fixtures,
    policy_test_document,
)
from policylatch.schemas import export_schema
from policylatch.validation import InputError

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "examples/policies/balanced.yaml"


def test_policy_test_runs_positive_and_negative_expectations():
    policy = load_policy(POLICY_PATH)
    fixtures = load_policy_fixtures(ROOT / "examples/policy-tests")
    report = policy_test_document(fixtures, policy, "gateway-strict.yaml", "fixtures")

    assert report["decision"] == "allow"
    assert report["summary"] == {"total": 2, "passed": 2, "failed": 0}
    assert all(result["passed"] for result in report["results"])


def test_fixture_metadata_is_not_passed_to_evaluator(monkeypatch):
    seen = {}

    def fake_evaluate(action, policy):
        seen.update(action)

        class Result:
            decision = "allow"

        return Result()

    monkeypatch.setattr("policylatch.policy_tooling.evaluate_action", fake_evaluate)
    policy_test_document(
        [("fixture.json", {"_expected": "allow", "_private": "never", "action_type": "file"})],
        {"rules": {}, "_provenance": {}},
        "test",
        "fixture.json",
    )

    assert seen == {"action_type": "file"}


def test_policy_test_mismatch_is_ci_failure(tmp_path):
    fixture = tmp_path / "mismatch.json"
    fixture.write_text(
        json.dumps({"_expected": "allow", "action_type": "shell", "command": "rm -rf demo"}),
        encoding="utf-8",
    )
    output = tmp_path / "result.json"

    code = main(
        [
            "policy-test",
            "--fixtures",
            str(fixture),
            "--policy",
            str(POLICY_PATH),
            "--output",
            str(output),
        ]
    )

    assert code == 2
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["failed"] == 1


def test_fixture_requires_valid_expected_decision():
    with pytest.raises(InputError, match="_expected"):
        policy_test_document(
            [("bad.json", {"_expected": "maybe", "action_type": "file", "path": "docs/a"})],
            load_policy(POLICY_PATH),
            "policy",
            "bad.json",
        )


def test_lint_reports_duplicate_conflict_broad_and_shadowed_patterns():
    policy = {
        "version": 1,
        "default_decision": "allow",
        "rules": {
            "shell": {"deny_patterns": ["git", "GIT"], "warn_patterns": ["git push"]},
            "network": {"allow_domains": ["*"], "deny_domains": ["*"]},
        },
        "_provenance": {},
    }

    report = lint_policy_document(policy, "synthetic")
    rules = {reason["rule"] for reason in report["reasons"]}
    assert report["decision"] == "warn"
    assert rules == {
        "policy-lint.conflicting-signal",
        "policy-lint.duplicate-pattern",
        "policy-lint.overly-broad-pattern",
        "policy-lint.shadowed-warning",
    }


def test_lint_does_not_modify_policy():
    policy = load_policy(POLICY_PATH)
    before = json.dumps(policy, sort_keys=True)
    lint_policy_document(policy, "gateway-strict.yaml")
    assert json.dumps(policy, sort_keys=True) == before


@pytest.mark.parametrize("kind", ["policy", "action", "gateway-request", "report"])
def test_exported_schemas_are_versioned_and_closed(kind):
    schema = export_schema(kind)
    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["$id"].endswith("-v1.json")


def test_policy_schema_stays_in_parity_with_runtime_rule_keys_and_decisions():
    schema = export_schema("policy")
    assert set(schema["properties"]["rules"]["properties"]) == set(RULE_KEYS)
    for section, names in RULE_KEYS.items():
        assert set(schema["properties"]["rules"]["properties"][section]["properties"]) == names
    assert set(schema["properties"]["default_decision"]["enum"]) == VALID_DECISIONS


def test_tooling_cli_exports_schema_and_sarif(tmp_path):
    schema_output = tmp_path / "policy-schema.json"
    sarif_output = tmp_path / "policy-test.sarif"
    assert main(["schema", "--kind", "policy", "--output", str(schema_output)]) == 0
    assert (
        main(
            [
                "policy-test",
                "--fixtures",
                str(ROOT / "examples/policy-tests"),
                "--policy",
                str(POLICY_PATH),
                "--format",
                "sarif",
                "--output",
                str(sarif_output),
            ]
        )
        == 0
    )
    assert json.loads(schema_output.read_text(encoding="utf-8"))["title"]
    assert json.loads(sarif_output.read_text(encoding="utf-8"))["version"] == "2.1.0"
