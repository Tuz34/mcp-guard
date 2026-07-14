import json
from pathlib import Path

import pytest

from policylatch.budgets import action_budget_facts, budget_check_document
from policylatch.cli import main
from policylatch.journal import append_journal
from policylatch.policy import PolicyError, load_policy
from policylatch.validation import InputError, validate_action

ROOT = Path(__file__).parents[1]
BUDGET_POLICY = ROOT / "examples/policies/budgeted.yaml"
BUDGET_ACTION = ROOT / "examples/actions/budgeted-shell.json"


def make_report(tmp_path, action_path=BUDGET_ACTION, policy_path=BUDGET_POLICY, name="report.json"):
    output = tmp_path / name
    assert (
        main(
            [
                "check",
                "--action",
                str(action_path),
                "--policy",
                str(policy_path),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    return output, json.loads(output.read_text(encoding="utf-8"))


def reserve(journal, report, timestamp):
    return append_journal(
        journal,
        report,
        stage="proposed",
        recorded_at=timestamp,
        window_seconds=3600,
        enabled=True,
    )


def test_budget_facts_are_data_minimized():
    action = json.loads(BUDGET_ACTION.read_text(encoding="utf-8"))
    facts = action_budget_facts(action)
    rendered = json.dumps(facts)
    assert facts["confirmation"] == "confirmed"
    assert facts["impact"] == 4
    assert facts["payload_size_class"] == "small"
    assert facts["target_fingerprint"].startswith("sha256:")
    assert "synthetic-target" not in rendered
    assert "synthetic_shell" not in rendered


def test_per_action_and_cumulative_budgets_count_retries(tmp_path):
    _, report = make_report(tmp_path)
    policy = load_policy(BUDGET_POLICY)
    journal = tmp_path / "audit.jsonl"

    first = reserve(journal, report, "2026-07-14T10:00:00Z")
    first_check = budget_check_document(report, policy, "budgeted.yaml", journal, first["event_id"])
    assert first_check["decision"] == "allow"

    second = reserve(journal, report, "2026-07-14T10:10:00Z")
    second_check = budget_check_document(
        report, policy, "budgeted.yaml", journal, second["event_id"]
    )
    assert second_check["decision"] == "allow"

    third = reserve(journal, report, "2026-07-14T10:20:00Z")
    third_check = budget_check_document(report, policy, "budgeted.yaml", journal, third["event_id"])
    by_name = {result["subject"]: result for result in third_check["results"]}
    assert third["duplicate"]["detected"] is True
    assert third_check["decision"] == "deny"
    assert by_name["hourly_shell_calls"]["usage"] == 3
    assert by_name["hourly_shell_calls"]["status"] == "exceeded"
    assert by_name["daily_shell_impact"]["usage"] == 12
    assert by_name["daily_shell_impact"]["decision"] == "warn"


@pytest.mark.parametrize("state", ["missing", "corrupt"])
def test_missing_or_corrupt_journal_denies_unknown_state(tmp_path, state):
    _, report = make_report(tmp_path)
    policy = load_policy(BUDGET_POLICY)
    journal = tmp_path / "audit.jsonl"
    if state == "corrupt":
        journal.write_text("{partial", encoding="utf-8")
    output = budget_check_document(
        report,
        policy,
        "budgeted.yaml",
        journal,
        "sha256:" + "1" * 64,
    )
    assert output["status"] == "unknown"
    assert output["decision"] == "deny"
    assert output["reasons"][0]["rule"] == "budget.journal-unavailable"


def test_budget_check_requires_matching_proposed_reservation(tmp_path):
    _, report = make_report(tmp_path)
    policy = load_policy(BUDGET_POLICY)
    journal = tmp_path / "audit.jsonl"
    evaluated = append_journal(
        journal,
        report,
        stage="evaluated",
        recorded_at="2026-07-14T10:00:00Z",
        window_seconds=300,
        enabled=True,
    )
    output = budget_check_document(report, policy, "budgeted.yaml", journal, evaluated["event_id"])
    assert output["decision"] == "deny"
    assert output["reasons"][0]["rule"] == "budget.reservation-missing"


def test_unknown_confirmation_fails_closed(tmp_path):
    action = json.loads(BUDGET_ACTION.read_text(encoding="utf-8"))
    action["budget"]["confirmation"] = "unknown"
    source = tmp_path / "unknown.json"
    source.write_text(json.dumps(action), encoding="utf-8")
    _, report = make_report(tmp_path, action_path=source, name="unknown-report.json")
    journal = tmp_path / "audit.jsonl"
    reservation = reserve(journal, report, "2026-07-14T10:00:00Z")
    output = budget_check_document(
        report,
        load_policy(BUDGET_POLICY),
        "budgeted.yaml",
        journal,
        reservation["event_id"],
    )
    assert output["status"] == "unknown"
    assert output["decision"] == "deny"
    assert output["results"][0]["reasons"][0]["matched"] == "unknown-state"


def test_unique_target_budget_counts_only_fingerprints(tmp_path):
    policy_path = tmp_path / "targets.yaml"
    policy_path.write_text(
        """version: 1
default_decision: allow
budgets:
  targets:
    metric: unique_targets
    limit: 1
    window: day
    action_types: [shell]
""",
        encoding="utf-8",
    )
    journal = tmp_path / "audit.jsonl"
    reports = []
    for index, target in enumerate(("SYNTHETIC_TARGET_ALPHA", "SYNTHETIC_TARGET_BETA")):
        action = json.loads(BUDGET_ACTION.read_text(encoding="utf-8"))
        action["budget"]["target_id"] = target
        action_path = tmp_path / f"action-{index}.json"
        action_path.write_text(json.dumps(action), encoding="utf-8")
        _, report = make_report(
            tmp_path,
            action_path=action_path,
            policy_path=policy_path,
            name=f"report-{index}.json",
        )
        reports.append(report)
    reserve(journal, reports[0], "2026-07-14T10:00:00Z")
    second = reserve(journal, reports[1], "2026-07-14T10:01:00Z")
    output = budget_check_document(
        reports[1], load_policy(policy_path), "targets.yaml", journal, second["event_id"]
    )
    journal_text = journal.read_text(encoding="utf-8")
    assert output["decision"] == "deny"
    assert output["results"][0]["usage"] == 2
    assert "SYNTHETIC_TARGET_ALPHA" not in journal_text
    assert "SYNTHETIC_TARGET_BETA" not in journal_text


def test_payload_class_filter_fails_closed_when_class_is_unknown(tmp_path):
    policy_path = tmp_path / "payload.yaml"
    policy_path.write_text(
        """version: 1
default_decision: allow
budgets:
  large_payloads:
    metric: calls
    limit: 2
    window: hour
    action_types: [shell]
    payload_classes: [large]
""",
        encoding="utf-8",
    )
    action = json.loads(BUDGET_ACTION.read_text(encoding="utf-8"))
    action["budget"].pop("payload_bytes")
    action_path = tmp_path / "unknown-payload.json"
    action_path.write_text(json.dumps(action), encoding="utf-8")
    _, report = make_report(
        tmp_path, action_path=action_path, policy_path=policy_path, name="payload-report.json"
    )
    journal = tmp_path / "audit.jsonl"
    reservation = reserve(journal, report, "2026-07-14T10:00:00Z")
    output = budget_check_document(
        report, load_policy(policy_path), "payload.yaml", journal, reservation["event_id"]
    )
    assert output["decision"] == "deny"
    assert output["results"][0]["status"] == "unknown"


def test_journal_change_during_budget_read_fails_closed(tmp_path, monkeypatch):
    _, report = make_report(tmp_path)
    policy = load_policy(BUDGET_POLICY)
    journal = tmp_path / "audit.jsonl"
    reservation = reserve(journal, report, "2026-07-14T10:00:00Z")
    from policylatch.journal import load_journal as real_load

    changed = False

    def racing_load(path):
        nonlocal changed
        records = real_load(path)
        if not changed:
            changed = True
            reserve(journal, report, "2026-07-14T10:00:01Z")
        return records

    monkeypatch.setattr("policylatch.budgets.load_journal", racing_load)
    output = budget_check_document(
        report, policy, "budgeted.yaml", journal, reservation["event_id"]
    )
    assert output["decision"] == "deny"
    assert output["reasons"][0]["rule"] == "budget.journal-race"


def test_budget_check_rejects_policy_mismatch(tmp_path):
    _, report = make_report(tmp_path)
    journal = tmp_path / "audit.jsonl"
    reservation = reserve(journal, report, "2026-07-14T10:00:00Z")
    output = budget_check_document(
        report,
        load_policy(ROOT / "examples/policies/balanced.yaml"),
        "balanced.yaml",
        journal,
        reservation["event_id"],
    )
    assert output["decision"] == "deny"
    assert output["reasons"][0]["rule"] == "budget.policy-mismatch"


@pytest.mark.parametrize(
    "budget_yaml,match",
    [
        ("metric: calls\n    limit: 1.5\n    window: hour\n    action_types: [shell]", "integer"),
        ("metric: unknown\n    limit: 1\n    window: hour\n    action_types: [shell]", "metric"),
        ("metric: calls\n    limit: 0\n    window: hour\n    action_types: [shell]", "positive"),
        ("metric: calls\n    limit: 1\n    window: week\n    action_types: [shell]", "window"),
    ],
)
def test_budget_policy_validation_boundaries(tmp_path, budget_yaml, match):
    policy = tmp_path / "invalid.yaml"
    policy.write_text(
        "version: 1\ndefault_decision: allow\nbudgets:\n  test:\n    " + budget_yaml + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match=match):
        load_policy(policy)


def test_action_budget_validation_boundaries():
    action = {
        "action_type": "shell",
        "command": "echo safe",
        "budget": {"confirmation": "confirmed"},
    }
    validate_action(action)
    action["budget"]["impact"] = float("nan")
    with pytest.raises(InputError, match="finite"):
        validate_action(action)


def test_budget_cli_uses_reserved_event_and_formats_report(tmp_path):
    report_path, report = make_report(tmp_path)
    journal = tmp_path / "audit.jsonl"
    reservation = reserve(journal, report, "2026-07-14T10:00:00Z")
    output = tmp_path / "budget.md"
    code = main(
        [
            "budget-check",
            "--input",
            str(report_path),
            "--journal",
            str(journal),
            "--event-id",
            reservation["event_id"],
            "--policy",
            str(BUDGET_POLICY),
            "--format",
            "markdown",
            "--output",
            str(output),
        ]
    )
    assert code == 0
    assert "PolicyLatch report" in output.read_text(encoding="utf-8")
