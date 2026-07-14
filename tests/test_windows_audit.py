import json
from pathlib import Path

import pytest

from policylatch.validation import InputError
from policylatch.windows_audit import parse_windows_setting_action

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "examples/windows-audit"


@pytest.mark.parametrize(
    "filename,state",
    [
        ("proposed-service-change.json", "proposed"),
        ("observed-firewall-change.json", "observed"),
        ("verified-registry-change.json", "verified"),
        ("verified-firewall-profile-change.json", "verified"),
        ("observed-service-runtime.json", "observed"),
    ],
)
def test_parses_synthetic_windows_audit_fixtures(filename, state):
    action = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))

    record = parse_windows_setting_action(action).to_dict()

    assert record["schema_version"] == 1
    assert record["kind"] == "windows_audit_record"
    assert record["verification_state"] == state
    assert record["before"]["redacted"] is True
    assert record["after"]["redacted"] is True


def test_normalized_record_starts_with_contract_identifiers():
    action = json.loads((FIXTURES / "proposed-service-change.json").read_text(encoding="utf-8"))

    record = parse_windows_setting_action(action).to_dict()

    assert list(record)[:2] == ["schema_version", "kind"]


def test_observed_record_is_not_promoted_to_verified():
    action = json.loads((FIXTURES / "observed-firewall-change.json").read_text(encoding="utf-8"))

    record = parse_windows_setting_action(action)

    assert record.verification_state == "observed"


@pytest.mark.parametrize(
    "field",
    ["value", "raw_value", "before_value", "after_value", "value_hash"],
)
def test_rejects_top_level_raw_value_fields(field):
    action = json.loads((FIXTURES / "proposed-service-change.json").read_text(encoding="utf-8"))
    action[field] = "must-never-be-serialized"

    with pytest.raises(InputError, match="raw values or value hashes"):
        parse_windows_setting_action(action)


def test_rejects_raw_value_inside_state_summary():
    action = json.loads((FIXTURES / "proposed-service-change.json").read_text(encoding="utf-8"))
    action["after"]["value"] = "must-never-be-serialized"

    with pytest.raises(InputError, match="raw values or value hashes"):
        parse_windows_setting_action(action)


@pytest.mark.parametrize("state", ["reported", "trusted", "complete"])
def test_rejects_unknown_verification_state(state):
    action = json.loads((FIXTURES / "proposed-service-change.json").read_text(encoding="utf-8"))
    action["verification_state"] = state

    with pytest.raises(InputError, match="verification_state must be one of"):
        parse_windows_setting_action(action)


def test_requires_timezone_in_timestamp():
    action = json.loads((FIXTURES / "proposed-service-change.json").read_text(encoding="utf-8"))
    action["timestamp"] = "2026-01-15T10:00:00"

    with pytest.raises(InputError, match="UTC offset or Z suffix"):
        parse_windows_setting_action(action)


def test_verified_change_requires_known_before_and_after_presence():
    action = json.loads((FIXTURES / "verified-registry-change.json").read_text(encoding="utf-8"))
    action["before"]["present"] = None

    with pytest.raises(InputError, match="Verified records require known"):
        parse_windows_setting_action(action)


def test_verified_change_presence_must_match_change_kind():
    action = json.loads((FIXTURES / "verified-registry-change.json").read_text(encoding="utf-8"))
    action["change"] = "deleted"

    with pytest.raises(InputError, match="inconsistent"):
        parse_windows_setting_action(action)


def test_verified_record_requires_snapshot_comparison_provenance():
    action = json.loads((FIXTURES / "verified-registry-change.json").read_text(encoding="utf-8"))
    action["source"] = "i_just_typed_this"

    with pytest.raises(InputError, match="comparison provenance"):
        parse_windows_setting_action(action)


def test_serialized_record_has_no_raw_value_fields():
    action = json.loads((FIXTURES / "verified-registry-change.json").read_text(encoding="utf-8"))

    serialized = json.dumps(parse_windows_setting_action(action).to_dict())

    for forbidden in ("raw_value", "before_value", "after_value", "value_hash"):
        assert forbidden not in serialized


def test_accepts_only_allowlisted_normalized_facts():
    action = json.loads((FIXTURES / "verified-registry-change.json").read_text(encoding="utf-8"))
    action["change"] = "updated"
    action["before"] = {
        "present": True,
        "facts": {"policy_state": "disabled"},
    }
    action["after"] = {
        "present": True,
        "facts": {"policy_state": "enabled"},
    }

    record = parse_windows_setting_action(action)

    assert record.before.to_dict()["facts"] == {"policy_state": "disabled"}
    assert record.after.to_dict()["facts"] == {"policy_state": "enabled"}


@pytest.mark.parametrize(
    "facts,message",
    [
        ({"raw_state": "anything"}, "Unsupported"),
        ({"policy_state": "custom text"}, "must be one of"),
    ],
)
def test_rejects_unallowlisted_fact_keys_and_values(facts, message):
    action = json.loads((FIXTURES / "proposed-service-change.json").read_text(encoding="utf-8"))
    action["after"] = {"present": True, "facts": facts}

    with pytest.raises(InputError, match=message):
        parse_windows_setting_action(action)
