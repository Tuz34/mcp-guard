import json
from pathlib import Path

import pytest

from policylatch.validation import InputError
from policylatch.windows_audit import (
    StateSummary,
    parse_windows_audit_record,
    parse_windows_setting_action,
)
from policylatch.windows_compare import compare_windows_snapshots
from policylatch.windows_history import (
    HistoryError,
    append_audit_record,
    filter_audit_history,
    load_audit_history,
)
from policylatch.windows_providers import ObservedWindowsSnapshot

ROOT = Path(__file__).parents[1]


def _record(timestamp="2026-01-15T10:00:00Z", *, category="registry", state="verified"):
    return parse_windows_setting_action(
        {
            "action_type": "windows_setting",
            "timestamp": timestamp,
            "verification_state": state,
            "source": (
                "snapshot_comparison:synthetic_provider->synthetic_provider"
                if state == "verified"
                else "synthetic_observation"
            ),
            "category": category,
            "target": "SyntheticTarget",
            "operation": "compare_presence",
            "change": "created" if state == "verified" else "unknown",
            "before": {"present": False if state == "verified" else None},
            "after": {"present": True if state == "verified" else None},
        }
    )


def test_normalized_record_round_trips():
    original = _record()

    loaded = parse_windows_audit_record(original.to_dict())

    assert loaded == original


def test_rejects_raw_values_in_normalized_record():
    payload = _record().to_dict()
    payload["before_value"] = "must-never-be-stored"

    with pytest.raises(InputError, match="raw values"):
        parse_windows_audit_record(payload)


def test_history_append_requires_explicit_opt_in(tmp_path):
    path = tmp_path / "audit.jsonl"

    with pytest.raises(HistoryError, match="enabled=True"):
        append_audit_record(path, _record(), enabled=False)

    assert not path.exists()


def test_appends_and_loads_summary_only_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_audit_record(path, _record(), enabled=True)
    append_audit_record(
        path,
        _record("2026-01-15T11:00:00Z", category="service", state="observed"),
        enabled=True,
    )

    records = load_audit_history(path)
    lines = path.read_text(encoding="utf-8").splitlines()

    assert len(records) == 2
    assert len(lines) == 2
    assert all(json.loads(line)["kind"] == "windows_audit_record" for line in lines)
    assert "raw_value" not in path.read_text(encoding="utf-8")


def test_loads_public_synthetic_history_example():
    records = load_audit_history(ROOT / "examples/windows-audit/synthetic-history.jsonl")

    assert [record.verification_state for record in records] == ["proposed", "verified"]


def test_verified_absence_comparison_round_trips_through_history(tmp_path):
    before = ObservedWindowsSnapshot(
        collected_at="2026-01-15T10:00:00Z",
        source="synthetic_provider",
        category="registry",
        target="HKCU\\SyntheticMissing",
        state=StateSummary(present=False),
    )
    after = ObservedWindowsSnapshot(
        collected_at="2026-01-15T10:01:00Z",
        source="synthetic_provider",
        category="registry",
        target="HKCU\\SyntheticMissing",
        state=StateSummary(present=False),
    )
    record = compare_windows_snapshots(before, after)
    path = tmp_path / "audit.jsonl"

    append_audit_record(path, record, enabled=True)

    assert load_audit_history(path) == [record]


def test_invalid_history_reports_line_number(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text(json.dumps(_record().to_dict()) + "\nnot-json\n", encoding="utf-8")

    with pytest.raises(HistoryError, match="line 2"):
        load_audit_history(path)


def test_oversized_single_line_is_rejected_by_bounded_reader(tmp_path, monkeypatch):
    path = tmp_path / "oversized.jsonl"
    path.write_text("x" * 33, encoding="utf-8")
    monkeypatch.setattr("policylatch.windows_history.MAX_HISTORY_LINE_BYTES", 32)

    with pytest.raises(HistoryError, match="line 1 is too large"):
        load_audit_history(path)


def test_filters_history_by_category_state_and_time():
    records = [
        _record("2026-01-15T10:00:00Z", category="registry", state="verified"),
        _record("2026-01-15T11:00:00Z", category="service", state="observed"),
        _record("2026-01-15T12:00:00Z", category="registry", state="verified"),
    ]

    filtered = filter_audit_history(
        records,
        category="registry",
        verification_state="verified",
        from_timestamp="2026-01-15T11:30:00Z",
        to_timestamp="2026-01-15T12:30:00Z",
    )

    assert [record.timestamp for record in filtered] == ["2026-01-15T12:00:00Z"]


def test_rejects_reversed_time_filter():
    with pytest.raises(HistoryError, match="cannot be later"):
        filter_audit_history(
            [],
            from_timestamp="2026-01-15T12:00:00Z",
            to_timestamp="2026-01-15T11:00:00Z",
        )
