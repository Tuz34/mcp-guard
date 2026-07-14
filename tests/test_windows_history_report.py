from policylatch.windows_audit import parse_windows_audit_record, parse_windows_setting_action
from policylatch.windows_history_report import history_document, history_html_report


def _record(target="HKCU\\SyntheticDemo"):
    return parse_windows_setting_action(
        {
            "action_type": "windows_setting",
            "timestamp": "2026-01-15T10:00:00Z",
            "verification_state": "verified",
            "source": "snapshot_comparison:synthetic_provider->synthetic_provider",
            "category": "registry",
            "target": target,
            "operation": "compare_presence",
            "change": "created",
            "before": {"present": False},
            "after": {"present": True},
            "actor": "demo-agent",
        }
    )


def test_history_html_is_compact_static_and_script_free():
    report = history_html_report(history_document([_record()], source="synthetic-history.jsonl"))
    assert "Windows audit history" in report
    assert "present=False → present=True" in report
    assert "No scripts, telemetry, or external assets." in report
    assert "<script" not in report
    assert "https://" not in report
    assert "http://" not in report


def test_history_html_escapes_record_and_filter_values():
    document = history_document(
        [_record('<img src=x onerror="alert(1)">')],
        source='<script>alert("source")</script>',
        filters={"category": '<b onclick="bad()">registry</b>'},
    )
    report = history_html_report(document)
    assert '<img src=x onerror="alert(1)">' not in report
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in report
    assert "&lt;script&gt;" in report
    assert "&lt;b onclick=&quot;" in report


def test_history_html_renders_empty_filtered_view():
    report = history_html_report(
        history_document([], source="synthetic-history.jsonl", filters={"category": "service"})
    )
    assert "No records match the selected filters." in report


def test_history_html_shows_normalized_fact_changes():
    record = _record()
    payload = record.to_dict()
    payload["change"] = "updated"
    payload["before"] = {
        "present": True,
        "redacted": True,
        "facts": {"policy_state": "disabled"},
    }
    payload["after"] = {
        "present": True,
        "redacted": True,
        "facts": {"policy_state": "enabled"},
    }
    report = history_html_report(
        history_document([parse_windows_audit_record(payload)], source="synthetic.jsonl")
    )

    assert "policy_state=disabled → policy_state=enabled" in report
