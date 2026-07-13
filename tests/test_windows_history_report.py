from mcp_guard.windows_audit import parse_windows_setting_action
from mcp_guard.windows_history_report import history_document, history_html_report


def _record(target="HKCU\\SyntheticDemo"):
    return parse_windows_setting_action(
        {
            "action_type": "windows_setting",
            "timestamp": "2026-01-15T10:00:00Z",
            "verification_state": "verified",
            "source": "synthetic_comparison",
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
    assert "False → True" in report
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
