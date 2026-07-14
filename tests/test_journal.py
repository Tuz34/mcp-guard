import json
from pathlib import Path

import pytest

from policylatch.cli import main
from policylatch.journal import (
    append_journal,
    filter_journal,
    journal_entry_from_report,
    journal_html_report,
    journal_report_document,
    load_journal,
)
from policylatch.validation import InputError

ROOT = Path(__file__).parents[1]
POLICY = ROOT / "examples/policies/balanced.yaml"


def make_report(tmp_path, marker="SYNTHETIC_PRIVATE_JOURNAL_VALUE"):
    action = tmp_path / "action.json"
    report = tmp_path / "report.json"
    action.write_text(
        json.dumps({"action_type": "shell", "command": f"echo {marker}"}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "check",
                "--action",
                str(action),
                "--policy",
                str(POLICY),
                "--output",
                str(report),
            ]
        )
        == 0
    )
    return report, json.loads(report.read_text(encoding="utf-8")), marker


def test_journal_append_requires_explicit_opt_in(tmp_path, capsys):
    report_path, _, _ = make_report(tmp_path)
    journal = tmp_path / "audit.jsonl"
    code = main(
        [
            "journal-append",
            "--input",
            str(report_path),
            "--journal",
            str(journal),
        ]
    )
    assert code == 3
    assert not journal.exists()
    assert "enabled=True" in capsys.readouterr().err


def test_journal_lifecycle_and_duplicate_window_are_unverified(tmp_path):
    report_path, report, _ = make_report(tmp_path)
    journal = tmp_path / "audit.jsonl"
    first_output = tmp_path / "first.json"
    second_output = tmp_path / "second.json"

    assert (
        main(
            [
                "journal-append",
                "--input",
                str(report_path),
                "--journal",
                str(journal),
                "--stage",
                "evaluated",
                "--at",
                "2026-07-14T10:00:00Z",
                "--enable-journal",
                "--output",
                str(first_output),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "journal-append",
                "--input",
                str(report_path),
                "--journal",
                str(journal),
                "--stage",
                "observed-result",
                "--at",
                "2026-07-14T10:01:00Z",
                "--window-seconds",
                "300",
                "--enable-journal",
                "--output",
                str(second_output),
            ]
        )
        == 0
    )

    records = load_journal(journal)
    assert records is not None
    assert [record["stage"] for record in records] == ["evaluated", "observed-result"]
    assert all(record["verification_state"] == "unverified" for record in records)
    assert records[0]["duplicate"]["detected"] is False
    assert records[1]["duplicate"]["detected"] is True
    assert records[1]["duplicate"]["prior_event_id"] == records[0]["event_id"]
    assert records[0]["request_id"] == report["receipt"]["request"]["fingerprint"]


def test_exact_event_replay_is_rejected(tmp_path):
    _, report, _ = make_report(tmp_path)
    journal = tmp_path / "audit.jsonl"
    append_journal(
        journal,
        report,
        stage="evaluated",
        recorded_at="2026-07-14T10:00:00Z",
        window_seconds=300,
        enabled=True,
    )
    with pytest.raises(InputError, match="exact event_id"):
        append_journal(
            journal,
            report,
            stage="evaluated",
            recorded_at="2026-07-14T10:00:00Z",
            window_seconds=300,
            enabled=True,
        )


def test_replay_check_without_source_is_explicit_unknown(tmp_path):
    report_path, _, _ = make_report(tmp_path)
    missing = tmp_path / "missing.jsonl"
    output = tmp_path / "check.json"
    code = main(
        [
            "journal-check",
            "--input",
            str(report_path),
            "--journal",
            str(missing),
            "--at",
            "2026-07-14T10:00:00Z",
            "--output",
            str(output),
        ]
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert code == 1
    assert payload["status"] == "source-unavailable"
    assert payload["duplicate"] is False
    assert not missing.exists()


def test_replay_check_finds_duplicate(tmp_path):
    report_path, report, _ = make_report(tmp_path)
    journal = tmp_path / "audit.jsonl"
    append_journal(
        journal,
        report,
        stage="proposed",
        recorded_at="2026-07-14T10:00:00Z",
        window_seconds=300,
        enabled=True,
    )
    output = tmp_path / "check.json"
    code = main(
        [
            "journal-check",
            "--input",
            str(report_path),
            "--journal",
            str(journal),
            "--at",
            "2026-07-14T10:02:00Z",
            "--output",
            str(output),
        ]
    )
    assert code == 1
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "duplicate"


def test_journal_revalidates_incomplete_and_oversized_lines(tmp_path, monkeypatch):
    incomplete = tmp_path / "incomplete.jsonl"
    incomplete.write_text("{}", encoding="utf-8")
    with pytest.raises(InputError, match="incomplete"):
        load_journal(incomplete)

    oversized = tmp_path / "oversized.jsonl"
    oversized.write_bytes(b"{" + b"x" * 32 + b"}\n")
    monkeypatch.setattr("policylatch.journal.MAX_JOURNAL_LINE_BYTES", 16)
    with pytest.raises(InputError, match="line"):
        load_journal(oversized)


def test_append_flushes_and_fsyncs(tmp_path, monkeypatch):
    _, report, _ = make_report(tmp_path)
    calls = []
    real_fsync = __import__("os").fsync

    def tracked_fsync(descriptor):
        calls.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr("policylatch.journal.os.fsync", tracked_fsync)
    append_journal(
        tmp_path / "audit.jsonl",
        report,
        stage="evaluated",
        recorded_at="2026-07-14T10:00:00Z",
        window_seconds=300,
        enabled=True,
    )
    assert len(calls) == 1


def test_filtered_json_and_html_omit_raw_action_values(tmp_path):
    _, report, marker = make_report(tmp_path)
    first = journal_entry_from_report(
        report,
        [],
        stage="evaluated",
        recorded_at="2026-07-14T10:00:00Z",
        window_seconds=300,
    )
    second = journal_entry_from_report(
        report,
        [first],
        stage="observed-result",
        recorded_at="2026-07-14T10:01:00Z",
        window_seconds=300,
    )
    filtered = filter_journal(
        [first, second],
        stage="observed-result",
        duplicate=True,
        from_timestamp="2026-07-14T10:00:30Z",
    )
    payload = journal_report_document(filtered, "audit.jsonl", {"duplicate": True})
    rendered_json = json.dumps(payload)
    rendered_html = journal_html_report(payload)
    assert len(filtered) == 1
    assert marker not in rendered_json
    assert marker not in rendered_html
    assert "<script" not in rendered_html
