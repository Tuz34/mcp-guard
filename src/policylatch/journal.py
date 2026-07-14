# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any

from .receipts import canonical_json, validate_receipt
from .reports import validate_report
from .validation import InputError

JOURNAL_STAGES = ("proposed", "evaluated", "observed-result")
MAX_JOURNAL_LINE_BYTES = 64 * 1024
MAX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_JOURNAL_RECORDS = 10_000
MAX_REPLAY_WINDOW_SECONDS = 86_400
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")


def _hash(value: Any) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _timestamp(value: str | None) -> tuple[str, datetime]:
    if value is None:
        parsed = datetime.now(timezone.utc)
    else:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise InputError("Journal timestamps must be valid ISO-8601 values.") from exc
        if parsed.tzinfo is None:
            raise InputError("Journal timestamps must include a timezone.")
        parsed = parsed.astimezone(timezone.utc)
    normalized = parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
    return normalized, parsed


def _window(seconds: int) -> int:
    if isinstance(seconds, bool) or not 1 <= seconds <= MAX_REPLAY_WINDOW_SECONDS:
        raise InputError(
            f"Replay window must be between 1 and {MAX_REPLAY_WINDOW_SECONDS} seconds."
        )
    return seconds


def _event_core(entry: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "schema_version",
        "kind",
        "request_id",
        "receipt_fingerprint",
        "stage",
        "verification_state",
        "recorded_at",
        "decision",
        "policy_hash",
        "evaluator_version",
        "rule_ids",
        "budget_facts",
    )
    return {field: entry[field] for field in fields}


def validate_journal_entry(entry: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "kind",
        "event_id",
        "request_id",
        "receipt_fingerprint",
        "stage",
        "verification_state",
        "recorded_at",
        "decision",
        "policy_hash",
        "evaluator_version",
        "rule_ids",
        "duplicate",
        "budget_facts",
    }
    if set(entry) != required:
        raise InputError("Journal entry fields do not match schema version 1.")
    if entry.get("schema_version") != 1 or entry.get("kind") != "agent_action_audit":
        raise InputError("Journal entry schema or kind is invalid.")
    if entry.get("stage") not in JOURNAL_STAGES:
        raise InputError("Journal entry stage is invalid.")
    if entry.get("verification_state") != "unverified":
        raise InputError("General journal entries must remain unverified.")
    if entry.get("decision") not in {"allow", "warn", "deny"}:
        raise InputError("Journal entry decision is invalid.")
    _, parsed = _timestamp(entry.get("recorded_at"))
    if parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != entry["recorded_at"]:
        raise InputError("Journal entry recorded_at must be normalized UTC seconds.")
    hash_fields = ("event_id", "request_id", "receipt_fingerprint", "policy_hash")
    if not all(
        isinstance(entry.get(field), str) and _FINGERPRINT.fullmatch(entry[field])
        for field in hash_fields
    ):
        raise InputError("Journal entry contains an invalid fingerprint.")
    if not isinstance(entry.get("evaluator_version"), str) or not entry["evaluator_version"]:
        raise InputError("Journal entry evaluator_version is invalid.")
    if not isinstance(entry.get("rule_ids"), list) or not all(
        isinstance(item, str) for item in entry["rule_ids"]
    ):
        raise InputError("Journal entry rule_ids must be an array of strings.")
    budget_facts = entry.get("budget_facts")
    if not isinstance(budget_facts, dict) or set(budget_facts) != {
        "action_type",
        "confirmation",
        "impact",
        "payload_size_class",
        "target_fingerprint",
        "tool_fingerprint",
    }:
        raise InputError("Journal entry budget_facts are invalid.")
    if budget_facts["action_type"] not in {
        "file",
        "filesystem",
        "network",
        "shell",
        "unknown",
    } or budget_facts["confirmation"] not in {"confirmed", "estimated", "unknown"}:
        raise InputError("Journal entry budget fact state is invalid.")
    if budget_facts["payload_size_class"] not in {"small", "medium", "large", "unknown"}:
        raise InputError("Journal entry payload size class is invalid.")
    impact = budget_facts["impact"]
    if impact is not None and (
        isinstance(impact, bool) or not isinstance(impact, (int, float)) or impact < 0
    ):
        raise InputError("Journal entry impact is invalid.")
    for field in ("target_fingerprint", "tool_fingerprint"):
        value = budget_facts[field]
        if value is not None and (not isinstance(value, str) or not _FINGERPRINT.fullmatch(value)):
            raise InputError(f"Journal entry {field} is invalid.")
    duplicate = entry.get("duplicate")
    if not isinstance(duplicate, dict) or set(duplicate) != {
        "detected",
        "window_seconds",
        "prior_event_id",
    }:
        raise InputError("Journal entry duplicate metadata is invalid.")
    if not isinstance(duplicate["detected"], bool):
        raise InputError("Journal entry duplicate.detected must be boolean.")
    _window(duplicate["window_seconds"])
    prior = duplicate["prior_event_id"]
    if duplicate["detected"] != (prior is not None):
        raise InputError("Journal entry duplicate prior reference is inconsistent.")
    if prior is not None and (not isinstance(prior, str) or not _FINGERPRINT.fullmatch(prior)):
        raise InputError("Journal entry prior_event_id is invalid.")
    if _hash(_event_core(entry)) != entry["event_id"]:
        raise InputError("Journal entry event_id does not match canonical content.")
    return entry


def load_journal(path: str | Path, *, missing_ok: bool = False) -> list[dict[str, Any]] | None:
    journal_path = Path(path)
    if not journal_path.exists():
        if missing_ok:
            return None
        raise InputError(f"Journal '{journal_path}' does not exist.")
    try:
        size = journal_path.stat().st_size
    except OSError as exc:
        raise InputError(f"Could not inspect journal '{journal_path}': {exc}") from exc
    if size > MAX_JOURNAL_BYTES:
        raise InputError(f"Journal exceeds the {MAX_JOURNAL_BYTES}-byte total limit.")
    records: list[dict[str, Any]] = []
    try:
        with journal_path.open("rb") as handle:
            while True:
                raw = handle.readline(MAX_JOURNAL_LINE_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_JOURNAL_LINE_BYTES:
                    raise InputError(
                        f"Journal line exceeds the {MAX_JOURNAL_LINE_BYTES}-byte limit."
                    )
                if not raw.endswith(b"\n"):
                    raise InputError("Journal contains an incomplete final record.")
                try:
                    value = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                    raise InputError("Journal contains an invalid JSONL record.") from exc
                if not isinstance(value, dict):
                    raise InputError("Journal records must be JSON objects.")
                records.append(validate_journal_entry(value))
                if len(records) > MAX_JOURNAL_RECORDS:
                    raise InputError(f"Journal exceeds the {MAX_JOURNAL_RECORDS}-record limit.")
    except OSError as exc:
        raise InputError(f"Could not read journal '{journal_path}': {exc}") from exc
    return records


def _prior_duplicate(
    records: list[dict[str, Any]], request_id: str, at: datetime, window_seconds: int
) -> dict[str, Any] | None:
    earliest = at - timedelta(seconds=window_seconds)
    matches = []
    for record in records:
        _, recorded_at = _timestamp(record["recorded_at"])
        if record["request_id"] == request_id and earliest <= recorded_at <= at:
            matches.append((recorded_at, record))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def _receipt_from_report(report: dict[str, Any]) -> dict[str, Any]:
    validate_report(report)
    receipt = report.get("receipt")
    if not isinstance(receipt, dict):
        raise InputError("Journal input report does not contain a decision receipt.")
    return validate_receipt(receipt)


def journal_entry_from_report(
    report: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    stage: str,
    recorded_at: str | None,
    window_seconds: int,
) -> dict[str, Any]:
    if stage not in JOURNAL_STAGES:
        raise InputError("Journal stage is invalid.")
    window_seconds = _window(window_seconds)
    timestamp, parsed_at = _timestamp(recorded_at)
    receipt = _receipt_from_report(report)
    budget_facts = report.get("budget_facts")
    if budget_facts is None:
        budget_facts = {
            "action_type": "unknown",
            "confirmation": "unknown",
            "impact": None,
            "payload_size_class": "unknown",
            "target_fingerprint": None,
            "tool_fingerprint": None,
        }
    if not isinstance(budget_facts, dict):
        raise InputError("Journal input report budget_facts must be an object.")
    request_id = receipt["request"]["fingerprint"]
    prior = _prior_duplicate(records, request_id, parsed_at, window_seconds)
    entry = {
        "schema_version": 1,
        "kind": "agent_action_audit",
        "request_id": request_id,
        "receipt_fingerprint": receipt["receipt_fingerprint"],
        "stage": stage,
        "verification_state": "unverified",
        "recorded_at": timestamp,
        "decision": receipt["decision"],
        "policy_hash": receipt["policy"]["hash"],
        "evaluator_version": receipt["evaluator"]["version"],
        "rule_ids": sorted({rule["id"] for rule in receipt["rules"]}),
        "budget_facts": dict(budget_facts),
        "duplicate": {
            "detected": prior is not None,
            "window_seconds": window_seconds,
            "prior_event_id": prior["event_id"] if prior else None,
        },
    }
    entry["event_id"] = _hash(_event_core(entry))
    return validate_journal_entry(entry)


def append_journal(
    path: str | Path,
    report: dict[str, Any],
    *,
    stage: str,
    recorded_at: str | None,
    window_seconds: int,
    enabled: bool,
) -> dict[str, Any]:
    if not enabled:
        raise InputError("Journal append requires enabled=True.")
    journal_path = Path(path)
    records = load_journal(journal_path, missing_ok=True) or []
    entry = journal_entry_from_report(
        report,
        records,
        stage=stage,
        recorded_at=recorded_at,
        window_seconds=window_seconds,
    )
    if any(record["event_id"] == entry["event_id"] for record in records):
        raise InputError("Journal already contains this exact event_id.")
    encoded = (canonical_json(entry) + "\n").encode("utf-8")
    if len(encoded) > MAX_JOURNAL_LINE_BYTES:
        raise InputError(f"Journal entry exceeds the {MAX_JOURNAL_LINE_BYTES}-byte line limit.")
    existing_size = journal_path.stat().st_size if journal_path.exists() else 0
    if existing_size + len(encoded) > MAX_JOURNAL_BYTES:
        raise InputError(f"Journal append exceeds the {MAX_JOURNAL_BYTES}-byte total limit.")
    if len(records) >= MAX_JOURNAL_RECORDS:
        raise InputError(f"Journal append exceeds the {MAX_JOURNAL_RECORDS}-record limit.")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(journal_path, flags, 0o600)
        primary_error: OSError | None = None
        try:
            written = os.write(descriptor, encoded)
            if written != len(encoded):
                raise OSError("partial journal append")
            os.fsync(descriptor)
        except OSError as exc:
            primary_error = exc
            raise
        finally:
            try:
                os.close(descriptor)
            except OSError:
                if primary_error is None:
                    raise
    except OSError as exc:
        raise InputError(f"Could not append journal '{journal_path}': {exc}") from exc
    return entry


def replay_check_document(
    report: dict[str, Any],
    journal_path: str | Path,
    *,
    at: str | None,
    window_seconds: int,
) -> dict[str, Any]:
    receipt = _receipt_from_report(report)
    window_seconds = _window(window_seconds)
    records = load_journal(journal_path, missing_ok=True)
    timestamp, parsed_at = _timestamp(at)
    if records is None:
        return {
            "schema_version": 1,
            "kind": "journal_replay_check",
            "source": Path(journal_path).name,
            "status": "source-unavailable",
            "checked_at": timestamp,
            "decision": "warn",
            "risk_level": "medium",
            "subject": "redacted-request-fingerprint",
            "duplicate": False,
            "reasons": [
                {
                    "rule": "journal.source-unavailable",
                    "effect": "warn",
                    "matched": "no-journal",
                    "message": "Duplicate status is unknown because the journal is unavailable.",
                }
            ],
        }
    prior = _prior_duplicate(
        records,
        receipt["request"]["fingerprint"],
        parsed_at,
        window_seconds,
    )
    duplicate = prior is not None
    return {
        "schema_version": 1,
        "kind": "journal_replay_check",
        "source": Path(journal_path).name,
        "status": "duplicate" if duplicate else "clear",
        "checked_at": timestamp,
        "decision": "warn" if duplicate else "allow",
        "risk_level": "medium" if duplicate else "low",
        "subject": "redacted-request-fingerprint",
        "duplicate": duplicate,
        "prior_event_id": prior["event_id"] if prior else None,
        "reasons": (
            [
                {
                    "rule": "journal.duplicate-window",
                    "effect": "warn",
                    "matched": "request-fingerprint",
                    "message": "A matching redacted request occurred inside the replay window.",
                }
            ]
            if duplicate
            else []
        ),
    }


def filter_journal(
    records: list[dict[str, Any]],
    *,
    stage: str | None = None,
    decision: str | None = None,
    duplicate: bool | None = None,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
) -> list[dict[str, Any]]:
    if stage is not None and stage not in JOURNAL_STAGES:
        raise InputError("Journal filter stage is invalid.")
    if decision is not None and decision not in {"allow", "warn", "deny"}:
        raise InputError("Journal filter decision is invalid.")
    from_dt = _timestamp(from_timestamp)[1] if from_timestamp else None
    to_dt = _timestamp(to_timestamp)[1] if to_timestamp else None
    if from_dt and to_dt and from_dt > to_dt:
        raise InputError("Journal --from timestamp cannot be after --to.")
    output = []
    for record in records:
        recorded_at = _timestamp(record["recorded_at"])[1]
        if stage is not None and record["stage"] != stage:
            continue
        if decision is not None and record["decision"] != decision:
            continue
        if duplicate is not None and record["duplicate"]["detected"] != duplicate:
            continue
        if from_dt and recorded_at < from_dt:
            continue
        if to_dt and recorded_at > to_dt:
            continue
        output.append(record)
    return output


def journal_report_document(
    records: list[dict[str, Any]], source: str, filters: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "agent_action_audit_report",
        "source": Path(source).name,
        "filters": filters,
        "summary": {
            "total": len(records),
            "duplicates": sum(record["duplicate"]["detected"] for record in records),
        },
        "records": records,
    }


def journal_html_report(report: dict[str, Any]) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{escape(record['recorded_at'])}</td>"
        f"<td>{escape(record['stage'])}</td>"
        f"<td>{escape(record['decision'])}</td>"
        f"<td>{'yes' if record['duplicate']['detected'] else 'no'}</td>"
        f"<td><code>{escape(record['event_id'])}</code></td>"
        "</tr>"
        for record in report["records"]
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PolicyLatch action journal</title><style>
body{{font:14px system-ui;margin:24px;color:#18212b;background:#f6f8fa}}main{{max-width:980px;margin:auto}}
table{{width:100%;border-collapse:collapse;background:white}}th,td{{padding:8px;border:1px solid #d8dee4;text-align:left}}
code{{overflow-wrap:anywhere}}.muted{{color:#57606a}}@media(prefers-color-scheme:dark){{body{{color:#e6edf3;background:#0d1117}}table{{background:#161b22}}th,td{{border-color:#30363d}}.muted{{color:#8b949e}}}}
</style></head><body><main><h1>Agent action journal</h1>
<p class="muted">Unverified, data-minimized local events. No tool execution is claimed.</p>
<p>Total: {report["summary"]["total"]} · Duplicates: {report["summary"]["duplicates"]}</p>
<table><thead><tr><th>Recorded</th><th>Stage</th><th>Decision</th><th>Duplicate</th><th>Event</th></tr></thead>
<tbody>{rows}</tbody></table></main></body></html>"""
