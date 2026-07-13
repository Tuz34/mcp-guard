from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .validation import InputError
from .windows_audit import (
    VERIFICATION_STATES,
    WINDOWS_CATEGORIES,
    WindowsAuditRecord,
    parse_windows_audit_record,
)

MAX_HISTORY_RECORDS = 10_000
MAX_HISTORY_LINE_BYTES = 1_000_000


class HistoryError(ValueError):
    """Raised when local JSONL history is disabled, invalid, or too large."""


def append_audit_record(
    path: str | Path,
    record: WindowsAuditRecord,
    *,
    enabled: bool,
) -> None:
    """Append one validated summary-only record after explicit opt-in."""

    if enabled is not True:
        raise HistoryError("Audit history is disabled; pass enabled=True explicitly.")

    validated = parse_windows_audit_record(record.to_dict())
    line = json.dumps(validated.to_dict(), ensure_ascii=False, separators=(",", ":"))
    if len(line.encode("utf-8")) > MAX_HISTORY_LINE_BYTES:
        raise HistoryError("Audit history record exceeds the maximum line size.")

    output = Path(path)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
    except OSError as exc:
        raise HistoryError(f"Could not append audit history '{output}': {exc}") from exc


def load_audit_history(
    path: str | Path,
    *,
    max_records: int = MAX_HISTORY_RECORDS,
) -> list[WindowsAuditRecord]:
    """Load and strictly validate a local JSONL audit history."""

    if type(max_records) is not int or max_records < 1:
        raise HistoryError("max_records must be a positive integer.")

    source = Path(path)
    records: list[WindowsAuditRecord] = []
    try:
        with source.open("r", encoding="utf-8") as handle:
            line_number = 0
            while True:
                line = handle.readline(MAX_HISTORY_LINE_BYTES + 1)
                if not line:
                    break
                line_number += 1
                if not line.strip():
                    continue
                if len(line.encode("utf-8")) > MAX_HISTORY_LINE_BYTES:
                    raise HistoryError(f"Audit history line {line_number} is too large.")
                if len(records) >= max_records:
                    raise HistoryError(f"Audit history exceeds {max_records} records.")
                try:
                    payload = json.loads(line)
                    records.append(parse_windows_audit_record(payload))
                except (json.JSONDecodeError, InputError) as exc:
                    raise HistoryError(
                        f"Invalid audit history record at line {line_number}: {exc}"
                    ) from exc
    except OSError as exc:
        raise HistoryError(f"Could not read audit history '{source}': {exc}") from exc
    return records


def _filter_instant(value: str | None, field: str) -> datetime | None:
    if value is None:
        return None
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except (TypeError, ValueError) as exc:
        raise HistoryError(f"{field} must be a valid ISO-8601 datetime.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HistoryError(f"{field} must include a UTC offset or Z suffix.")
    return parsed.astimezone(timezone.utc)


def filter_audit_history(
    records: list[WindowsAuditRecord],
    *,
    category: str | None = None,
    verification_state: str | None = None,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
) -> list[WindowsAuditRecord]:
    """Return a deterministic static view without modifying stored history."""

    normalized_category = category.lower() if isinstance(category, str) else category
    if normalized_category is not None and normalized_category not in WINDOWS_CATEGORIES:
        raise HistoryError("category is not supported.")
    normalized_state = (
        verification_state.lower() if isinstance(verification_state, str) else verification_state
    )
    if normalized_state is not None and normalized_state not in VERIFICATION_STATES:
        raise HistoryError("verification_state is not supported.")

    start = _filter_instant(from_timestamp, "from_timestamp")
    end = _filter_instant(to_timestamp, "to_timestamp")
    if start is not None and end is not None and start > end:
        raise HistoryError("from_timestamp cannot be later than to_timestamp.")

    selected: list[WindowsAuditRecord] = []
    for record in records:
        instant = _filter_instant(record.timestamp, "record.timestamp")
        if normalized_category is not None and record.category != normalized_category:
            continue
        if normalized_state is not None and record.verification_state != normalized_state:
            continue
        if start is not None and instant is not None and instant < start:
            continue
        if end is not None and instant is not None and instant > end:
            continue
        selected.append(record)
    return selected
