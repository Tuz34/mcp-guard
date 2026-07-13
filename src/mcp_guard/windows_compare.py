from __future__ import annotations

from datetime import datetime, timezone

from .windows_audit import ChangeKind, StateSummary, WindowsAuditRecord
from .windows_providers import ObservedWindowsSnapshot


class ComparisonError(ValueError):
    """Raised when snapshots cannot support a trustworthy comparison."""


def _instant(value: str, field: str) -> datetime:
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ComparisonError(f"{field} must be a valid ISO-8601 datetime.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ComparisonError(f"{field} must include a UTC offset or Z suffix.")
    return parsed.astimezone(timezone.utc)


def _summary_change(before: StateSummary, after: StateSummary) -> ChangeKind:
    if before.present is None or after.present is None:
        return "unknown"
    if before.present is False and after.present is True:
        return "created"
    if before.present is True and after.present is False:
        return "deleted"
    if before.present is False and after.present is False:
        return "unchanged"

    before_facts = dict(before.facts)
    after_facts = dict(after.facts)
    if before_facts.keys() != after_facts.keys():
        return "unknown"
    if before_facts != after_facts:
        return "updated"
    return "unchanged"


def compare_windows_snapshots(
    before: ObservedWindowsSnapshot,
    after: ObservedWindowsSnapshot,
    *,
    proposed: WindowsAuditRecord | None = None,
) -> WindowsAuditRecord:
    """Compare presence-only snapshots without inferring hidden value changes."""

    if before.category != after.category:
        raise ComparisonError("Snapshots must have the same category.")
    if before.target != after.target:
        raise ComparisonError("Snapshots must have the same target.")
    if before.state.redacted is not True or after.state.redacted is not True:
        raise ComparisonError("Snapshots must contain redacted summaries only.")

    before_time = _instant(before.collected_at, "before.collected_at")
    after_time = _instant(after.collected_at, "after.collected_at")
    if after_time < before_time:
        raise ComparisonError("The after snapshot cannot be older than the before snapshot.")

    if proposed is not None:
        if proposed.verification_state != "proposed":
            raise ComparisonError("The optional intent record must have proposed state.")
        if proposed.category != after.category or proposed.target != after.target:
            raise ComparisonError("The proposed intent must match snapshot category and target.")

    change = _summary_change(before.state, after.state)
    verification_state = "verified" if change != "unknown" else "observed"
    timestamp = after_time.isoformat().replace("+00:00", "Z")

    return WindowsAuditRecord(
        timestamp=timestamp,
        verification_state=verification_state,
        source=f"snapshot_comparison:{before.source}->{after.source}",
        category=after.category,
        target=after.target,
        operation=proposed.operation if proposed else "compare_presence",
        change=change,
        before=StateSummary(present=before.state.present, facts=before.state.facts),
        after=StateSummary(present=after.state.present, facts=after.state.facts),
        actor=proposed.actor if proposed else None,
        tool=proposed.tool if proposed else None,
    )
