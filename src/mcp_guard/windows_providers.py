from __future__ import annotations

import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, cast

from .validation import InputError
from .windows_audit import (
    WINDOWS_CATEGORIES,
    StateSummary,
    WindowsCategory,
    parse_windows_setting_action,
)

_ALLOWED_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "collected_at",
        "verification_state",
        "source",
        "category",
        "target",
        "state",
    }
)


class WindowsProviderError(RuntimeError):
    """Base error for the explicit Windows snapshot provider boundary."""


class ProviderNotEnabledError(WindowsProviderError):
    """Raised before any platform or provider access when opt-in is absent."""


class UnsupportedPlatformError(WindowsProviderError):
    """Raised when an enabled Windows provider is requested elsewhere."""


class ProviderContractError(WindowsProviderError):
    """Raised when a provider violates the summary-only contract."""


class ProviderReadError(WindowsProviderError):
    """Raised when a read-only provider cannot produce a trustworthy summary."""


class WindowsSnapshotProvider(Protocol):
    """Interface for a future, explicitly invoked read-only Windows adapter."""

    name: str
    category: WindowsCategory

    def read_summary(self, target: str) -> StateSummary:
        """Return a redacted summary for target without changing the system."""
        ...


@dataclass(frozen=True)
class ObservedWindowsSnapshot:
    """One provider observation; never equivalent to independent verification."""

    collected_at: str
    source: str
    category: WindowsCategory
    target: str
    state: StateSummary
    schema_version: int = 1
    kind: str = "windows_snapshot"
    verification_state: Literal["observed"] = "observed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "collected_at": self.collected_at,
            "verification_state": self.verification_state,
            "source": self.source,
            "category": self.category,
            "target": self.target,
            "state": self.state.to_dict(),
        }


def parse_observed_windows_snapshot(data: dict[str, Any]) -> ObservedWindowsSnapshot:
    """Strictly validate a saved summary-only provider snapshot."""

    if not isinstance(data, dict):
        raise InputError("Windows snapshot must be an object.")
    unknown = set(data) - _ALLOWED_SNAPSHOT_FIELDS
    if unknown:
        names = ", ".join(sorted(unknown))
        raise InputError(f"Unknown Windows snapshot fields: {names}.")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise InputError("Windows snapshot schema_version must be 1.")
    if data.get("kind") != "windows_snapshot":
        raise InputError("Windows snapshot kind must be 'windows_snapshot'.")
    if data.get("verification_state") != "observed":
        raise InputError("Provider snapshots must have observed verification state.")

    record = parse_windows_setting_action(
        {
            "action_type": "windows_setting",
            "timestamp": data.get("collected_at"),
            "verification_state": "observed",
            "source": data.get("source"),
            "category": data.get("category"),
            "target": data.get("target"),
            "operation": "collect_snapshot",
            "change": "unknown",
            "before": {"present": None},
            "after": data.get("state"),
        }
    )
    return ObservedWindowsSnapshot(
        collected_at=record.timestamp,
        source=record.source,
        category=record.category,
        target=record.target,
        state=record.after,
    )


def _provider_text(provider: WindowsSnapshotProvider, field: str) -> str:
    value = getattr(provider, field, None)
    if not isinstance(value, str) or not value.strip():
        raise ProviderContractError(f"Provider {field} must be a non-empty string.")
    return value.strip()


def collect_windows_snapshot(
    provider: WindowsSnapshotProvider,
    target: str,
    *,
    enabled: bool,
) -> ObservedWindowsSnapshot:
    """Call a provider only after explicit opt-in and a Windows platform check."""

    if enabled is not True:
        raise ProviderNotEnabledError(
            "Windows snapshot collection is disabled; pass enabled=True explicitly."
        )

    current_platform = platform.system()
    if current_platform.casefold() != "windows":
        raise UnsupportedPlatformError(
            f"Windows snapshot providers are unsupported on '{current_platform or 'unknown'}'."
        )

    if not isinstance(target, str) or not target.strip():
        raise ProviderContractError("Snapshot target must be a non-empty string.")

    source = _provider_text(provider, "name")
    category = _provider_text(provider, "category").lower()
    if category not in WINDOWS_CATEGORIES:
        choices = ", ".join(sorted(WINDOWS_CATEGORIES))
        raise ProviderContractError(f"Provider category must be one of: {choices}.")

    summary = provider.read_summary(target.strip())
    if not isinstance(summary, StateSummary) or summary.redacted is not True:
        raise ProviderContractError(
            "Provider must return a redacted StateSummary without raw values."
        )

    collected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return ObservedWindowsSnapshot(
        collected_at=collected_at,
        source=source,
        category=cast(WindowsCategory, category),
        target=target.strip(),
        state=summary,
    )
