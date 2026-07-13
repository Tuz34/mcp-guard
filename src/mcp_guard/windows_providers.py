from __future__ import annotations

import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, cast

from .windows_audit import WINDOWS_CATEGORIES, StateSummary, WindowsCategory


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
        """Return presence-only state for target without changing the system."""
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
            "state": {
                "present": self.state.present,
                "redacted": self.state.redacted,
            },
        }


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
