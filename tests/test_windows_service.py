import platform
from dataclasses import dataclass

import pytest

from mcp_guard.windows_audit import StateSummary
from mcp_guard.windows_providers import (
    ProviderContractError,
    ProviderReadError,
    collect_windows_snapshot,
)
from mcp_guard.windows_service import (
    ServiceRuntimeProvider,
    ServiceSummaryProvider,
    _CtypesServiceStatusBackend,
)


@dataclass
class SyntheticServiceBackend:
    state: str | None = "running"
    error: Exception | None = None
    calls: int = 0

    def read_runtime_state(self, service_name: str) -> str | None:
        self.calls += 1
        if self.error:
            raise self.error
        return self.state


def _enable(monkeypatch, backend):
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")
    monkeypatch.setattr("mcp_guard.windows_service._load_service_backend", lambda: backend)


@pytest.mark.parametrize(
    "state",
    [
        "stopped",
        "start_pending",
        "stop_pending",
        "running",
        "continue_pending",
        "pause_pending",
        "paused",
    ],
)
def test_service_runtime_provider_returns_only_normalized_state(monkeypatch, state):
    backend = SyntheticServiceBackend(state=state)
    _enable(monkeypatch, backend)

    snapshot = collect_windows_snapshot(
        ServiceRuntimeProvider(), "SyntheticDemoService", enabled=True
    )

    assert snapshot.state.to_dict()["facts"] == {"runtime_state": state}
    assert backend.calls == 1


def test_missing_service_returns_presence_false(monkeypatch):
    backend = SyntheticServiceBackend(state=None)
    _enable(monkeypatch, backend)

    snapshot = collect_windows_snapshot(
        ServiceRuntimeProvider(), "SyntheticMissingService", enabled=True
    )

    assert snapshot.state.present is False


def test_backend_access_denied_is_not_reported_as_stopped(monkeypatch):
    backend = SyntheticServiceBackend(error=ProviderReadError("access was denied"))
    _enable(monkeypatch, backend)

    with pytest.raises(ProviderReadError, match="access was denied"):
        collect_windows_snapshot(ServiceRuntimeProvider(), "SyntheticDemoService", enabled=True)


def test_invalid_service_name_fails_before_backend_load(monkeypatch):
    backend = SyntheticServiceBackend()
    _enable(monkeypatch, backend)

    with pytest.raises(ProviderContractError):
        collect_windows_snapshot(ServiceRuntimeProvider(), "Bad\\Service", enabled=True)

    assert backend.calls == 0


def test_undocumented_backend_state_fails_closed(monkeypatch):
    backend = SyntheticServiceBackend(state="mystery")
    _enable(monkeypatch, backend)

    with pytest.raises(ProviderReadError, match="unsupported runtime state"):
        collect_windows_snapshot(ServiceRuntimeProvider(), "SyntheticDemoService", enabled=True)


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows API binding check")
def test_windows_service_api_bindings_load_without_querying_a_service():
    backend = _CtypesServiceStatusBackend()

    assert backend is not None


def test_service_summary_combines_runtime_and_startup_facts(monkeypatch):
    monkeypatch.setattr(
        "mcp_guard.windows_service.ServiceRuntimeProvider.read_summary",
        lambda self, target: StateSummary(present=True, facts=(("runtime_state", "running"),)),
    )
    monkeypatch.setattr(
        "mcp_guard.windows_service.ServiceStartupProvider.read_summary",
        lambda self, target: StateSummary(present=True, facts=(("startup_type", "automatic"),)),
    )

    summary = ServiceSummaryProvider().read_summary("SyntheticDemoService")

    assert summary.to_dict()["facts"] == {
        "runtime_state": "running",
        "startup_type": "automatic",
    }


def test_service_summary_fails_closed_on_presence_disagreement(monkeypatch):
    monkeypatch.setattr(
        "mcp_guard.windows_service.ServiceRuntimeProvider.read_summary",
        lambda self, target: StateSummary(present=False),
    )
    monkeypatch.setattr(
        "mcp_guard.windows_service.ServiceStartupProvider.read_summary",
        lambda self, target: StateSummary(present=True, facts=(("startup_type", "automatic"),)),
    )

    with pytest.raises(ProviderReadError, match="disagree"):
        ServiceSummaryProvider().read_summary("SyntheticDemoService")
