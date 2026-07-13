from dataclasses import dataclass

import pytest

from mcp_guard.validation import InputError
from mcp_guard.windows_audit import StateSummary
from mcp_guard.windows_providers import (
    ProviderContractError,
    ProviderNotEnabledError,
    UnsupportedPlatformError,
    collect_windows_snapshot,
    parse_observed_windows_snapshot,
)


@dataclass
class SyntheticProvider:
    name: str = "synthetic_service_provider"
    category: str = "service"
    calls: int = 0
    summary: object = StateSummary(present=True)

    def read_summary(self, target: str) -> object:
        self.calls += 1
        return self.summary


def test_disabled_collection_touches_neither_platform_nor_provider(monkeypatch):
    provider = SyntheticProvider()
    platform_calls = 0

    def unexpected_platform_probe():
        nonlocal platform_calls
        platform_calls += 1
        return "Windows"

    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", unexpected_platform_probe)

    with pytest.raises(ProviderNotEnabledError, match="enabled=True"):
        collect_windows_snapshot(provider, "SyntheticDemoService", enabled=False)

    assert platform_calls == 0
    assert provider.calls == 0


def test_unsupported_platform_does_not_call_provider(monkeypatch):
    provider = SyntheticProvider()
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Linux")

    with pytest.raises(UnsupportedPlatformError, match="unsupported on 'Linux'"):
        collect_windows_snapshot(provider, "SyntheticDemoService", enabled=True)

    assert provider.calls == 0


def test_explicit_windows_collection_returns_observed_summary(monkeypatch):
    provider = SyntheticProvider()
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")

    snapshot = collect_windows_snapshot(provider, "SyntheticDemoService", enabled=True).to_dict()

    assert provider.calls == 1
    assert snapshot["verification_state"] == "observed"
    assert snapshot["source"] == "synthetic_service_provider"
    assert snapshot["state"] == {"present": True, "redacted": True}


def test_provider_cannot_claim_verified_state(monkeypatch):
    provider = SyntheticProvider()
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")

    snapshot = collect_windows_snapshot(provider, "SyntheticDemoService", enabled=True)

    assert snapshot.verification_state == "observed"


def test_rejects_non_redacted_provider_result(monkeypatch):
    provider = SyntheticProvider(summary=StateSummary(present=True, redacted=False))
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")

    with pytest.raises(ProviderContractError, match="redacted StateSummary"):
        collect_windows_snapshot(provider, "SyntheticDemoService", enabled=True)


@pytest.mark.parametrize(
    "facts",
    [
        (("raw_state", "must-not-escape"),),
        (("policy_state", "free-form-secret"),),
    ],
)
def test_collector_revalidates_third_party_provider_facts(monkeypatch, facts):
    provider = SyntheticProvider(summary=StateSummary(present=True, facts=facts))
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")

    with pytest.raises(ProviderContractError, match="invalid summary"):
        collect_windows_snapshot(provider, "SyntheticDemoService", enabled=True)


def test_rejects_unknown_provider_category_before_provider_call(monkeypatch):
    provider = SyntheticProvider(category="everything")
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")

    with pytest.raises(ProviderContractError, match="Provider category"):
        collect_windows_snapshot(provider, "SyntheticDemoService", enabled=True)

    assert provider.calls == 0


def test_rejects_empty_target_before_provider_call(monkeypatch):
    provider = SyntheticProvider()
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")

    with pytest.raises(ProviderContractError, match="target"):
        collect_windows_snapshot(provider, "  ", enabled=True)

    assert provider.calls == 0


def test_observed_snapshot_round_trips_through_strict_parser(monkeypatch):
    provider = SyntheticProvider(
        summary=StateSummary(
            present=True,
            facts=(("runtime_state", "running"),),
        )
    )
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")
    snapshot = collect_windows_snapshot(provider, "SyntheticDemoService", enabled=True)

    loaded = parse_observed_windows_snapshot(snapshot.to_dict())

    assert loaded == snapshot


def test_saved_snapshot_cannot_claim_verified_state(monkeypatch):
    provider = SyntheticProvider()
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")
    payload = collect_windows_snapshot(provider, "SyntheticDemoService", enabled=True).to_dict()
    payload["verification_state"] = "verified"

    with pytest.raises(InputError, match="must have observed"):
        parse_observed_windows_snapshot(payload)
