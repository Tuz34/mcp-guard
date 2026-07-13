from dataclasses import dataclass

import pytest

from mcp_guard.windows_providers import (
    ProviderContractError,
    ProviderReadError,
    collect_windows_snapshot,
)
from mcp_guard.windows_settings import (
    FirewallProfileProvider,
    LongPathsPolicyProvider,
    ServiceStartupProvider,
)


@dataclass
class SyntheticWinreg:
    value: int | None = 1
    value_type: int = 4
    open_error: Exception | None = None
    query_error: Exception | None = None

    HKEY_LOCAL_MACHINE = object()
    KEY_READ = 0x20019
    REG_DWORD = 4

    def __post_init__(self):
        self.calls = []
        self.handle = object()

    def OpenKey(self, hive, subkey, reserved, access):
        self.calls.append(("OpenKey", hive, subkey, reserved, access))
        if self.open_error:
            raise self.open_error
        return self.handle

    def QueryValueEx(self, handle, value_name):
        self.calls.append(("QueryValueEx", handle, value_name))
        if self.query_error:
            raise self.query_error
        return self.value, self.value_type

    def CloseKey(self, handle):
        self.calls.append(("CloseKey", handle))

    def SetValueEx(self, *args):
        raise AssertionError("Settings providers must never write Registry values")


def _enable(monkeypatch, backend):
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")
    monkeypatch.setattr("mcp_guard.windows_registry_state._load_winreg", lambda: backend)


@pytest.mark.parametrize("target", ["domain", "private", "public"])
def test_firewall_provider_reads_only_allowlisted_profile_dword(monkeypatch, target):
    backend = SyntheticWinreg(value=1)
    _enable(monkeypatch, backend)

    snapshot = collect_windows_snapshot(FirewallProfileProvider(), target, enabled=True)

    assert snapshot.state.to_dict()["facts"] == {"policy_state": "enabled"}
    assert [call[0] for call in backend.calls] == ["OpenKey", "QueryValueEx", "CloseKey"]


def test_long_paths_policy_normalizes_disabled_state(monkeypatch):
    backend = SyntheticWinreg(value=0)
    _enable(monkeypatch, backend)

    snapshot = collect_windows_snapshot(
        LongPathsPolicyProvider(), "long_paths_enabled", enabled=True
    )

    assert snapshot.state.to_dict()["facts"] == {"policy_state": "disabled"}


@pytest.mark.parametrize(
    "value,expected",
    [(0, "boot"), (1, "system"), (2, "automatic"), (3, "manual"), (4, "disabled")],
)
def test_service_startup_provider_normalizes_documented_values(monkeypatch, value, expected):
    backend = SyntheticWinreg(value=value)
    _enable(monkeypatch, backend)

    snapshot = collect_windows_snapshot(
        ServiceStartupProvider(), "SyntheticDemoService", enabled=True
    )

    assert snapshot.state.to_dict()["facts"] == {"startup_type": expected}


def test_missing_allowlisted_policy_value_is_not_configured(monkeypatch):
    backend = SyntheticWinreg(query_error=FileNotFoundError())
    _enable(monkeypatch, backend)

    snapshot = collect_windows_snapshot(
        LongPathsPolicyProvider(), "long_paths_enabled", enabled=True
    )

    assert snapshot.state.to_dict()["facts"] == {"policy_state": "not_configured"}


def test_access_denied_is_not_reported_as_disabled(monkeypatch):
    backend = SyntheticWinreg(query_error=PermissionError())
    _enable(monkeypatch, backend)

    with pytest.raises(ProviderReadError, match="denied"):
        collect_windows_snapshot(FirewallProfileProvider(), "public", enabled=True)


@pytest.mark.parametrize(
    "provider,target",
    [
        (FirewallProfileProvider(), "all"),
        (LongPathsPolicyProvider(), "arbitrary_registry_value"),
        (ServiceStartupProvider(), "Bad\\Service"),
    ],
)
def test_unallowlisted_targets_fail_before_registry_access(monkeypatch, provider, target):
    backend = SyntheticWinreg()
    _enable(monkeypatch, backend)

    with pytest.raises(ProviderContractError):
        collect_windows_snapshot(provider, target, enabled=True)

    assert backend.calls == []


def test_unexpected_policy_dword_fails_closed(monkeypatch):
    backend = SyntheticWinreg(value=7)
    _enable(monkeypatch, backend)

    with pytest.raises(ProviderReadError, match="must be 0 or 1"):
        collect_windows_snapshot(FirewallProfileProvider(), "domain", enabled=True)
