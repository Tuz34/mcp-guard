import pytest

from mcp_guard.windows_providers import (
    ProviderContractError,
    ProviderReadError,
    collect_windows_snapshot,
)
from mcp_guard.windows_registry import RegistryKeyPresenceProvider


class SyntheticWinreg:
    HKEY_CURRENT_USER = object()
    KEY_READ = 0x20019

    def __init__(self, *, exists=True, error=None):
        self.exists = exists
        self.error = error
        self.calls = []
        self.handle = object()

    def OpenKey(self, hive, subkey, reserved, access):
        self.calls.append(("OpenKey", hive, subkey, reserved, access))
        if self.error is not None:
            raise self.error
        if not self.exists:
            raise FileNotFoundError
        return self.handle

    def CloseKey(self, handle):
        self.calls.append(("CloseKey", handle))

    def QueryValueEx(self, *args):
        raise AssertionError("Registry values must never be queried")

    def SetValueEx(self, *args):
        raise AssertionError("Registry values must never be written")


def _enable_windows(monkeypatch, backend):
    monkeypatch.setattr("mcp_guard.windows_providers.platform.system", lambda: "Windows")
    monkeypatch.setattr("mcp_guard.windows_registry._load_winreg", lambda: backend)


def test_reports_existing_hkcu_key_without_reading_values(monkeypatch):
    backend = SyntheticWinreg(exists=True)
    _enable_windows(monkeypatch, backend)

    snapshot = collect_windows_snapshot(
        RegistryKeyPresenceProvider(),
        "HKCU\\Software\\SyntheticDemo",
        enabled=True,
    ).to_dict()

    assert snapshot["state"] == {"present": True, "redacted": True}
    assert [call[0] for call in backend.calls] == ["OpenKey", "CloseKey"]


def test_reports_missing_hkcu_key_without_assuming_an_error(monkeypatch):
    backend = SyntheticWinreg(exists=False)
    _enable_windows(monkeypatch, backend)

    snapshot = collect_windows_snapshot(
        RegistryKeyPresenceProvider(),
        "HKEY_CURRENT_USER/Software/SyntheticDemo",
        enabled=True,
    )

    assert snapshot.state.present is False
    assert [call[0] for call in backend.calls] == ["OpenKey"]


@pytest.mark.parametrize("target", ["HKLM\\Software\\Demo", "HKCU", "HKCU\\", ""])
def test_rejects_targets_outside_narrow_hkcu_key_scope(monkeypatch, target):
    backend = SyntheticWinreg()
    _enable_windows(monkeypatch, backend)

    with pytest.raises(ProviderContractError):
        collect_windows_snapshot(
            RegistryKeyPresenceProvider(),
            target,
            enabled=True,
        )

    assert backend.calls == []


def test_access_denied_is_not_misreported_as_missing(monkeypatch):
    backend = SyntheticWinreg(error=PermissionError())
    _enable_windows(monkeypatch, backend)

    with pytest.raises(ProviderReadError, match="access was denied"):
        collect_windows_snapshot(
            RegistryKeyPresenceProvider(),
            "HKCU\\Software\\SyntheticDemo",
            enabled=True,
        )


def test_unexpected_os_error_is_not_misreported_as_missing(monkeypatch):
    backend = SyntheticWinreg(error=OSError("synthetic failure"))
    _enable_windows(monkeypatch, backend)

    with pytest.raises(ProviderReadError, match="absence was not assumed"):
        collect_windows_snapshot(
            RegistryKeyPresenceProvider(),
            "HKCU\\Software\\SyntheticDemo",
            enabled=True,
        )
