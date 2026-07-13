from __future__ import annotations

import importlib
from dataclasses import dataclass
from types import ModuleType

from .windows_providers import ProviderReadError, UnsupportedPlatformError


@dataclass(frozen=True)
class RegistryDwordRead:
    key_present: bool
    value_present: bool
    value: int | None = None


def _load_winreg() -> ModuleType:
    try:
        return importlib.import_module("winreg")
    except ImportError as exc:
        raise UnsupportedPlatformError("Windows Registry state providers require Windows.") from exc


def read_allowlisted_hklm_dword(subkey: str, value_name: str) -> RegistryDwordRead:
    """Read one provider-owned DWORD target and return no raw output document."""

    winreg = _load_winreg()
    access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    try:
        handle = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            subkey,
            0,
            access,
        )
    except FileNotFoundError:
        return RegistryDwordRead(key_present=False, value_present=False)
    except PermissionError as exc:
        raise ProviderReadError("Allowlisted Registry state read was denied.") from exc
    except OSError as exc:
        raise ProviderReadError("Allowlisted Registry key could not be opened.") from exc

    try:
        try:
            value, value_type = winreg.QueryValueEx(handle, value_name)
        except FileNotFoundError:
            return RegistryDwordRead(key_present=True, value_present=False)
        except PermissionError as exc:
            raise ProviderReadError("Allowlisted Registry value read was denied.") from exc
        except OSError as exc:
            raise ProviderReadError("Allowlisted Registry value could not be read.") from exc

        if value_type != winreg.REG_DWORD or type(value) is not int:
            raise ProviderReadError("Allowlisted Registry value is not a DWORD.")
        return RegistryDwordRead(key_present=True, value_present=True, value=value)
    finally:
        try:
            winreg.CloseKey(handle)
        except OSError as exc:
            raise ProviderReadError("Registry state handle could not be closed cleanly.") from exc
