from __future__ import annotations

import importlib
import sys
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
        read_failed = sys.exc_info()[0] is not None
        try:
            winreg.CloseKey(handle)
        except OSError as exc:
            if not read_failed:
                raise ProviderReadError(
                    "Registry state handle could not be closed cleanly."
                ) from exc


def hklm_value_exists(subkey: str, value_name: str) -> bool:
    """Check one value name under a provider-owned HKLM key without returning content."""

    winreg = _load_winreg()
    access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    try:
        handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, access)
    except FileNotFoundError:
        return False
    except PermissionError as exc:
        raise ProviderReadError("Allowlisted Registry key presence read was denied.") from exc
    except OSError as exc:
        raise ProviderReadError("Allowlisted Registry key presence could not be read.") from exc

    try:
        try:
            winreg.QueryValueEx(handle, value_name)
            return True
        except FileNotFoundError:
            return False
        except PermissionError as exc:
            raise ProviderReadError("Allowlisted Registry value presence read was denied.") from exc
        except OSError as exc:
            raise ProviderReadError(
                "Allowlisted Registry value presence could not be read."
            ) from exc
    finally:
        read_failed = sys.exc_info()[0] is not None
        try:
            winreg.CloseKey(handle)
        except OSError as exc:
            if not read_failed:
                raise ProviderReadError(
                    "Registry presence handle could not be closed cleanly."
                ) from exc
