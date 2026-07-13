from __future__ import annotations

import importlib
from types import ModuleType

from .windows_audit import StateSummary
from .windows_providers import (
    ProviderContractError,
    ProviderReadError,
    UnsupportedPlatformError,
)


def _load_winreg() -> ModuleType:
    try:
        return importlib.import_module("winreg")
    except ImportError as exc:
        raise UnsupportedPlatformError(
            "The Registry key-presence provider requires Windows."
        ) from exc


def _hkcu_subkey(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        raise ProviderContractError("Registry target must be a non-empty string.")
    if "\x00" in target:
        raise ProviderContractError("Registry target cannot contain a null byte.")

    normalized = target.strip().replace("/", "\\")
    hive, separator, subkey = normalized.partition("\\")
    if hive.upper() not in {"HKCU", "HKEY_CURRENT_USER"}:
        raise ProviderContractError("Registry key-presence provider supports HKCU targets only.")
    if not separator or not subkey.strip("\\ "):
        raise ProviderContractError("Registry target must include an HKCU subkey.")
    return subkey.strip("\\")


class RegistryKeyPresenceProvider:
    """Read only whether an HKCU key exists; never query a Registry value."""

    name = "windows_registry_key_presence"
    category = "registry"

    def read_summary(self, target: str) -> StateSummary:
        subkey = _hkcu_subkey(target)
        winreg = _load_winreg()

        try:
            handle = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                subkey,
                0,
                winreg.KEY_READ,
            )
        except FileNotFoundError:
            return StateSummary(present=False)
        except PermissionError as exc:
            raise ProviderReadError(
                "Registry key presence could not be read because access was denied."
            ) from exc
        except OSError as exc:
            raise ProviderReadError(
                "Registry key presence could not be read; absence was not assumed."
            ) from exc

        try:
            winreg.CloseKey(handle)
        except OSError as exc:
            raise ProviderReadError("Registry key handle could not be closed cleanly.") from exc
        return StateSummary(present=True)
