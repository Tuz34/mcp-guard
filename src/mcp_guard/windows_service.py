from __future__ import annotations

import ctypes
import re
from ctypes import wintypes
from typing import Protocol

from .windows_audit import SAFE_FACT_VALUES, StateSummary
from .windows_providers import ProviderContractError, ProviderReadError
from .windows_settings import ServiceStartupProvider

_SERVICE_NAME = re.compile(r"^[A-Za-z0-9_. -]{1,256}$")
_SC_MANAGER_CONNECT = 0x0001
_SERVICE_QUERY_STATUS = 0x0004
_SC_STATUS_PROCESS_INFO = 0
_ERROR_ACCESS_DENIED = 5
_ERROR_SERVICE_DOES_NOT_EXIST = 1060


class _ServiceStatusProcess(ctypes.Structure):
    _fields_ = [
        ("service_type", wintypes.DWORD),
        ("current_state", wintypes.DWORD),
        ("controls_accepted", wintypes.DWORD),
        ("win32_exit_code", wintypes.DWORD),
        ("service_specific_exit_code", wintypes.DWORD),
        ("check_point", wintypes.DWORD),
        ("wait_hint", wintypes.DWORD),
        ("process_id", wintypes.DWORD),
        ("service_flags", wintypes.DWORD),
    ]


class ServiceStatusBackend(Protocol):
    def read_runtime_state(self, service_name: str) -> str | None: ...


class _CtypesServiceStatusBackend:
    """Minimal read-only wrapper around the Windows Service Control Manager."""

    def __init__(self) -> None:
        try:
            self._api = ctypes.WinDLL("advapi32", use_last_error=True)
        except (AttributeError, OSError) as exc:
            raise ProviderReadError("Windows Service API is unavailable.") from exc

        self._api.OpenSCManagerW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
        ]
        self._api.OpenSCManagerW.restype = wintypes.HANDLE
        self._api.OpenServiceW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPCWSTR,
            wintypes.DWORD,
        ]
        self._api.OpenServiceW.restype = wintypes.HANDLE
        self._api.QueryServiceStatusEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.POINTER(wintypes.BYTE),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._api.QueryServiceStatusEx.restype = wintypes.BOOL
        self._api.CloseServiceHandle.argtypes = [wintypes.HANDLE]
        self._api.CloseServiceHandle.restype = wintypes.BOOL

    def _last_error(self, message: str) -> None:
        error = ctypes.get_last_error()
        if error == _ERROR_ACCESS_DENIED:
            raise ProviderReadError(f"{message}: access was denied.")
        raise ProviderReadError(f"{message}: Windows error {error}.")

    def read_runtime_state(self, service_name: str) -> str | None:
        manager = self._api.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
        if not manager:
            self._last_error("Service Control Manager could not be opened")

        try:
            service = self._api.OpenServiceW(manager, service_name, _SERVICE_QUERY_STATUS)
            if not service:
                error = ctypes.get_last_error()
                if error == _ERROR_SERVICE_DOES_NOT_EXIST:
                    return None
                self._last_error("Service could not be opened")

            try:
                status = _ServiceStatusProcess()
                needed = wintypes.DWORD()
                buffer = ctypes.cast(
                    ctypes.byref(status),
                    ctypes.POINTER(wintypes.BYTE),
                )
                success = self._api.QueryServiceStatusEx(
                    service,
                    _SC_STATUS_PROCESS_INFO,
                    buffer,
                    ctypes.sizeof(status),
                    ctypes.byref(needed),
                )
                if not success:
                    self._last_error("Service runtime state could not be queried")

                states = {
                    1: "stopped",
                    2: "start_pending",
                    3: "stop_pending",
                    4: "running",
                    5: "continue_pending",
                    6: "pause_pending",
                    7: "paused",
                }
                state = states.get(status.current_state)
                if state is None:
                    raise ProviderReadError("Service returned an undocumented runtime state.")
                return state
            finally:
                if not self._api.CloseServiceHandle(service):
                    self._last_error("Service handle could not be closed")
        finally:
            if not self._api.CloseServiceHandle(manager):
                self._last_error("Service Control Manager handle could not be closed")


def _load_service_backend() -> ServiceStatusBackend:
    return _CtypesServiceStatusBackend()


class ServiceRuntimeProvider:
    """Read one service's normalized runtime state without executing a command."""

    name = "windows_service_runtime"
    category = "service"

    def read_summary(self, target: str) -> StateSummary:
        if not isinstance(target, str) or not _SERVICE_NAME.fullmatch(target):
            raise ProviderContractError("Service target must be a valid Windows service name.")

        state = _load_service_backend().read_runtime_state(target)
        if state is None:
            return StateSummary(present=False)
        if state not in SAFE_FACT_VALUES["runtime_state"]:
            raise ProviderReadError("Service backend returned an unsupported runtime state.")
        return StateSummary(present=True, facts=(("runtime_state", state),))


class ServiceSummaryProvider:
    """Combine runtime and startup facts for one explicitly selected service."""

    name = "windows_service_summary"
    category = "service"

    def read_summary(self, target: str) -> StateSummary:
        runtime = ServiceRuntimeProvider().read_summary(target)
        startup = ServiceStartupProvider().read_summary(target)
        if runtime.present != startup.present:
            raise ProviderReadError(
                "Service runtime and startup providers disagree about target presence."
            )
        if runtime.present is not True:
            return StateSummary(present=runtime.present)
        facts = tuple(sorted((*runtime.facts, *startup.facts)))
        return StateSummary(present=True, facts=facts)
