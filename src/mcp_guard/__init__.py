"""Compatibility imports for the former ``mcp_guard`` package name.

New code should import :mod:`policylatch`. This alias package is intentionally
small and will remain for the documented transition window.
"""

from __future__ import annotations

import sys
from importlib import import_module

from policylatch import __version__

_MODULES = (
    "adapters",
    "cli",
    "environment",
    "evaluator",
    "gateway",
    "gateway_trace",
    "html_report",
    "matching",
    "models",
    "policy",
    "policy_draft",
    "policy_tooling",
    "profiles",
    "receipts",
    "reports",
    "sarif_report",
    "schemas",
    "scanners",
    "tool_policy",
    "validation",
    "windows_audit",
    "windows_compare",
    "windows_history",
    "windows_history_report",
    "windows_providers",
    "windows_registry",
    "windows_registry_state",
    "windows_service",
    "windows_settings",
)

for _name in _MODULES:
    _module = import_module(f"policylatch.{_name}")
    sys.modules[f"{__name__}.{_name}"] = _module
    globals()[_name] = _module

__all__ = ["__version__"]
