from __future__ import annotations

import re

from .windows_audit import StateSummary
from .windows_providers import ProviderContractError, ProviderReadError
from .windows_registry_state import (
    RegistryDwordRead,
    hklm_value_exists,
    read_allowlisted_hklm_dword,
)

_FIREWALL_KEYS = {
    "domain": (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
        r"\FirewallPolicy\DomainProfile"
    ),
    "private": (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
        r"\FirewallPolicy\StandardProfile"
    ),
    "public": (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
        r"\FirewallPolicy\PublicProfile"
    ),
}
_LONG_PATHS_KEY = r"SYSTEM\CurrentControlSet\Control\FileSystem"
_FIREWALL_RULES_KEY = (
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
    r"\FirewallPolicy\FirewallRules"
)
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9_. -]{1,256}$")
_FIREWALL_RULE_ID = re.compile(r"^[A-Za-z0-9{}_. -]{1,256}$")


def _policy_summary(result: RegistryDwordRead) -> StateSummary:
    if not result.key_present:
        return StateSummary(present=False)
    if not result.value_present:
        return StateSummary(present=True, facts=(("policy_state", "not_configured"),))
    if result.value not in {0, 1}:
        raise ProviderReadError("Allowlisted policy DWORD must be 0 or 1.")
    state = "enabled" if result.value == 1 else "disabled"
    return StateSummary(present=True, facts=(("policy_state", state),))


class FirewallProfileProvider:
    """Read one allowlisted Windows Firewall profile enablement DWORD."""

    name = "windows_firewall_profile"
    category = "firewall"

    def read_summary(self, target: str) -> StateSummary:
        normalized = target.strip().lower() if isinstance(target, str) else ""
        if normalized not in _FIREWALL_KEYS:
            choices = ", ".join(sorted(_FIREWALL_KEYS))
            raise ProviderContractError(f"Firewall target must be one of: {choices}.")
        return _policy_summary(
            read_allowlisted_hklm_dword(_FIREWALL_KEYS[normalized], "EnableFirewall")
        )


class FirewallRulePresenceProvider:
    """Check one explicitly named firewall rule value without returning its content."""

    name = "windows_firewall_rule_presence"
    category = "firewall"

    def read_summary(self, target: str) -> StateSummary:
        if not isinstance(target, str) or not _FIREWALL_RULE_ID.fullmatch(target):
            raise ProviderContractError("Firewall rule target must be a valid rule ID.")
        return StateSummary(present=hklm_value_exists(_FIREWALL_RULES_KEY, target))


class LongPathsPolicyProvider:
    """Read only the allowlisted Windows long-path policy DWORD."""

    name = "windows_long_paths_policy"
    category = "policy"

    def read_summary(self, target: str) -> StateSummary:
        normalized = target.strip().lower() if isinstance(target, str) else ""
        if normalized != "long_paths_enabled":
            raise ProviderContractError("Policy target must be 'long_paths_enabled'.")
        return _policy_summary(read_allowlisted_hklm_dword(_LONG_PATHS_KEY, "LongPathsEnabled"))


class ServiceStartupProvider:
    """Read one service's allowlisted Start DWORD and normalize the startup type."""

    name = "windows_service_startup"
    category = "service"

    def read_summary(self, target: str) -> StateSummary:
        if not isinstance(target, str) or not _SERVICE_NAME.fullmatch(target):
            raise ProviderContractError("Service target must be a valid Windows service name.")

        result = read_allowlisted_hklm_dword(
            rf"SYSTEM\CurrentControlSet\Services\{target}",
            "Start",
        )
        if not result.key_present:
            return StateSummary(present=False)
        if not result.value_present:
            raise ProviderReadError("Service exists but has no readable startup type.")
        startup_types = {
            0: "boot",
            1: "system",
            2: "automatic",
            3: "manual",
            4: "disabled",
        }
        startup_type = startup_types.get(result.value)
        if startup_type is None:
            raise ProviderReadError("Service startup type is outside the documented range.")
        return StateSummary(present=True, facts=(("startup_type", startup_type),))
