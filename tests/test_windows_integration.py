"""Opt-in, read-only integration checks for the Windows CI runner.

These tests never run during the default local suite. They query only fixed,
non-secret Windows surfaces and do not mutate system state.
"""

import os
import platform

import pytest

from mcp_guard.windows_audit import SAFE_FACT_VALUES
from mcp_guard.windows_providers import collect_windows_snapshot
from mcp_guard.windows_registry import RegistryKeyPresenceProvider
from mcp_guard.windows_service import ServiceRuntimeProvider
from mcp_guard.windows_settings import FirewallProfileProvider, LongPathsPolicyProvider

pytestmark = pytest.mark.skipif(
    platform.system() != "Windows" or os.getenv("MCP_GUARD_WINDOWS_INTEGRATION") != "1",
    reason="requires explicit opt-in on a Windows CI runner",
)


def test_real_eventlog_service_runtime_query_is_summary_only():
    snapshot = collect_windows_snapshot(ServiceRuntimeProvider(), "EventLog", enabled=True)

    assert snapshot.state.present is True
    facts = dict(snapshot.state.facts)
    assert facts["runtime_state"] in SAFE_FACT_VALUES["runtime_state"]
    assert snapshot.state.redacted is True


def test_real_hkcu_key_presence_query_returns_no_values():
    snapshot = collect_windows_snapshot(
        RegistryKeyPresenceProvider(),
        r"HKCU\Control Panel\Desktop",
        enabled=True,
    )

    assert snapshot.state.present is True
    assert snapshot.state.facts == ()
    assert snapshot.state.redacted is True


@pytest.mark.parametrize(
    "provider,target",
    [
        (LongPathsPolicyProvider(), "long_paths_enabled"),
        (FirewallProfileProvider(), "public"),
    ],
)
def test_real_allowlisted_hklm_queries_return_normalized_summaries(provider, target):
    snapshot = collect_windows_snapshot(provider, target, enabled=True)

    assert snapshot.state.present in {True, False}
    assert snapshot.state.redacted is True
    facts = dict(snapshot.state.facts)
    if facts:
        assert facts["policy_state"] in SAFE_FACT_VALUES["policy_state"]
