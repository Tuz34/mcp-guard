import io
import json
import sys
import threading
from pathlib import Path

import pytest

from policylatch.approval import (
    TerminalApprovalProvider,
    build_approval_request,
    parse_approval_response,
)
from policylatch.gateway import evaluate_mcp_request
from policylatch.policy import load_policy
from policylatch.receipts import canonical_policy_hash
from policylatch.runtime_gateway import UpstreamConfig, upstream_identity
from policylatch.validation import InputError

ROOT = Path(__file__).parents[1]
POLICY = load_policy(ROOT / "examples/policies/gateway-strict.yaml")


def config():
    return UpstreamConfig(
        server_id="synthetic-approval",
        argv=(sys.executable, str(ROOT / "tests/fixtures/fake_mcp_server.py")),
        cwd=str(ROOT),
    )


def warned_request(marker="SYNTHETIC_PRIVATE_APPROVAL_TARGET"):
    return {
        "jsonrpc": "2.0",
        "id": "approval-id",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "safe", "unknown": marker},
        },
    }


def approval_for(request=None, timeout=10):
    request = request or warned_request()
    return build_approval_request(
        request,
        evaluate_mcp_request(request, POLICY),
        upstream_fingerprint=upstream_identity(config()),
        policy_hash=canonical_policy_hash(POLICY),
        timeout_seconds=timeout,
    )


def test_approval_request_is_data_minimized_and_value_bound():
    marker = "SYNTHETIC_PRIVATE_APPROVAL_TARGET"
    first = approval_for(warned_request(marker))
    changed = approval_for(warned_request(marker + "-changed"))
    serialized = json.dumps(first.document)

    assert marker not in serialized
    assert "read_file" not in serialized
    assert first.scope_fingerprint != changed.scope_fingerprint
    assert first.document["scope"]["capabilities"] == ["file", "unclassified"]


def test_response_requires_exact_pending_fingerprint_and_bounded_grant():
    response = {
        "schema_version": 1,
        "kind": "approval_response",
        "request_fingerprint": "sha256:" + "0" * 64,
        "decision": "approve",
        "grant": None,
    }
    with pytest.raises(InputError, match="pending"):
        parse_approval_response(response, expected_request_fingerprint="sha256:" + "1" * 64)

    response["request_fingerprint"] = "sha256:" + "1" * 64
    response["grant"] = {"ttl_seconds": 301, "max_uses": 1}
    with pytest.raises(InputError, match="bounded"):
        parse_approval_response(
            response, expected_request_fingerprint=response["request_fingerprint"]
        )


def test_terminal_defaults_closed_and_accepts_one_explicit_approval():
    approval = approval_for()
    closed = TerminalApprovalProvider(None, io.StringIO(), timeout_seconds=1)
    assert closed.authorize(approval).approved is False

    output = io.StringIO()
    provider = TerminalApprovalProvider(io.StringIO("approve\n"), output, timeout_seconds=1)
    outcome = provider.authorize(approval)
    assert outcome.approved is True
    assert outcome.source == "explicit-approval"
    assert approval.request_fingerprint in output.getvalue()


def test_terminal_timeout_is_deny_and_closes_future_prompts():
    class BlockingInput:
        def readline(self, _limit):
            threading.Event().wait()

    provider = TerminalApprovalProvider(BlockingInput(), io.StringIO(), timeout_seconds=0.05)
    first = provider.authorize(approval_for())
    second = provider.authorize(approval_for())

    assert first.approved is False
    assert first.source == "timeout-or-closed"
    assert second.source == "closed-input"


def test_session_grant_has_deterministic_ttl_and_use_count():
    now = [100.0]
    provider = TerminalApprovalProvider(
        io.StringIO("grant 5 2\n"),
        io.StringIO(),
        timeout_seconds=1,
        clock=lambda: now[0],
    )
    approval = approval_for()

    assert provider.authorize(approval).source == "explicit-approval"
    assert provider.authorize(approval).source == "session-grant"
    assert provider.authorize(approval).source == "session-grant"
    assert provider.authorize(approval).approved is False

    second = TerminalApprovalProvider(
        io.StringIO("grant 5 2\n"),
        io.StringIO(),
        timeout_seconds=1,
        clock=lambda: now[0],
    )
    assert second.authorize(approval).approved is True
    now[0] = 105.0
    assert second.authorize(approval).approved is False
