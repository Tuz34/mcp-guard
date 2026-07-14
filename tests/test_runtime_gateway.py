import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from policylatch.approval import TerminalApprovalProvider
from policylatch.policy import load_policy
from policylatch.runtime_gateway import (
    RuntimeGatewayError,
    UpstreamConfig,
    parse_upstream_config,
    run_stdio_gateway,
)

ROOT = Path(__file__).parents[1]
FAKE_SERVER = ROOT / "tests/fixtures/fake_mcp_server.py"
POLICY = load_policy(ROOT / "examples/policies/gateway-strict.yaml")


def line(message):
    return (json.dumps(message, separators=(",", ":")) + "\n").encode()


def initialize_messages(*requests):
    messages = [
        {
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "synthetic-tests", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        *requests,
    ]
    return io.BytesIO(b"".join(line(message) for message in messages))


def call(request_id, name, arguments):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def config(*extra_argv):
    return UpstreamConfig(
        server_id="synthetic-fake",
        argv=(sys.executable, str(FAKE_SERVER), *extra_argv),
        cwd=str(ROOT),
    )


def run_session(client_input, timeout=2, approval_provider=None, upstream_config=None):
    output = io.BytesIO()
    summary = run_stdio_gateway(
        client_input,
        output,
        POLICY,
        upstream_config or config(),
        timeout_seconds=timeout,
        enabled=True,
        approval_provider=approval_provider,
    )
    payloads = [json.loads(row) for row in output.getvalue().splitlines()]
    return summary, payloads


def test_allow_forwards_after_lifecycle_and_child_is_cleaned_up():
    marker = "SYNTHETIC_PRIVATE_ALLOWED_ARGUMENT"
    summary, payloads = run_session(
        initialize_messages(call("allowed", "read_file", {"path": marker}))
    )

    assert payloads[-1]["result"]["content"][0]["text"] == "synthetic-upstream-ok"
    assert summary["forwarded"] == 3
    assert summary["blocked"] == 0
    assert summary["response_clean"] == 1
    assert summary["child_cleaned_up"] is True
    assert marker not in json.dumps(summary)


@pytest.mark.parametrize(
    "name,arguments,decision",
    [
        ("run_command", {"command": "Remove-Item -Recurse C:\\synthetic"}, "deny"),
        ("read_file", {"path": "safe", "unknown": "private"}, "warn"),
    ],
)
def test_warn_and_deny_never_reach_upstream(name, arguments, decision):
    marker = "SYNTHETIC_PRIVATE_BLOCKED_ARGUMENT"
    arguments = {**arguments, "marker": marker} if decision == "warn" else arguments
    summary, payloads = run_session(initialize_messages(call("blocked", name, arguments)))

    error = payloads[-1]["error"]
    assert error["code"] == -32041
    assert error["data"]["decision"] == decision
    assert error["data"]["forwarded"] is False
    assert summary["forwarded"] == 2
    assert summary["blocked"] == 1
    assert marker not in json.dumps(payloads)


def test_explicit_warn_approval_forwards_without_exposing_raw_arguments():
    marker = "SYNTHETIC_PRIVATE_APPROVED_ARGUMENT"
    approval_output = io.StringIO()
    provider = TerminalApprovalProvider(
        io.StringIO("approve\n"),
        approval_output,
        timeout_seconds=1,
    )
    summary, payloads = run_session(
        initialize_messages(
            call("approved-warn", "read_file", {"path": "safe", "unknown": marker})
        ),
        approval_provider=provider,
    )

    assert payloads[-1]["result"]["content"][0]["text"] == "synthetic-upstream-ok"
    assert summary["approved"] == 1
    assert summary["blocked"] == 0
    assert marker not in approval_output.getvalue()


def test_deny_never_offers_an_approval_override():
    approval_output = io.StringIO()
    provider = TerminalApprovalProvider(
        io.StringIO("approve\n"), approval_output, timeout_seconds=1
    )
    summary, payloads = run_session(
        initialize_messages(
            call("deny-no-override", "run_command", {"command": "rm -rf synthetic"})
        ),
        approval_provider=provider,
    )

    assert payloads[-1]["error"]["data"]["decision"] == "deny"
    assert summary["approved"] == 0
    assert approval_output.getvalue() == ""


def test_task_augmented_warning_is_not_approvable():
    approval_output = io.StringIO()
    provider = TerminalApprovalProvider(
        io.StringIO("approve\n"), approval_output, timeout_seconds=1
    )
    request = call("task-no-override", "read_file", {"path": "safe"})
    request["params"]["task"] = {"ttl": 1}
    summary, payloads = run_session(
        initialize_messages(request),
        approval_provider=provider,
    )

    assert payloads[-1]["error"]["data"]["decision"] == "warn"
    assert summary["approved"] == 0
    assert approval_output.getvalue() == ""


def test_review_response_is_withheld_by_default_and_redacted():
    marker = "unexpected.example.invalid"
    summary, payloads = run_session(
        initialize_messages(call("review-result", "read_file", {"path": "safe"})),
        upstream_config=config("--result-mode", "review"),
    )

    assert payloads[-1]["error"]["code"] == -32043
    assert payloads[-1]["error"]["data"]["decision"] == "warn"
    assert marker not in json.dumps(payloads[-1])
    assert summary["response_review"] == 1
    assert summary["response_approved"] == 0


def test_review_response_can_be_explicitly_approved_without_approval_leak():
    approval_output = io.StringIO()
    provider = TerminalApprovalProvider(
        io.StringIO("approve\n"), approval_output, timeout_seconds=1
    )
    summary, payloads = run_session(
        initialize_messages(call("review-approved", "read_file", {"path": "safe"})),
        approval_provider=provider,
        upstream_config=config("--result-mode", "review"),
    )

    assert "unexpected.example.invalid" in json.dumps(payloads[-1])
    assert "unexpected.example.invalid" not in approval_output.getvalue()
    assert summary["response_approved"] == 1


def test_blocked_response_rejects_grant_and_never_reaches_client():
    provider = TerminalApprovalProvider(
        io.StringIO("grant 60 2\n"), io.StringIO(), timeout_seconds=1
    )
    summary, payloads = run_session(
        initialize_messages(call("blocked-result", "read_file", {"path": "safe"})),
        approval_provider=provider,
        upstream_config=config("--result-mode", "block"),
    )

    assert payloads[-1]["error"]["code"] == -32043
    assert "ignore previous" not in json.dumps(payloads)
    assert summary["response_blocked"] == 1
    assert summary["response_approved"] == 0


@pytest.mark.parametrize("mode", ["oversized", "malformed", "notification"])
def test_unsafe_upstream_response_fails_closed(mode):
    summary, payloads = run_session(
        initialize_messages(call(f"unsafe-{mode}", "read_file", {"path": "safe"})),
        upstream_config=config("--result-mode", mode),
    )

    assert payloads[-1]["error"]["code"] == -32042
    assert summary["protocol_errors"] == 1
    assert summary["child_cleaned_up"] is True


def test_duplicate_json_keys_and_non_finite_numbers_fail_closed():
    prefix = initialize_messages().getvalue()
    duplicate = (
        b'{"jsonrpc":"2.0","id":"one","id":"two","method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"path":"safe"}}}\n'
    )
    non_finite = (
        b'{"jsonrpc":"2.0","id":"nan","method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"unknown":NaN}}}\n'
    )

    for raw in (duplicate, non_finite):
        summary, payloads = run_session(io.BytesIO(prefix + raw))
        assert payloads[-1]["error"]["code"] == -32042
        assert summary["protocol_errors"] == 1


def test_protocol_error_before_initialize_is_local_and_closes_child():
    summary, payloads = run_session(
        io.BytesIO(line(call("too-early", "read_file", {"path": "safe"})))
    )

    assert payloads[0]["error"]["code"] == -32042
    assert payloads[0]["error"]["data"]["forwarded"] is False
    assert summary["forwarded"] == 0
    assert summary["protocol_errors"] == 1
    assert summary["child_cleaned_up"] is True


def test_upstream_timeout_fails_closed_and_cleans_child():
    policy = {
        **POLICY,
        "rules": {
            **POLICY["rules"],
            "mcp_tools": {
                **POLICY["rules"]["mcp_tools"],
                "allow_names": [*POLICY["rules"]["mcp_tools"]["allow_names"], "synthetic_hang"],
            },
        },
    }
    output = io.BytesIO()
    summary = run_stdio_gateway(
        initialize_messages(call("timeout", "synthetic_hang", {})),
        output,
        policy,
        config(),
        timeout_seconds=0.05,
        enabled=True,
    )
    payloads = [json.loads(row) for row in output.getvalue().splitlines()]

    assert payloads[-1]["error"]["message"] == "Upstream response timed out."
    assert summary["protocol_errors"] == 1
    assert summary["child_cleaned_up"] is True


def test_upstream_protocol_drift_fails_closed_before_response_is_forwarded():
    drifted = UpstreamConfig(
        server_id="synthetic-drift",
        argv=(sys.executable, str(FAKE_SERVER), "--protocol-version", "1900-01-01"),
        cwd=str(ROOT),
    )
    output = io.BytesIO()
    summary = run_stdio_gateway(
        initialize_messages(),
        output,
        POLICY,
        drifted,
        timeout_seconds=2,
        enabled=True,
    )
    payloads = [json.loads(row) for row in output.getvalue().splitlines()]

    assert len(payloads) == 1
    assert payloads[0]["error"]["code"] == -32042
    assert "2025-11-25" in payloads[0]["error"]["message"]
    assert summary["protocol_errors"] == 1


def test_forwarding_requires_explicit_enable_and_strict_config(tmp_path):
    with pytest.raises(RuntimeGatewayError, match="enabled=True"):
        run_stdio_gateway(
            io.BytesIO(),
            io.BytesIO(),
            POLICY,
            config(),
            timeout_seconds=1,
            enabled=False,
        )

    with pytest.raises(RuntimeGatewayError, match="fields"):
        parse_upstream_config({"schema_version": 1, "argv": ["python"]}, tmp_path / "up.json")


def test_tools_call_notification_fails_closed():
    request = call("ignored", "read_file", {"path": "safe"})
    del request["id"]
    summary, payloads = run_session(initialize_messages(request))

    assert payloads[-1]["error"]["code"] == -32042
    assert summary["forwarded"] == 2
    assert summary["protocol_errors"] == 1


def test_gateway_stdio_cli_keeps_protocol_on_stdout_and_summary_redacted(tmp_path):
    marker = "SYNTHETIC_CLI_PRIVATE_ARGUMENT"
    config_path = tmp_path / "upstream.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "server_id": "synthetic-cli",
                "argv": [sys.executable, str(FAKE_SERVER)],
                "cwd": str(ROOT),
            }
        ),
        encoding="utf-8",
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "policylatch.cli",
            "gateway-stdio",
            "--upstream-config",
            str(config_path),
            "--policy",
            str(ROOT / "examples/policies/gateway-strict.yaml"),
            "--enable-forwarding",
        ],
        input=initialize_messages(call("cli", "read_file", {"path": marker})).getvalue(),
        capture_output=True,
        cwd=ROOT,
        env=env,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0
    payloads = [json.loads(row) for row in completed.stdout.splitlines()]
    assert payloads[-1]["result"]["content"][0]["text"] == "synthetic-upstream-ok"
    summary = json.loads(completed.stderr)
    assert summary["forwarded"] == 3
    assert summary["child_cleaned_up"] is True
    assert marker.encode() not in completed.stderr


def test_bundled_synthetic_upstream_config_is_bounded_and_resolves_to_repo():
    source = ROOT / "examples/gateway/synthetic-upstream.json"
    parsed = parse_upstream_config(json.loads(source.read_text(encoding="utf-8")), source)

    assert parsed.server_id == "policylatch-synthetic-fake"
    assert parsed.argv == ("python", "tests/fixtures/fake_mcp_server.py")
    assert parsed.cwd == str(ROOT.resolve())
