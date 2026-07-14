import json
from pathlib import Path

import pytest

from mcp_guard.gateway_trace import (
    GatewayTraceError,
    gateway_trace_document,
    load_gateway_trace,
)
from mcp_guard.policy import load_policy

ROOT = Path(__file__).parents[1]
POLICY = load_policy(ROOT / "examples/policies/gateway-strict.yaml")


def test_replays_bounded_synthetic_trace_without_raw_arguments():
    path = ROOT / "examples/gateway/synthetic-trace.jsonl"
    results = load_gateway_trace(path, POLICY)
    payload = gateway_trace_document(results, source=str(path), policy="gateway-strict.yaml")
    serialized = json.dumps(payload)

    assert payload["decision"] == "deny"
    assert payload["summary"] == {"total": 3, "allow": 1, "warn": 0, "deny": 2}
    assert payload["gateway"] == {"mode": "dry-run", "forwarded": False}
    assert [item["request"]["id"] for item in payload["results"]] == [
        "trace-1",
        "trace-2",
        "trace-3",
    ]
    assert "arguments" not in serialized
    assert "synthetic-demo" not in serialized


def test_trace_reports_invalid_line_number(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text(
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}\nnot-json\n',
        encoding="utf-8",
    )

    with pytest.raises(GatewayTraceError, match="line 2"):
        load_gateway_trace(path, POLICY)


def test_trace_rejects_oversized_line_with_bounded_reader(tmp_path, monkeypatch):
    path = tmp_path / "oversized.jsonl"
    path.write_bytes(b"x" * 33)
    monkeypatch.setattr("mcp_guard.gateway_trace.MAX_TRACE_LINE_BYTES", 32)

    with pytest.raises(GatewayTraceError, match="line 1 is too large"):
        load_gateway_trace(path, POLICY)


def test_trace_rejects_record_limit(tmp_path):
    path = tmp_path / "many.jsonl"
    line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file"},
        }
    )
    path.write_text(f"{line}\n{line}\n", encoding="utf-8")

    with pytest.raises(GatewayTraceError, match="exceeds 1 records"):
        load_gateway_trace(path, POLICY, max_records=1)


def test_trace_rejects_total_byte_limit(tmp_path, monkeypatch):
    path = tmp_path / "total-limit.jsonl"
    path.write_bytes(b" \n \n")
    monkeypatch.setattr("mcp_guard.gateway_trace.MAX_TRACE_TOTAL_BYTES", 3)

    with pytest.raises(GatewayTraceError, match="total limit"):
        load_gateway_trace(path, POLICY)


def test_trace_rejects_empty_input(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("\n", encoding="utf-8")

    with pytest.raises(GatewayTraceError, match="at least one"):
        load_gateway_trace(path, POLICY)
