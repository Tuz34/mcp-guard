from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .gateway import GatewayResult, evaluate_mcp_request
from .models import aggregate
from .validation import InputError

MAX_TRACE_LINE_BYTES = 1024 * 1024
MAX_TRACE_TOTAL_BYTES = 8 * 1024 * 1024
MAX_TRACE_RECORDS = 1000


class GatewayTraceError(ValueError):
    """Raised when a synthetic gateway trace is invalid or exceeds its limits."""


def load_gateway_trace(
    path: str | Path,
    policy: dict[str, Any],
    *,
    max_records: int = MAX_TRACE_RECORDS,
) -> list[GatewayResult]:
    if type(max_records) is not int or max_records < 1:
        raise GatewayTraceError("max_records must be a positive integer.")

    source = Path(path)
    results: list[GatewayResult] = []
    total_bytes = 0
    try:
        with source.open("rb") as handle:
            line_number = 0
            while True:
                raw = handle.readline(MAX_TRACE_LINE_BYTES + 1)
                if not raw:
                    break
                line_number += 1
                total_bytes += len(raw)
                if len(raw) > MAX_TRACE_LINE_BYTES:
                    raise GatewayTraceError(f"Gateway trace line {line_number} is too large.")
                if total_bytes > MAX_TRACE_TOTAL_BYTES:
                    raise GatewayTraceError(
                        f"Gateway trace exceeds the {MAX_TRACE_TOTAL_BYTES}-byte total limit."
                    )
                if not raw.strip():
                    continue
                if len(results) >= max_records:
                    raise GatewayTraceError(f"Gateway trace exceeds {max_records} records.")
                try:
                    payload = json.loads(raw.decode("utf-8"))
                    if not isinstance(payload, dict):
                        raise InputError("MCP trace record must be a JSON object.")
                    results.append(evaluate_mcp_request(payload, policy))
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    InputError,
                    RecursionError,
                ) as exc:
                    raise GatewayTraceError(
                        f"Invalid gateway trace record at line {line_number}: {exc}"
                    ) from exc
    except OSError as exc:
        raise GatewayTraceError(f"Could not read gateway trace '{source}': {exc}") from exc

    if not results:
        raise GatewayTraceError("Gateway trace must contain at least one tools/call request.")
    return results


def gateway_trace_document(
    results: list[GatewayResult],
    *,
    source: str,
    policy: str,
) -> dict[str, Any]:
    if not results:
        raise GatewayTraceError("Gateway trace results cannot be empty.")
    decision, risk_level = aggregate([result.evaluation for result in results])
    counts = {
        name: sum(result.evaluation.decision == name for result in results)
        for name in ("allow", "warn", "deny")
    }
    return {
        "schema_version": 1,
        "kind": "mcp_gateway_replay",
        "source": Path(source).name,
        "policy": Path(policy).name,
        "gateway": {"mode": "dry-run", "forwarded": False},
        "decision": decision,
        "risk_level": risk_level,
        "summary": {"total": len(results), **counts},
        "results": [result.to_entry() for result in results],
    }
