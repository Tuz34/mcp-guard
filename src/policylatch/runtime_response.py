from __future__ import annotations

import hashlib
import json
from typing import Any

from .receipts import canonical_json
from .result_scanner import scan_tool_result
from .validation import InputError


def _fingerprint(label: str, value: Any) -> str:
    try:
        encoded = canonical_json({"contract": label, "value": value}).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise InputError("Runtime MCP response cannot be safely fingerprinted.") from exc
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def scan_mcp_tool_response(request: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    params = request.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        raise InputError("Runtime MCP request correlation is invalid.")
    if ("result" in response) == ("error" in response):
        raise InputError("Runtime MCP response must contain exactly one result or error.")
    envelope = (
        {"result": response["result"]} if "result" in response else {"error": response["error"]}
    )
    try:
        content = json.dumps(
            envelope,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise InputError("Runtime MCP response cannot be normalized as bounded JSON text.") from exc
    tool_result = {
        "schema_version": 1,
        "kind": "tool_result",
        "request_id": _fingerprint("runtime-request-v1", request),
        "result_id": _fingerprint("runtime-response-v1", response),
        "tool": params["name"],
        "source_trust": "untrusted",
        "content": content,
        "fields": {},
        "expected_domains": [],
    }
    return scan_tool_result(tool_result, "runtime-upstream.json")
