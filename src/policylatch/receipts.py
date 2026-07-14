from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any

from . import __version__
from .policy import VALID_DECISIONS, policy_provenance
from .reports import validate_report
from .validation import InputError, manifest_entries

RECEIPT_SCHEMA_VERSION = 1
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _hash(value: Any) -> str:
    encoded = canonical_json(value).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def canonical_policy_hash(policy: dict[str, Any]) -> str:
    semantic = {
        "version": policy["version"],
        "default_decision": policy["default_decision"],
        "rules": policy["rules"],
        "budgets": policy.get("budgets", {}),
    }
    return _hash(semantic)


def action_request_projection(action: dict[str, Any]) -> dict[str, Any]:
    action_type = action.get("action_type")
    normalized_type = action_type.casefold() if isinstance(action_type, str) else "invalid"
    fixed_fields = sorted(
        field for field in ("command", "domain", "path", "url") if field in action
    )
    return {
        "contract": "action-v1",
        "action_type": normalized_type,
        "fields": fixed_fields,
        "actor_present": "actor" in action,
        "tool_present": "tool" in action,
        "budget_fields": sorted(action.get("budget", {}))
        if isinstance(action.get("budget"), dict)
        else [],
    }


def gateway_request_projection(request: dict[str, Any]) -> dict[str, Any]:
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    recognized = sorted(
        field for field in ("command", "domain", "path", "url") if field in arguments
    )
    return {
        "contract": "mcp-tools-call-v1",
        "method": request.get("method") if request.get("method") == "tools/call" else "invalid",
        "argument_fields": recognized,
        "unclassified_arguments": bool(set(arguments) - {"command", "domain", "path", "url"}),
        "task_augmented": "task" in params,
    }


def manifest_request_projection(manifest: dict[str, Any]) -> dict[str, Any]:
    shapes = []
    for entry in manifest_entries(manifest):
        shapes.append(
            {
                "description_present": bool(entry["description"]),
                "schema_present": bool(entry["inputSchema"]),
                "server_command_present": "command" in entry,
            }
        )
    return {
        "contract": "mcp-manifest-v1",
        "tool_count": len(shapes),
        "tool_shapes": sorted(shapes, key=canonical_json),
    }


def report_request_projection(report: dict[str, Any]) -> dict[str, Any]:
    rows = report.get("results")
    result_count = len(rows) if isinstance(rows, list) else 1
    capabilities: set[str] = set()
    if isinstance(report.get("capabilities"), list):
        capabilities.update(item for item in report["capabilities"] if isinstance(item, str))
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("capabilities"), list):
                capabilities.update(item for item in row["capabilities"] if isinstance(item, str))
    projection: dict[str, Any] = {
        "contract": str(report.get("kind", "decision")),
        "result_count": result_count,
        "capabilities": sorted(capabilities),
    }
    adapter = report.get("adapter")
    if isinstance(adapter, dict):
        projection["adapter"] = {
            "runtime": adapter.get("runtime"),
            "event": adapter.get("event"),
            "mode": adapter.get("mode"),
        }
    return projection


def _matched_rules(report: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, str]]:
    rows = validate_report(report)
    sources = policy_provenance(policy).get("rule_sources", {})
    rules = {
        (reason["rule"], reason["effect"], sources.get(reason["rule"], "runtime"))
        for row in rows
        for reason in row.get("reasons", [])
    }
    return [
        {"id": rule, "effect": effect, "source": source} for rule, effect, source in sorted(rules)
    ]


def decision_receipt(
    report: dict[str, Any],
    policy: dict[str, Any],
    request_projection: dict[str, Any],
) -> dict[str, Any]:
    validate_report(report)
    provenance = policy_provenance(policy)
    core = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "kind": "decision_receipt",
        "evaluator": {"name": "policylatch", "version": __version__},
        "policy": {
            "hash": canonical_policy_hash(policy),
            "profiles": list(provenance.get("profiles", [])),
            "sources": list(provenance.get("sources", [])),
        },
        "request": {
            "projection": str(request_projection.get("contract", "decision")),
            "fingerprint": _hash(request_projection),
        },
        "decision": report["decision"],
        "rules": _matched_rules(report, policy),
        "execution": {"claimed": False},
        "extensions": {},
    }
    return {**core, "receipt_fingerprint": _hash(core)}


def attach_receipt(
    report: dict[str, Any],
    policy: dict[str, Any],
    request_projection: dict[str, Any],
) -> dict[str, Any]:
    report["receipt"] = decision_receipt(report, policy, request_projection)
    return report


def validate_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "kind",
        "evaluator",
        "policy",
        "request",
        "decision",
        "rules",
        "execution",
        "extensions",
        "receipt_fingerprint",
    }
    if set(receipt) != required:
        raise InputError("Decision receipt fields do not match schema version 1.")
    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise InputError("Only decision receipt schema version 1 is supported.")
    if receipt.get("kind") != "decision_receipt":
        raise InputError("Decision receipt kind must be decision_receipt.")
    if receipt.get("decision") not in VALID_DECISIONS:
        raise InputError("Decision receipt decision is invalid.")
    for container in ("evaluator", "policy", "request", "execution", "extensions"):
        if not isinstance(receipt.get(container), dict):
            raise InputError(f"Decision receipt {container} must be an object.")
    evaluator = receipt["evaluator"]
    if (
        set(evaluator) != {"name", "version"}
        or evaluator.get("name") != "policylatch"
        or not isinstance(evaluator.get("version"), str)
    ):
        raise InputError("Decision receipt evaluator is invalid.")
    policy = receipt["policy"]
    if set(policy) != {"hash", "profiles", "sources"} or not all(
        isinstance(policy.get(field), list) and all(isinstance(item, str) for item in policy[field])
        for field in ("profiles", "sources")
    ):
        raise InputError("Decision receipt policy provenance is invalid.")
    request = receipt["request"]
    if set(request) != {"projection", "fingerprint"} or not isinstance(
        request.get("projection"), str
    ):
        raise InputError("Decision receipt request projection is invalid.")
    if receipt["execution"] != {"claimed": False}:
        raise InputError("Decision receipt cannot claim tool execution.")
    if not isinstance(receipt.get("rules"), list) or not all(
        isinstance(item, dict)
        and set(item) == {"id", "effect", "source"}
        and all(isinstance(value, str) for value in item.values())
        and item["effect"] in {"warn", "deny"}
        for item in receipt.get("rules", [])
    ):
        raise InputError("Decision receipt rules are invalid.")
    hashes = (
        receipt.get("receipt_fingerprint"),
        receipt["policy"].get("hash"),
        receipt["request"].get("fingerprint"),
    )
    if not all(isinstance(value, str) and _HASH.fullmatch(value) for value in hashes):
        raise InputError("Decision receipt contains an invalid SHA-256 fingerprint.")
    core = deepcopy(receipt)
    fingerprint = core.pop("receipt_fingerprint")
    if _hash(core) != fingerprint:
        raise InputError("Decision receipt fingerprint does not match its canonical content.")
    return receipt


def receipt_jsonl(receipt: dict[str, Any]) -> str:
    validate_receipt(receipt)
    return canonical_json(receipt) + "\n"
