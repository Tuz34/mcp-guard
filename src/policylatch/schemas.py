from __future__ import annotations

from copy import deepcopy
from typing import Any

from .policy import RULE_KEYS, VALID_DECISIONS
from .profiles import profile_names

SCHEMA_VERSION = 1
SCHEMA_KINDS = ("action", "gateway-request", "policy", "receipt", "report")

_TEXT_ARRAY = {
    "type": "array",
    "items": {"type": "string", "minLength": 1},
}


def _rules_schema() -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for section, names in sorted(RULE_KEYS.items()):
        properties[section] = {
            "type": "object",
            "properties": {name: deepcopy(_TEXT_ARRAY) for name in sorted(names)},
            "additionalProperties": False,
        }
    return {"type": "object", "properties": properties, "additionalProperties": False}


def policy_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/Tuz34/policylatch/schemas/policy-v1.json",
        "title": "PolicyLatch policy v1",
        "type": "object",
        "required": ["version"],
        "properties": {
            "version": {"const": 1},
            "profile": {"enum": list(profile_names())},
            "extends": {
                "oneOf": [
                    {"type": "string", "minLength": 1},
                    deepcopy(_TEXT_ARRAY),
                ]
            },
            "default_decision": {"enum": sorted(VALID_DECISIONS)},
            "rules": _rules_schema(),
        },
        "additionalProperties": False,
    }


def action_schema() -> dict[str, Any]:
    base_properties = {
        "actor": {"type": "string"},
        "tool": {"type": "string"},
        "metadata": {"type": "object"},
    }
    variants = []
    for action_type, field in (
        ("shell", "command"),
        ("file", "path"),
        ("filesystem", "path"),
    ):
        variants.append(
            {
                "type": "object",
                "required": ["action_type", field],
                "properties": {
                    **base_properties,
                    "action_type": {"const": action_type},
                    field: {"type": "string", "minLength": 1},
                },
                "additionalProperties": True,
            }
        )
    variants.append(
        {
            "type": "object",
            "required": ["action_type"],
            "properties": {
                **base_properties,
                "action_type": {"const": "network"},
                "url": {"type": "string", "minLength": 1},
                "domain": {"type": "string", "minLength": 1},
            },
            "oneOf": [{"required": ["url"]}, {"required": ["domain"]}],
            "additionalProperties": True,
        }
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/Tuz34/policylatch/schemas/action-v1.json",
        "title": "PolicyLatch action v1",
        "oneOf": variants,
    }


def gateway_request_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/Tuz34/policylatch/schemas/gateway-request-v1.json",
        "title": "PolicyLatch MCP tools/call request v1",
        "type": "object",
        "required": ["jsonrpc", "method", "params"],
        "properties": {
            "jsonrpc": {"const": "2.0"},
            "id": {
                "oneOf": [
                    {"type": "string", "maxLength": 256},
                    {"type": "integer"},
                    {"type": "null"},
                ]
            },
            "method": {"const": "tools/call"},
            "params": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 256},
                    "arguments": {"type": "object"},
                    "task": {"type": "object"},
                },
                "additionalProperties": True,
            },
        },
        "additionalProperties": True,
    }


def report_schema() -> dict[str, Any]:
    reason = {
        "type": "object",
        "required": ["rule", "effect", "matched", "message"],
        "properties": {
            "rule": {"type": "string"},
            "effect": {"enum": ["warn", "deny"]},
            "matched": {"type": "string"},
            "message": {"type": "string"},
        },
        "additionalProperties": True,
    }
    result = {
        "type": "object",
        "required": ["decision", "risk_level"],
        "properties": {
            "decision": {"enum": sorted(VALID_DECISIONS)},
            "risk_level": {"enum": ["low", "medium", "high"]},
            "reasons": {"type": "array", "items": reason},
        },
        "additionalProperties": True,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/Tuz34/policylatch/schemas/report-v1.json",
        "title": "PolicyLatch report v1",
        **result,
        "properties": {
            **result["properties"],
            "schema_version": {"const": 1},
            "results": {"type": "array", "minItems": 1, "items": result},
        },
    }


def receipt_schema() -> dict[str, Any]:
    sha256 = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/Tuz34/policylatch/schemas/receipt-v1.json",
        "title": "PolicyLatch decision receipt v1",
        "type": "object",
        "required": [
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
        ],
        "properties": {
            "schema_version": {"const": 1},
            "kind": {"const": "decision_receipt"},
            "evaluator": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "policylatch"},
                    "version": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "policy": {
                "type": "object",
                "required": ["hash", "profiles", "sources"],
                "properties": {
                    "hash": sha256,
                    "profiles": {"type": "array", "items": {"type": "string"}},
                    "sources": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": False,
            },
            "request": {
                "type": "object",
                "required": ["projection", "fingerprint"],
                "properties": {
                    "projection": {"type": "string"},
                    "fingerprint": sha256,
                },
                "additionalProperties": False,
            },
            "decision": {"enum": sorted(VALID_DECISIONS)},
            "rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "effect", "source"],
                    "properties": {
                        "id": {"type": "string"},
                        "effect": {"enum": ["warn", "deny"]},
                        "source": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            "execution": {
                "type": "object",
                "required": ["claimed"],
                "properties": {"claimed": {"const": False}},
                "additionalProperties": False,
            },
            "extensions": {"type": "object"},
            "receipt_fingerprint": sha256,
        },
        "additionalProperties": False,
    }


def export_schema(kind: str) -> dict[str, Any]:
    builders = {
        "action": action_schema,
        "gateway-request": gateway_request_schema,
        "policy": policy_schema,
        "receipt": receipt_schema,
        "report": report_schema,
    }
    try:
        return builders[kind]()
    except KeyError as exc:
        raise ValueError(f"Unsupported schema kind '{kind}'.") from exc
