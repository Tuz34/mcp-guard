from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import risk_for
from .policy import policy_provenance
from .scanners import scan_manifest
from .tool_policy import tool_name_is_allowed
from .validation import InputError, manifest_entries

MAX_DRAFT_TOOLS = 512
MAX_SCHEMA_NODES = 2048
MAX_SCHEMA_DEPTH = 16

_CAPABILITY_MARKERS = {
    "database": ("database", "query", "sql", "table"),
    "filesystem": ("file", "path", "directory", "folder", "workspace"),
    "mutation": ("create", "delete", "remove", "update", "upload", "write"),
    "network": ("browser", "domain", "fetch", "http", "network", "url"),
    "shell": ("command", "exec", "shell", "terminal"),
}
_DESCRIPTION_DENY_MARKERS = (
    "exfiltrate",
    "ignore previous instructions",
    "no approval needed",
    "send file contents",
)


def _schema_keys(schema: dict[str, Any]) -> tuple[set[str], bool]:
    keys: set[str] = set()
    stack: list[tuple[Any, int]] = [(schema, 0)]
    nodes = 0
    truncated = False
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_SCHEMA_NODES or depth > MAX_SCHEMA_DEPTH:
            truncated = True
            break
        if isinstance(value, dict):
            keys.update(key.casefold() for key in value)
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
    return keys, truncated


def _capabilities(name: str, schema: dict[str, Any]) -> list[str]:
    keys, truncated = _schema_keys(schema)
    searchable = " ".join([name.casefold(), *sorted(keys)])
    capabilities = [
        capability
        for capability, markers in _CAPABILITY_MARKERS.items()
        if any(marker in searchable for marker in markers)
    ]
    if truncated:
        capabilities.append("schema-complexity")
    return capabilities


def policy_draft_document(manifest: dict[str, Any], source: str) -> dict[str, Any]:
    entries = manifest_entries(manifest)
    if len(entries) > MAX_DRAFT_TOOLS:
        raise InputError(f"Policy draft input exceeds the {MAX_DRAFT_TOOLS}-tool limit.")

    deny_names: list[str] = []
    warn_names: list[str] = []
    recommendations: list[dict[str, Any]] = []
    provenance: list[dict[str, str]] = []
    for tool in sorted(entries, key=lambda item: item["name"].casefold()):
        name = tool["name"]
        if len(name) > 256:
            raise InputError("Policy draft tool names cannot exceed 256 characters.")
        description = tool["description"].casefold()
        blocked_categories = [
            marker for marker in _DESCRIPTION_DENY_MARKERS if marker in description
        ]
        capabilities = _capabilities(name, tool["inputSchema"])
        if blocked_categories:
            deny_names.append(name)
            disposition = "deny-review"
            provenance.append(
                {
                    "rule": "mcp_tools.deny_names",
                    "pattern": name,
                    "source": f"manifest-tool:{name}",
                    "reason": "fixed blocked-description category matched; raw text omitted",
                }
            )
        elif capabilities:
            warn_names.append(name)
            disposition = "warn-review"
            provenance.append(
                {
                    "rule": "mcp_tools.warn_if_name_contains",
                    "pattern": name,
                    "source": f"manifest-tool:{name}",
                    "reason": "fixed capability classifier matched name or schema keys",
                }
            )
        else:
            disposition = "todo"
        recommendations.append(
            {
                "tool": name,
                "disposition": disposition,
                "capabilities": capabilities or ["unclassified"],
            }
        )

    return {
        "draft": True,
        "draft_schema_version": 1,
        "source": Path(source).name,
        "notice": "Review required: generated drafts are not valid enforcement policies.",
        "generated_policy": {
            "draft": True,
            "version": 1,
            "default_decision": "warn",
            "rules": {
                "mcp_tools": {
                    "deny_names": sorted(deny_names, key=str.casefold),
                    "warn_if_name_contains": sorted(warn_names, key=str.casefold),
                }
            },
        },
        "recommendations": recommendations,
        "provenance": provenance,
    }


def policy_draft_yaml(document: dict[str, Any]) -> str:
    return yaml.safe_dump(
        document,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    )


def policy_coverage_document(
    manifest: dict[str, Any],
    policy: dict[str, Any],
    policy_label: str,
    source: str,
) -> dict[str, Any]:
    evaluations = scan_manifest(manifest, policy)
    mcp_rules = policy["rules"].get("mcp_tools", {})
    results: list[dict[str, Any]] = []
    uncovered = 0
    for evaluation in sorted(evaluations, key=lambda item: (item.subject or "").casefold()):
        explicitly_allowed = tool_name_is_allowed(evaluation.subject or "", mcp_rules)
        covered = explicitly_allowed or bool(evaluation.reasons)
        uncovered += not covered
        result = {
            "subject": evaluation.subject,
            "decision": "allow" if covered else "warn",
            "risk_level": "low" if covered else "medium",
            "covered": covered,
            "policy_decision": evaluation.decision,
            "reasons": [],
        }
        if not covered:
            result["reasons"].append(
                {
                    "rule": "policy-coverage.unclassified-tool",
                    "effect": "warn",
                    "matched": "no-explicit-rule",
                    "message": "Tool has no explicit allow, warn, or deny policy signal.",
                }
            )
        results.append(result)
    decision = "warn" if uncovered else "allow"
    return {
        "schema_version": 1,
        "kind": "policy_coverage",
        "source": Path(source).name,
        "policy": policy_label,
        "policy_provenance": policy_provenance(policy),
        "decision": decision,
        "risk_level": risk_for(decision),
        "summary": {
            "total": len(results),
            "covered": len(results) - uncovered,
            "uncovered": uncovered,
        },
        "results": results,
    }
