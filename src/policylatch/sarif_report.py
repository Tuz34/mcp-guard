from __future__ import annotations

import json
import re
from typing import Any

from . import __version__
from .reports import validate_report

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_ABSOLUTE_WINDOWS_PATH = re.compile(r"^[A-Za-z]:/")


def _artifact_uri(source: Any) -> str:
    value = str(source or "input.json").replace("\\", "/")
    parts = [part for part in value.split("/") if part not in {"", "."}]
    if not parts:
        return "input.json"
    if value.startswith("/") or _ABSOLUTE_WINDOWS_PATH.match(value) or ".." in parts:
        return parts[-1]
    return "/".join(parts)


def _level(effect: str) -> str:
    return "error" if effect == "deny" else "warning"


def sarif_document(data: dict[str, Any]) -> dict[str, Any]:
    """Build a minimal deterministic SARIF 2.1.0 document."""

    rows = validate_report(data)
    source_uri = _artifact_uri(data.get("source"))
    results: list[dict[str, Any]] = []
    rule_levels: dict[str, str] = {}

    for item in rows:
        for reason in item.get("reasons", []):
            rule_id = reason["rule"]
            level = _level(reason["effect"])
            if rule_levels.get(rule_id) != "error":
                rule_levels[rule_id] = level
            properties: dict[str, str] = {
                "decision": item["decision"],
                "riskLevel": item["risk_level"],
            }
            subject = item.get("subject")
            if isinstance(subject, str) and subject:
                properties["subject"] = subject
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": reason["message"]},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": source_uri}}}],
                    "properties": properties,
                }
            )

    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": f"PolicyLatch policy rule {rule_id}"},
            "defaultConfiguration": {"level": rule_levels[rule_id]},
        }
        for rule_id in sorted(rule_levels)
    ]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "policylatch",
                "informationUri": "https://github.com/Tuz34/policylatch",
                "semanticVersion": __version__,
                "rules": rules,
            }
        },
        "results": results,
    }
    receipt = data.get("receipt")
    if isinstance(receipt, dict) and isinstance(receipt.get("receipt_fingerprint"), str):
        run["properties"] = {"decisionReceipt": receipt["receipt_fingerprint"]}
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def sarif_report(data: dict[str, Any]) -> str:
    return json.dumps(sarif_document(data), indent=2, ensure_ascii=False) + "\n"
