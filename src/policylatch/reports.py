from __future__ import annotations

import json
from typing import Any

VALID_DECISIONS = {"allow", "warn", "deny"}
VALID_RISKS = {"low", "medium", "high"}


def json_report(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("results", [data])
    if not isinstance(rows, list) or not rows:
        raise ValueError("Report input must contain at least one result.")
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            raise ValueError(f"Report result {index} must be an object.")
        if item.get("decision") not in VALID_DECISIONS:
            raise ValueError(f"Report result {index} has an invalid decision.")
        if item.get("risk_level") not in VALID_RISKS:
            raise ValueError(f"Report result {index} has an invalid risk_level.")
        if not isinstance(item.get("reasons", []), list):
            raise ValueError(f"Report result {index} reasons must be an array.")
    return rows


def validate_report(data: dict[str, Any]) -> list[dict[str, Any]]:
    if data.get("decision") not in VALID_DECISIONS:
        raise ValueError("Report input does not contain a valid top-level decision.")
    if data.get("risk_level") not in VALID_RISKS:
        raise ValueError("Report input does not contain a valid top-level risk_level.")
    rows = _rows(data)
    for item in rows:
        for reason in item.get("reasons", []):
            if not isinstance(reason, dict):
                raise ValueError("Each report reason must be an object.")
            required = ("rule", "effect", "matched", "message")
            if any(not isinstance(reason.get(field), str) for field in required):
                raise ValueError("Each report reason requires rule, effect, matched, and message.")
            if reason["effect"] not in {"warn", "deny"}:
                raise ValueError("Each report reason effect must be warn or deny.")
    return rows


def _inline_code(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("`", "'")


def _table_cell(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def markdown_report(data: dict[str, Any]) -> str:
    rows = validate_report(data)
    lines = [
        "# PolicyLatch report",
        "",
        f"Source: `{_inline_code(data.get('source', 'action'))}`",
        "",
    ]
    if "decision" in data and "risk_level" in data:
        lines.extend(
            [
                f"Overall decision: **{str(data['decision']).upper()}**",
                f"Overall risk: **{data['risk_level']}**",
                "",
            ]
        )
    outcome = data.get("postflight_outcome")
    if isinstance(outcome, str):
        lines.extend([f"Post-flight outcome: **{outcome.upper()}**", ""])
    lines.extend(["| Subject | Decision | Risk |", "|---|---|---|"])
    for item in rows:
        subject = _table_cell(item.get("subject", "action"))
        lines.append(f"| {subject} | **{item['decision'].upper()}** | {item['risk_level']} |")
    lines += ["", "## Findings", ""]

    found = False
    for item in rows:
        for reason in item.get("reasons", []):
            found = True
            lines.append(
                f"- **{reason['effect'].upper()}** `{_inline_code(reason['rule'])}` matched "
                f"`{_inline_code(reason['matched'])}`: {_table_cell(reason['message'])}"
            )
    if not found:
        lines.append("No policy findings.")
    provenance = data.get("policy_provenance")
    if isinstance(provenance, dict) and isinstance(provenance.get("sources"), list):
        lines += ["", "## Policy provenance", ""]
        for source in provenance["sources"]:
            lines.append(f"- `{_inline_code(source)}`")
    receipt = data.get("receipt")
    if isinstance(receipt, dict) and isinstance(receipt.get("receipt_fingerprint"), str):
        lines += [
            "",
            "## Decision receipt",
            "",
            f"`{_inline_code(receipt['receipt_fingerprint'])}`",
        ]
    lines += [
        "",
        "> PolicyLatch evaluates proposed actions; it does not execute tools or provide a sandbox.",
        "",
    ]
    return "\n".join(lines)
