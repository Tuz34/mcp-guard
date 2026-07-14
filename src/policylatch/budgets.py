from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .journal import load_journal
from .models import DECISION_RANK, risk_for
from .policy import policy_provenance
from .receipts import (
    attach_receipt,
    canonical_json,
    canonical_policy_hash,
    validate_receipt,
)
from .reports import validate_report
from .validation import InputError, validate_action

_WINDOW_SECONDS = {"hour": 3600, "day": 86_400}
_EVENT_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


def _fingerprint(label: str, value: str) -> str:
    digest = hashlib.sha256(canonical_json({label: value}).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def action_budget_facts(action: dict[str, Any]) -> dict[str, Any]:
    validate_action(action)
    budget = action.get("budget") if isinstance(action.get("budget"), dict) else {}
    payload_bytes = budget.get("payload_bytes")
    if payload_bytes is None:
        payload_size_class = "unknown"
    elif payload_bytes <= 1024 * 1024:
        payload_size_class = "small"
    elif payload_bytes <= 100 * 1024 * 1024:
        payload_size_class = "medium"
    else:
        payload_size_class = "large"
    target = budget.get("target_id")
    tool = action.get("tool")
    return {
        "action_type": str(action["action_type"]).casefold(),
        "confirmation": budget.get("confirmation", "unknown"),
        "impact": budget.get("impact"),
        "payload_size_class": payload_size_class,
        "target_fingerprint": (
            _fingerprint("budget-target", target) if isinstance(target, str) else None
        ),
        "tool_fingerprint": _fingerprint("budget-tool", tool) if isinstance(tool, str) else None,
    }


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _receipt_from_report(report: dict[str, Any]) -> dict[str, Any]:
    validate_report(report)
    receipt = report.get("receipt")
    if not isinstance(receipt, dict):
        raise InputError("Budget input report does not contain a decision receipt.")
    return validate_receipt(receipt)


def _reason(rule: str, effect: str, matched: str, message: str) -> dict[str, str]:
    return {"rule": rule, "effect": effect, "matched": matched, "message": message}


def _unknown_document(
    report: dict[str, Any],
    policy: dict[str, Any],
    policy_label: str,
    source: str,
    rule: str,
    message: str,
    event_id: str,
) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "kind": "policy_budget_check",
        "source": Path(source).name,
        "policy": policy_label,
        "policy_provenance": policy_provenance(policy),
        "status": "unknown",
        "decision": "deny",
        "risk_level": "high",
        "subject": "budget-state",
        "reasons": [_reason(rule, "deny", "unknown-state", message)],
    }
    return attach_receipt(
        payload,
        policy,
        {"contract": "budget-check-v1", "event_id": event_id, "status": "unknown"},
    )


def budget_check_document(
    report: dict[str, Any],
    policy: dict[str, Any],
    policy_label: str,
    journal_path: str | Path,
    event_id: str,
) -> dict[str, Any]:
    if not _EVENT_ID.fullmatch(event_id):
        raise InputError("Budget check event_id must be a SHA-256 fingerprint.")
    receipt = _receipt_from_report(report)
    if receipt["policy"]["hash"] != canonical_policy_hash(policy):
        return _unknown_document(
            report,
            policy,
            policy_label,
            str(journal_path),
            "budget.policy-mismatch",
            "Report receipt and selected budget policy do not have the same canonical hash.",
            event_id,
        )
    try:
        state_before = Path(journal_path).stat()
        before_signature = (state_before.st_size, state_before.st_mtime_ns)
        records = load_journal(journal_path)
        state_after = Path(journal_path).stat()
        after_signature = (state_after.st_size, state_after.st_mtime_ns)
    except InputError:
        return _unknown_document(
            report,
            policy,
            policy_label,
            str(journal_path),
            "budget.journal-unavailable",
            "Budget state is unknown because the journal is missing or invalid.",
            event_id,
        )
    except OSError:
        return _unknown_document(
            report,
            policy,
            policy_label,
            str(journal_path),
            "budget.journal-unavailable",
            "Budget state is unknown because the journal cannot be inspected.",
            event_id,
        )
    if before_signature != after_signature:
        return _unknown_document(
            report,
            policy,
            policy_label,
            str(journal_path),
            "budget.journal-race",
            "Budget state changed during the check; retry with a fresh reservation.",
            event_id,
        )
    if records is None:
        return _unknown_document(
            report,
            policy,
            policy_label,
            str(journal_path),
            "budget.journal-unavailable",
            "Budget state is unknown because the journal is unavailable.",
            event_id,
        )
    reservation = next((record for record in records if record["event_id"] == event_id), None)
    if (
        reservation is None
        or reservation["stage"] != "proposed"
        or reservation["receipt_fingerprint"] != receipt["receipt_fingerprint"]
    ):
        return _unknown_document(
            report,
            policy,
            policy_label,
            str(journal_path),
            "budget.reservation-missing",
            "A matching proposed-stage journal reservation is required before budget check.",
            event_id,
        )

    current_facts = reservation["budget_facts"]
    current_time = _parsed_timestamp(reservation["recorded_at"])
    results: list[dict[str, Any]] = []
    for budget_id, config in sorted(policy.get("budgets", {}).items()):
        if current_facts["action_type"] not in config["action_types"]:
            continue
        rule_id = f"budgets.{budget_id}"
        effect = config.get("effect", "deny")
        earliest = current_time - timedelta(seconds=_WINDOW_SECONDS[config["window"]])
        candidates = []
        unknown_message = None
        for record in records:
            if record["stage"] != "proposed":
                continue
            recorded_at = _parsed_timestamp(record["recorded_at"])
            if not earliest <= recorded_at <= current_time:
                continue
            facts = record["budget_facts"]
            if facts["action_type"] not in config["action_types"]:
                continue
            if facts["confirmation"] != "confirmed":
                unknown_message = "A matching reservation has non-confirmed budget state."
                break
            if config.get("per_tool", False):
                if current_facts["tool_fingerprint"] is None or facts["tool_fingerprint"] is None:
                    unknown_message = "Per-tool budget state is missing a tool fingerprint."
                    break
                if facts["tool_fingerprint"] != current_facts["tool_fingerprint"]:
                    continue
            payload_classes = config.get("payload_classes", [])
            if payload_classes:
                if facts["payload_size_class"] == "unknown":
                    unknown_message = "Payload-class budget state is unknown."
                    break
                if facts["payload_size_class"] not in payload_classes:
                    continue
            if not config.get("count_duplicates", True) and record["duplicate"]["detected"]:
                continue
            candidates.append(record)

        reasons: list[dict[str, str]] = []
        usage: int | float | None = None
        status = "ok"
        decision = "allow"
        if current_facts["confirmation"] != "confirmed":
            unknown_message = "Current action budget confirmation is not confirmed."
        if unknown_message is None:
            if config["metric"] == "calls":
                usage = len(candidates)
            elif config["metric"] == "impact":
                impacts = [record["budget_facts"]["impact"] for record in candidates]
                if any(value is None for value in impacts):
                    unknown_message = "Impact budget state is missing a numeric impact value."
                else:
                    usage = sum(impacts)
            else:
                targets = [record["budget_facts"]["target_fingerprint"] for record in candidates]
                if any(value is None for value in targets):
                    unknown_message = "Unique-target budget state is missing a target fingerprint."
                else:
                    usage = len(set(targets))
        if unknown_message is not None:
            status = "unknown"
            decision = "deny"
            reasons.append(
                _reason(
                    rule_id,
                    "deny",
                    "unknown-state",
                    unknown_message,
                )
            )
        elif usage is not None and usage > config["limit"]:
            status = "exceeded"
            decision = effect
            reasons.append(
                _reason(
                    rule_id,
                    effect,
                    f"usage:{usage};limit:{config['limit']}",
                    "Cumulative budget usage exceeds the configured limit.",
                )
            )
        results.append(
            {
                "subject": budget_id,
                "decision": decision,
                "risk_level": risk_for(decision),
                "status": status,
                "metric": config["metric"],
                "window": config["window"],
                "usage": usage,
                "limit": config["limit"],
                "reasons": reasons,
            }
        )

    if results:
        decision = max((result["decision"] for result in results), key=DECISION_RANK.get)
        status = (
            "unknown"
            if any(row["status"] == "unknown" for row in results)
            else ("exceeded" if any(row["status"] == "exceeded" for row in results) else "ok")
        )
        payload: dict[str, Any] = {
            "schema_version": 1,
            "kind": "policy_budget_check",
            "source": Path(journal_path).name,
            "policy": policy_label,
            "policy_provenance": policy_provenance(policy),
            "status": status,
            "decision": decision,
            "risk_level": risk_for(decision),
            "results": results,
        }
    else:
        payload = {
            "schema_version": 1,
            "kind": "policy_budget_check",
            "source": Path(journal_path).name,
            "policy": policy_label,
            "policy_provenance": policy_provenance(policy),
            "status": "not-applicable",
            "decision": "allow",
            "risk_level": "low",
            "subject": "budget-check",
            "reasons": [],
        }
    return attach_receipt(
        payload,
        policy,
        {
            "contract": "budget-check-v1",
            "event_id": event_id,
            "applicable_budgets": len(results),
        },
    )
