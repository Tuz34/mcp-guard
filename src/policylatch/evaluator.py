from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlparse

from .matching import domain_matches, path_matches, text_matches
from .models import Evaluation, Reason, decision_for, risk_for
from .policy import default_decision
from .validation import InputError, validate_action


def _text_reasons(
    value: str,
    patterns: list[str],
    rule: str,
    effect: Literal["warn", "deny"],
    message: str,
) -> list[Reason]:
    return [
        Reason(rule, effect, pattern, message)
        for pattern in patterns
        if text_matches(value, pattern)
    ]


def _path_reasons(
    value: str,
    patterns: list[str],
    rule: str,
    effect: Literal["warn", "deny"],
    message: str,
) -> list[Reason]:
    return [
        Reason(rule, effect, pattern, message)
        for pattern in patterns
        if path_matches(value, pattern)
    ]


def evaluate_action(action: dict[str, Any], policy: dict[str, Any]) -> Evaluation:
    validate_action(action)
    reasons: list[Reason] = []
    rules = policy["rules"]
    action_type = action["action_type"].lower()

    if action_type == "shell":
        command = action["command"]
        shell = rules.get("shell", {})
        reasons += _text_reasons(
            command,
            shell.get("deny_patterns", []),
            "shell.deny_patterns",
            "deny",
            "Blocked shell pattern detected.",
        )
        reasons += _text_reasons(
            command,
            shell.get("warn_patterns", []),
            "shell.warn_patterns",
            "warn",
            "Shell action requires review.",
        )
    elif action_type in {"file", "filesystem"}:
        path = action["path"]
        files = rules.get("files", {})
        reasons += _path_reasons(
            path,
            files.get("deny_paths", []),
            "files.deny_paths",
            "deny",
            "Sensitive path is blocked.",
        )
        reasons += _path_reasons(
            path,
            files.get("warn_paths", []),
            "files.warn_paths",
            "warn",
            "File path requires review.",
        )
    else:
        url = action.get("url")
        target = url if isinstance(url, str) and url.strip() else action["domain"]
        parsed = urlparse(target if "://" in target else f"//{target}")
        domain = (parsed.hostname or "").lower()
        if not domain:
            raise InputError("Network action URL or domain does not contain a valid hostname.")
        network = rules.get("network", {})
        for pattern in network.get("deny_domains", []):
            if domain_matches(domain, pattern):
                reasons.append(
                    Reason(
                        "network.deny_domains",
                        "deny",
                        pattern,
                        "Destination domain is blocked.",
                    )
                )
        allowed = network.get("allow_domains", [])
        if allowed and not any(domain_matches(domain, pattern) for pattern in allowed):
            reasons.append(
                Reason(
                    "network.allow_domains",
                    "warn",
                    "outside-allowlist",
                    "Destination is not on the allow list.",
                )
            )

    decision = decision_for(reasons, default_decision(policy))
    return Evaluation(decision, risk_for(decision), reasons, action.get("tool", "action"))
