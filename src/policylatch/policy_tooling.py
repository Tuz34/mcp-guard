from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .evaluator import evaluate_action
from .gateway import evaluate_mcp_request
from .models import risk_for
from .policy import VALID_DECISIONS, policy_provenance
from .validation import InputError

MAX_FIXTURE_BYTES = 256 * 1024
MAX_FIXTURE_TOTAL_BYTES = 8 * 1024 * 1024
MAX_FIXTURES = 256


def _fixture_paths(path: str | Path) -> list[Path]:
    target = Path(path)
    if target.is_file():
        return [target]
    if not target.is_dir():
        raise InputError(f"Policy test fixture path '{target}' does not exist.")
    paths = sorted(item for item in target.iterdir() if item.is_file() and item.suffix == ".json")
    if not paths:
        raise InputError("Policy test fixture directory contains no JSON files.")
    if len(paths) > MAX_FIXTURES:
        raise InputError(f"Policy test fixture count exceeds the {MAX_FIXTURES}-file limit.")
    return paths


def load_policy_fixtures(path: str | Path) -> list[tuple[str, dict[str, Any]]]:
    fixtures: list[tuple[str, dict[str, Any]]] = []
    total = 0
    for fixture_path in _fixture_paths(path):
        try:
            with fixture_path.open("rb") as handle:
                raw = handle.read(MAX_FIXTURE_BYTES + 1)
        except OSError as exc:
            raise InputError(f"Could not read policy test fixture '{fixture_path}': {exc}") from exc
        if len(raw) > MAX_FIXTURE_BYTES:
            raise InputError(
                f"Policy test fixture '{fixture_path}' exceeds the {MAX_FIXTURE_BYTES}-byte limit."
            )
        total += len(raw)
        if total > MAX_FIXTURE_TOTAL_BYTES:
            raise InputError(
                f"Policy test fixtures exceed the {MAX_FIXTURE_TOTAL_BYTES}-byte total limit."
            )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise InputError(f"Invalid JSON policy test fixture '{fixture_path}'.") from exc
        if not isinstance(payload, dict):
            raise InputError(f"Policy test fixture '{fixture_path}' must be an object.")
        fixtures.append((fixture_path.name, payload))
    return fixtures


def policy_test_document(
    fixtures: list[tuple[str, dict[str, Any]]],
    policy: dict[str, Any],
    policy_label: str,
    source: str,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    failures = 0
    for name, fixture in fixtures:
        expected = fixture.get("_expected")
        if expected not in VALID_DECISIONS:
            raise InputError(f"Fixture '{name}' _expected must be allow, warn, or deny.")
        kind = fixture.get("_kind")
        if kind not in {None, "action", "gateway"}:
            raise InputError(f"Fixture '{name}' _kind must be action or gateway.")
        evaluator_input = {key: value for key, value in fixture.items() if not key.startswith("_")}
        is_gateway = kind == "gateway" or (kind is None and "jsonrpc" in evaluator_input)
        evaluation = (
            evaluate_mcp_request(evaluator_input, policy).evaluation
            if is_gateway
            else evaluate_action(evaluator_input, policy)
        )
        passed = evaluation.decision == expected
        failures += not passed
        result = {
            "subject": name,
            "decision": "allow" if passed else "deny",
            "risk_level": "low" if passed else "high",
            "expected": expected,
            "actual": evaluation.decision,
            "passed": passed,
            "reasons": [],
        }
        if not passed:
            result["reasons"].append(
                {
                    "rule": "policy-test.expected-decision",
                    "effect": "deny",
                    "matched": f"expected:{expected};actual:{evaluation.decision}",
                    "message": "Fixture decision did not match its declared expectation.",
                }
            )
        results.append(result)
    decision = "deny" if failures else "allow"
    return {
        "schema_version": 1,
        "kind": "policy_test",
        "source": Path(source).name,
        "policy": policy_label,
        "policy_provenance": policy_provenance(policy),
        "decision": decision,
        "risk_level": risk_for(decision),
        "summary": {"total": len(results), "passed": len(results) - failures, "failed": failures},
        "results": results,
    }


def _finding(rule: str, matched: str, message: str) -> dict[str, str]:
    return {"rule": rule, "effect": "warn", "matched": matched, "message": message}


def _normalized(values: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for value in values:
        grouped.setdefault(value.casefold(), []).append(value)
    return grouped


def lint_policy_document(policy: dict[str, Any], policy_label: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    rules = policy["rules"]
    for section, values in sorted(rules.items()):
        for rule_name, patterns in sorted(values.items()):
            location = f"{section}.{rule_name}"
            for variants in _normalized(patterns).values():
                if len(variants) > 1:
                    findings.append(
                        _finding(
                            "policy-lint.duplicate-pattern",
                            variants[0],
                            f"{location} contains the same case-insensitive pattern "
                            "more than once.",
                        )
                    )
            for pattern in patterns:
                compact = pattern.strip().casefold()
                if compact in {"*", "**", "/", "\\", "."} or len(compact) < 3:
                    findings.append(
                        _finding(
                            "policy-lint.overly-broad-pattern",
                            pattern,
                            f"{location} contains a pattern broad enough to dominate "
                            "normal matches.",
                        )
                    )

    conflicting_pairs = (
        ("network", "allow_domains", "deny_domains"),
        ("mcp_tools", "allow_names", "deny_names"),
    )
    for section, allow_name, deny_name in conflicting_pairs:
        values = rules.get(section, {})
        allow = {item.casefold(): item for item in values.get(allow_name, [])}
        deny = {item.casefold(): item for item in values.get(deny_name, [])}
        for key in sorted(set(allow) & set(deny)):
            findings.append(
                _finding(
                    "policy-lint.conflicting-signal",
                    allow[key],
                    f"{section} contains the same pattern in {allow_name} and {deny_name}.",
                )
            )

    shadow_pairs = (
        ("shell", "deny_patterns", "warn_patterns"),
        ("files", "deny_paths", "warn_paths"),
    )
    for section, deny_name, warn_name in shadow_pairs:
        values = rules.get(section, {})
        deny_patterns = values.get(deny_name, [])
        for warning in values.get(warn_name, []):
            if section == "shell":
                shadowed = any(block.casefold() in warning.casefold() for block in deny_patterns)
            else:
                warning_key = warning.casefold()
                shadowed = any(
                    block.casefold() == warning_key or block.strip() in {"*", "**"}
                    for block in deny_patterns
                )
            if shadowed:
                findings.append(
                    _finding(
                        "policy-lint.shadowed-warning",
                        warning,
                        f"{section}.{warn_name} is always superseded by a matching deny pattern.",
                    )
                )

    decision = "warn" if findings else "allow"
    return {
        "schema_version": 1,
        "kind": "policy_lint",
        "source": policy_label,
        "policy": policy_label,
        "policy_provenance": policy_provenance(policy),
        "decision": decision,
        "risk_level": risk_for(decision),
        "summary": {"findings": len(findings)},
        "subject": policy_label,
        "reasons": findings,
    }
