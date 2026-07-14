from __future__ import annotations

import math
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from .models import Decision
from .profiles import builtin_profile, profile_names

VALID_DECISIONS = {"allow", "warn", "deny"}
MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_TOTAL_BYTES = 4 * 1024 * 1024
MAX_POLICY_FILES = 16
MAX_POLICY_DEPTH = 8
RULE_KEYS = {
    "shell": {"deny_patterns", "warn_patterns"},
    "files": {"deny_paths", "warn_paths"},
    "network": {"allow_domains", "deny_domains"},
    "mcp_tools": {
        "allow_names",
        "deny_names",
        "deny_if_description_contains",
        "warn_if_name_contains",
        "warn_if_schema_contains",
    },
}
MAX_BUDGETS = 128
_BUDGET_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_ACTION_TYPES = {"file", "filesystem", "network", "shell"}


class PolicyError(ValueError):
    """Raised when a policy cannot be parsed or validated."""


def _string_list(value: Any, location: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"{location} must be a list of strings.")
    if any(not item.strip() for item in value):
        raise PolicyError(f"{location} cannot contain empty patterns.")
    return value


def _read_mapping(policy_path: Path, state: dict[str, int]) -> dict[str, Any]:
    try:
        with policy_path.open("rb") as handle:
            encoded = handle.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise PolicyError(f"Could not read policy '{policy_path}': {exc}") from exc
    if len(encoded) > MAX_POLICY_BYTES:
        raise PolicyError(f"Policy '{policy_path}' exceeds the {MAX_POLICY_BYTES}-byte limit.")
    state["files"] += 1
    state["bytes"] += len(encoded)
    if state["files"] > MAX_POLICY_FILES:
        raise PolicyError(f"Policy inheritance exceeds the {MAX_POLICY_FILES}-file limit.")
    if state["bytes"] > MAX_POLICY_TOTAL_BYTES:
        raise PolicyError(
            f"Policy inheritance exceeds the {MAX_POLICY_TOTAL_BYTES}-byte total limit."
        )
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(f"Policy '{policy_path}' must be valid UTF-8.") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"Invalid YAML in policy '{policy_path}': {exc}") from exc
    except RecursionError as exc:
        raise PolicyError(f"Policy '{policy_path}' is nested too deeply.") from exc

    if not isinstance(raw, dict):
        raise PolicyError("Policy must be a YAML mapping.")
    return raw


def _validate_mapping(raw: dict[str, Any]) -> None:
    unknown_top_level = set(raw) - {
        "version",
        "default_decision",
        "rules",
        "profile",
        "extends",
        "budgets",
    }
    if unknown_top_level:
        names = ", ".join(sorted(unknown_top_level))
        raise PolicyError(f"Unknown top-level policy field(s): {names}")
    if raw.get("version") != 1:
        raise PolicyError("Only policy version 1 is supported.")

    if "default_decision" in raw and raw["default_decision"] not in VALID_DECISIONS:
        raise PolicyError("default_decision must be allow, warn, or deny.")
    profile = raw.get("profile")
    if profile is not None:
        if not isinstance(profile, str) or not profile.strip():
            raise PolicyError("profile must be a non-empty built-in profile name.")
        if profile not in profile_names():
            available = ", ".join(profile_names())
            raise PolicyError(
                f"Unknown policy profile '{profile}'. Available profiles: {available}."
            )
    extends = raw.get("extends", [])
    if isinstance(extends, str):
        extends = [extends]
    if not isinstance(extends, list) or not all(isinstance(item, str) for item in extends):
        raise PolicyError("extends must be a relative path or a list of relative paths.")
    if any(not item.strip() for item in extends):
        raise PolicyError("extends cannot contain an empty path.")
    if len(extends) > MAX_POLICY_FILES:
        raise PolicyError(f"extends cannot contain more than {MAX_POLICY_FILES} paths.")
    rules = raw.get("rules", {})
    if not isinstance(rules, dict):
        raise PolicyError("rules must be a mapping.")

    unknown_sections = set(rules) - set(RULE_KEYS)
    if unknown_sections:
        names = ", ".join(sorted(unknown_sections))
        raise PolicyError(f"Unknown rule section(s): {names}")
    for section, values in rules.items():
        if not isinstance(values, dict):
            raise PolicyError(f"rules.{section} must be a mapping.")
        unknown_rules = set(values) - RULE_KEYS[section]
        if unknown_rules:
            names = ", ".join(sorted(unknown_rules))
            raise PolicyError(f"Unknown rule(s) in rules.{section}: {names}")
        for name, patterns in values.items():
            _string_list(patterns, f"rules.{section}.{name}")

    budgets = raw.get("budgets", {})
    if not isinstance(budgets, dict) or len(budgets) > MAX_BUDGETS:
        raise PolicyError(f"budgets must be a mapping with at most {MAX_BUDGETS} entries.")
    allowed_budget_fields = {
        "metric",
        "limit",
        "window",
        "effect",
        "action_types",
        "per_tool",
        "count_duplicates",
        "payload_classes",
    }
    for budget_id, budget in budgets.items():
        if not isinstance(budget_id, str) or not _BUDGET_ID.fullmatch(budget_id):
            raise PolicyError("Budget IDs may use 1-64 letters, numbers, dot, dash, or underscore.")
        if not isinstance(budget, dict):
            raise PolicyError(f"budgets.{budget_id} must be a mapping.")
        unknown = set(budget) - allowed_budget_fields
        if unknown:
            raise PolicyError(f"budgets.{budget_id} contains unknown fields.")
        if budget.get("metric") not in {"calls", "impact", "unique_targets"}:
            raise PolicyError(f"budgets.{budget_id}.metric is invalid.")
        limit = budget.get("limit")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, (int, float))
            or not math.isfinite(limit)
            or limit <= 0
        ):
            raise PolicyError(f"budgets.{budget_id}.limit must be a positive finite number.")
        if budget["metric"] != "impact" and not isinstance(limit, int):
            raise PolicyError(f"budgets.{budget_id}.limit must be an integer for this metric.")
        if budget.get("window") not in {"hour", "day"}:
            raise PolicyError(f"budgets.{budget_id}.window must be hour or day.")
        if budget.get("effect", "deny") not in {"warn", "deny"}:
            raise PolicyError(f"budgets.{budget_id}.effect must be warn or deny.")
        action_types = budget.get("action_types", [])
        if (
            not isinstance(action_types, list)
            or not action_types
            or not all(isinstance(item, str) and item in _ACTION_TYPES for item in action_types)
        ):
            raise PolicyError(f"budgets.{budget_id}.action_types must list supported actions.")
        for field in ("per_tool", "count_duplicates"):
            if field in budget and not isinstance(budget[field], bool):
                raise PolicyError(f"budgets.{budget_id}.{field} must be boolean.")
        payload_classes = budget.get("payload_classes", [])
        if not isinstance(payload_classes, list) or not all(
            isinstance(item, str) and item in {"small", "medium", "large"}
            for item in payload_classes
        ):
            raise PolicyError(f"budgets.{budget_id}.payload_classes is invalid.")


def _empty_policy() -> dict[str, Any]:
    return {
        "version": 1,
        "default_decision": "warn",
        "rules": {},
        "budgets": {},
        "_provenance": {
            "profiles": [],
            "sources": [],
            "default_decision_source": "built-in-default",
            "rule_sources": {},
            "budget_sources": {},
        },
    }


def _merge(target: dict[str, Any], overlay: dict[str, Any], source: str) -> None:
    provenance = target["_provenance"]
    if "default_decision" in overlay:
        target["default_decision"] = overlay["default_decision"]
        provenance["default_decision_source"] = source
    for section, values in overlay.get("rules", {}).items():
        destination = target["rules"].setdefault(section, {})
        for name, patterns in values.items():
            destination[name] = list(patterns)
            provenance["rule_sources"][f"{section}.{name}"] = source
    for budget_id, budget in overlay.get("budgets", {}).items():
        target["budgets"][budget_id] = deepcopy(budget)
        provenance["budget_sources"][budget_id] = source
        provenance["rule_sources"][f"budgets.{budget_id}"] = source
    if source not in provenance["sources"]:
        provenance["sources"].append(source)


def _merge_resolved(target: dict[str, Any], resolved: dict[str, Any]) -> None:
    source_map = resolved["_provenance"]["rule_sources"]
    if resolved["_provenance"]["default_decision_source"] != "built-in-default":
        target["default_decision"] = resolved["default_decision"]
        target["_provenance"]["default_decision_source"] = resolved["_provenance"][
            "default_decision_source"
        ]
    for section, values in resolved["rules"].items():
        destination = target["rules"].setdefault(section, {})
        for name, patterns in values.items():
            destination[name] = list(patterns)
            key = f"{section}.{name}"
            target["_provenance"]["rule_sources"][key] = source_map[key]
    for budget_id, budget in resolved.get("budgets", {}).items():
        target["budgets"][budget_id] = deepcopy(budget)
        source = resolved["_provenance"]["budget_sources"][budget_id]
        target["_provenance"]["budget_sources"][budget_id] = source
        target["_provenance"]["rule_sources"][f"budgets.{budget_id}"] = source
    for profile in resolved["_provenance"]["profiles"]:
        if profile not in target["_provenance"]["profiles"]:
            target["_provenance"]["profiles"].append(profile)
    for source in resolved["_provenance"]["sources"]:
        if source not in target["_provenance"]["sources"]:
            target["_provenance"]["sources"].append(source)


def load_profile(name: str) -> dict[str, Any]:
    try:
        raw = builtin_profile(name)
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc
    _validate_mapping(raw)
    resolved = _empty_policy()
    source = f"profile:{name}"
    resolved["_provenance"]["profiles"].append(name)
    _merge(resolved, raw, source)
    return resolved


def _source_label(path: Path, root: Path) -> str:
    return f"policy:{path.relative_to(root).as_posix()}"


def _resolve_reference(reference: str, current: Path, root: Path) -> Path:
    if "://" in reference:
        raise PolicyError("Remote policy includes are not supported.")
    raw_path = Path(reference)
    if raw_path.is_absolute():
        raise PolicyError("Policy extends paths must be relative.")
    candidate = (current.parent / raw_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PolicyError(
            "Policy extends path must stay inside the root policy directory."
        ) from exc
    return candidate


def _resolve_file(
    path: Path,
    *,
    root: Path,
    state: dict[str, int],
    stack: tuple[Path, ...],
) -> dict[str, Any]:
    resolved_path = path.resolve()
    if len(stack) >= MAX_POLICY_DEPTH:
        raise PolicyError(f"Policy inheritance exceeds the {MAX_POLICY_DEPTH}-level depth limit.")
    if resolved_path in stack:
        chain = " -> ".join(item.name for item in (*stack, resolved_path))
        raise PolicyError(f"Policy inheritance cycle detected: {chain}")

    raw = _read_mapping(resolved_path, state)
    _validate_mapping(raw)
    result = _empty_policy()
    profile = raw.get("profile")
    if profile:
        _merge_resolved(result, load_profile(profile))

    references = raw.get("extends", [])
    if isinstance(references, str):
        references = [references]
    for reference in references:
        inherited = _resolve_file(
            _resolve_reference(reference, resolved_path, root),
            root=root,
            state=state,
            stack=(*stack, resolved_path),
        )
        _merge_resolved(result, inherited)

    own_fields = {
        key: deepcopy(value)
        for key, value in raw.items()
        if key in {"default_decision", "rules", "budgets"}
    }
    _merge(result, own_fields, _source_label(resolved_path, root))
    return result


def load_policy(path: str | Path) -> dict[str, Any]:
    policy_path = Path(path).resolve()
    return _resolve_file(
        policy_path,
        root=policy_path.parent,
        state={"files": 0, "bytes": 0},
        stack=(),
    )


def policy_provenance(policy: dict[str, Any]) -> dict[str, Any]:
    return deepcopy(policy.get("_provenance", {}))


def default_decision(policy: dict[str, Any]) -> Decision:
    return policy["default_decision"]
