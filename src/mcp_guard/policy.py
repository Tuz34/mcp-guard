from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Decision

VALID_DECISIONS = {"allow", "warn", "deny"}
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


class PolicyError(ValueError):
    """Raised when a policy cannot be parsed or validated."""


def _string_list(value: Any, location: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"{location} must be a list of strings.")
    if any(not item.strip() for item in value):
        raise PolicyError(f"{location} cannot contain empty patterns.")
    return value


def load_policy(path: str | Path) -> dict[str, Any]:
    policy_path = Path(path)
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"Could not read policy '{policy_path}': {exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"Invalid YAML in policy '{policy_path}': {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyError("Policy must be a YAML mapping.")
    unknown_top_level = set(raw) - {"version", "default_decision", "rules"}
    if unknown_top_level:
        names = ", ".join(sorted(unknown_top_level))
        raise PolicyError(f"Unknown top-level policy field(s): {names}")
    if raw.get("version") != 1:
        raise PolicyError("Only policy version 1 is supported.")

    default = raw.get("default_decision", "warn")
    if default not in VALID_DECISIONS:
        raise PolicyError("default_decision must be allow, warn, or deny.")
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

    return {"version": 1, "default_decision": default, "rules": rules}


def default_decision(policy: dict[str, Any]) -> Decision:
    return policy["default_decision"]
