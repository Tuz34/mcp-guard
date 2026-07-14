from __future__ import annotations

import fnmatch
import json
from typing import Any


def text_matches(value: str, pattern: str) -> bool:
    value_lower = value.lower()
    pattern_lower = pattern.lower()
    if "*" in pattern_lower or "?" in pattern_lower:
        return fnmatch.fnmatch(value_lower, f"*{pattern_lower}*")
    return pattern_lower in value_lower


def name_matches(value: str, pattern: str) -> bool:
    """Match a complete tool name with case-insensitive glob semantics."""
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def path_matches(value: str, pattern: str) -> bool:
    normalized = value.replace("\\", "/").lower()
    normalized_pattern = pattern.replace("\\", "/").lower()
    patterns = [normalized_pattern]
    if normalized_pattern.startswith("**/"):
        # In policy syntax, **/ means zero or more directories. Python's fnmatch
        # requires a slash here, so also test the top-level form explicitly.
        patterns.append(normalized_pattern[3:])
    # Paths use glob semantics only. Substring fallback would make a segment such
    # as ``mysecrets`` match the distinct policy segment ``secrets``.
    return any(fnmatch.fnmatch(normalized, candidate) for candidate in patterns)


def domain_matches(domain: str, pattern: str) -> bool:
    return fnmatch.fnmatch(domain.lower().rstrip("."), pattern.lower().rstrip("."))


def flatten_schema(schema: dict[str, Any]) -> str:
    return json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
