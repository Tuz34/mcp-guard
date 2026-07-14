from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .matching import domain_matches
from .receipts import attach_receipt, canonical_json
from .validation import InputError

MAX_TOOL_RESULT_BYTES = 1024 * 1024
MAX_CONTENT_BYTES = 512 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_FIELDS = 128
MAX_FIELD_NAME_CHARS = 128
MAX_FIELD_VALUE_BYTES = 64 * 1024
MAX_EXPECTED_DOMAINS = 64

_PROMPT_MARKERS = (
    "developer message",
    "follow these instructions",
    "ignore previous instructions",
    "reveal the system prompt",
    "system message",
)
_EXFILTRATION_MARKERS = (
    "exfiltrate",
    "post the data",
    "send this to",
    "upload this",
)
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|password|secret)\b\s*[:=]\s*[^\s,;]{4,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_PII_FIELD_TOKENS = {
    "address",
    "birth",
    "dob",
    "email",
    "passport",
    "phone",
    "ssn",
}
_ALLOWED_FIELDS = {
    "schema_version",
    "kind",
    "request_id",
    "result_id",
    "tool",
    "source_trust",
    "content",
    "fields",
    "expected_domains",
}


def _fingerprint(label: str, value: str) -> str:
    digest = hashlib.sha256(canonical_json({label: value}).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _required_text(data: dict[str, Any], field: str, max_chars: int) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"tool_result.{field} must be a non-empty string.")
    if len(value) > max_chars:
        raise InputError(f"tool_result.{field} cannot exceed {max_chars} characters.")
    return value


def validate_tool_result(data: dict[str, Any]) -> dict[str, Any]:
    unknown = set(data) - _ALLOWED_FIELDS
    if unknown:
        raise InputError("tool_result contains unsupported fields.")
    if data.get("schema_version") != 1 or data.get("kind") != "tool_result":
        raise InputError("tool_result schema_version must be 1 and kind must be tool_result.")
    _required_text(data, "request_id", 256)
    _required_text(data, "result_id", 256)
    _required_text(data, "tool", 256)
    if data.get("source_trust") not in {"trusted-local", "unknown", "untrusted"}:
        raise InputError("tool_result.source_trust is invalid.")
    content = data.get("content", "")
    if not isinstance(content, str):
        raise InputError("tool_result.content must be a string.")
    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise InputError(f"tool_result.content exceeds the {MAX_CONTENT_BYTES}-byte limit.")
    if any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in content.splitlines()):
        raise InputError(f"tool_result.content line exceeds the {MAX_LINE_BYTES}-byte limit.")
    fields = data.get("fields", {})
    if not isinstance(fields, dict) or len(fields) > MAX_FIELDS:
        raise InputError(f"tool_result.fields must be an object with at most {MAX_FIELDS} fields.")
    for name, value in fields.items():
        if not isinstance(name, str) or not name or len(name) > MAX_FIELD_NAME_CHARS:
            raise InputError("tool_result field names are invalid.")
        if not isinstance(value, str):
            raise InputError("tool_result field values must be strings.")
        if len(value.encode("utf-8")) > MAX_FIELD_VALUE_BYTES:
            raise InputError(
                f"tool_result field value exceeds the {MAX_FIELD_VALUE_BYTES}-byte limit."
            )
        if any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in value.splitlines()):
            raise InputError(
                f"tool_result field value line exceeds the {MAX_LINE_BYTES}-byte limit."
            )
    expected = data.get("expected_domains", [])
    if (
        not isinstance(expected, list)
        or len(expected) > MAX_EXPECTED_DOMAINS
        or not all(isinstance(item, str) and _DOMAIN.fullmatch(item) for item in expected)
    ):
        raise InputError("tool_result.expected_domains contains invalid domain patterns.")
    return data


def _scanner_policy() -> dict[str, Any]:
    rule_ids = (
        "tool-result.exfiltration-direction",
        "tool-result.external-url",
        "tool-result.pii-field-name",
        "tool-result.prompt-injection",
        "tool-result.secret-like-content",
    )
    return {
        "version": 1,
        "default_decision": "allow",
        "rules": {
            "tool_result": {
                "prompt_markers": list(_PROMPT_MARKERS),
                "exfiltration_markers": list(_EXFILTRATION_MARKERS),
                "secret_pattern_count": len(_SECRET_PATTERNS),
            }
        },
        "_provenance": {
            "profiles": [],
            "sources": ["builtin:tool-result-v1"],
            "default_decision_source": "builtin:tool-result-v1",
            "rule_sources": {rule_id: "builtin:tool-result-v1" for rule_id in rule_ids},
        },
    }


def scan_tool_result(data: dict[str, Any], source: str) -> dict[str, Any]:
    validate_tool_result(data)
    request_fingerprint = _fingerprint("request_id", data["request_id"])
    result_fingerprint = _fingerprint("result_id", data["result_id"])
    tool_fingerprint = _fingerprint("tool", data["tool"])
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: str, effect: str, category: str, message: str, location: str) -> None:
        key = (rule, location)
        if key in seen:
            return
        seen.add(key)
        occurrence = _fingerprint(
            "finding",
            canonical_json(
                {"category": category, "location": location, "request": request_fingerprint}
            ),
        )
        findings.append(
            {
                "rule": rule,
                "effect": effect,
                "matched": f"redacted:{occurrence}",
                "message": message,
            }
        )

    values = [("content", data.get("content", ""))]
    fields = data.get("fields", {})
    for index, (name, value) in enumerate(sorted(fields.items(), key=lambda item: item[0])):
        tokens = {token for token in re.split(r"[^a-z0-9]+", name.casefold()) if token}
        if tokens & _PII_FIELD_TOKENS:
            add(
                "tool-result.pii-field-name",
                "warn",
                "pii-field-name",
                "Result field name indicates possible personal data.",
                f"field-name:{index}",
            )
        values.append((f"field-value:{index}", value))

    expected_domains = data.get("expected_domains", [])
    for location, value in values:
        lowered = value.casefold()
        if any(marker in lowered for marker in _PROMPT_MARKERS):
            add(
                "tool-result.prompt-injection",
                "deny",
                "prompt-injection",
                "Untrusted result contains an instruction-smuggling marker.",
                location,
            )
        if any(marker in lowered for marker in _EXFILTRATION_MARKERS):
            add(
                "tool-result.exfiltration-direction",
                "deny",
                "exfiltration-direction",
                "Untrusted result directs a later step to transmit data.",
                location,
            )
        if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
            add(
                "tool-result.secret-like-content",
                "deny",
                "secret-like-content",
                "Result contains a secret-like value pattern.",
                location,
            )
        for url_index, match in enumerate(_URL.finditer(value)):
            hostname = (urlparse(match.group(0)).hostname or "").casefold()
            expected = bool(hostname) and any(
                domain_matches(hostname, pattern) for pattern in expected_domains
            )
            if not expected:
                add(
                    "tool-result.external-url",
                    "warn",
                    "unexpected-external-url",
                    "Result contains a URL outside the declared expected domains.",
                    f"{location}:url:{url_index}",
                )

    findings.sort(key=lambda item: (item["rule"], item["matched"]))
    if any(finding["effect"] == "deny" for finding in findings):
        outcome, decision, risk = "block-next-step", "deny", "high"
    elif findings:
        outcome, decision, risk = "review", "warn", "medium"
    else:
        outcome, decision, risk = "clean", "allow", "low"
    report = {
        "schema_version": 1,
        "kind": "tool_result_scan",
        "source": Path(source).name,
        "postflight_outcome": outcome,
        "decision": decision,
        "risk_level": risk,
        "subject": "tool-result",
        "source_trust": data["source_trust"],
        "correlation": {
            "request_fingerprint": request_fingerprint,
            "result_fingerprint": result_fingerprint,
            "tool_fingerprint": tool_fingerprint,
        },
        "summary": {
            "findings": len(findings),
            "review": sum(item["effect"] == "warn" for item in findings),
            "block_next_step": sum(item["effect"] == "deny" for item in findings),
        },
        "reasons": findings,
        "recommended_action": {
            "clean": "Continue only within the original request scope.",
            "review": "Require review before using this result in another action.",
            "block-next-step": "Do not feed this result into another tool or agent step.",
        }[outcome],
    }
    projection = {
        "contract": "tool-result-v1",
        "source_trust": data["source_trust"],
        "content_present": bool(data.get("content")),
        "field_count": len(fields),
        "expected_domain_count": len(expected_domains),
    }
    return attach_receipt(report, _scanner_policy(), projection)
