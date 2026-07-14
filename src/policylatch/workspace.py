from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .models import DECISION_RANK, aggregate, risk_for
from .policy import policy_provenance
from .receipts import (
    attach_receipt,
    canonical_json,
    canonical_policy_hash,
    report_request_projection,
    validate_receipt,
)
from .scanners import scan_manifest
from .validation import InputError, manifest_entries

DEFAULT_CONFIG_NAMES = frozenset(
    {".mcp.json", "mcp.json", "mcp-config.json", "claude_desktop_config.json"}
)
IGNORED_DIRECTORIES = frozenset(
    {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", "build", "dist"}
)
MAX_PATTERNS = 16
MAX_PATTERN_CHARS = 256
MAX_DEPTH_LIMIT = 32
MAX_FILE_LIMIT = 1_000
MAX_TOTAL_BYTE_LIMIT = 64 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_DIRECTORY_ENTRIES = 20_000
_ENTRY_FIELDS = {
    "path",
    "shape",
    "tool_count",
    "decision",
    "risk_level",
    "counts",
    "content_fingerprint",
    "entry_fingerprint",
}
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def _fingerprint(label: str, value: Any) -> str:
    try:
        encoded = canonical_json({"contract": label, "value": value}).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise InputError("Workspace value cannot be safely fingerprinted.") from exc
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _normalize_patterns(patterns: list[str] | None) -> tuple[str, ...]:
    values = patterns or []
    if len(values) > MAX_PATTERNS:
        raise InputError(f"Workspace scan accepts at most {MAX_PATTERNS} extra patterns.")
    normalized: list[str] = []
    for pattern in values:
        value = pattern.replace("\\", "/") if isinstance(pattern, str) else ""
        parts = PurePosixPath(value).parts
        if (
            not value
            or len(value) > MAX_PATTERN_CHARS
            or "\x00" in value
            or PurePosixPath(value).is_absolute()
            or ":" in value
            or ".." in parts
        ):
            raise InputError("Workspace patterns must be bounded relative paths without '..'.")
        normalized.append(value)
    return tuple(sorted(set(normalized)))


def _matches(relative: str, name: str, patterns: tuple[str, ...]) -> bool:
    if name.casefold() in DEFAULT_CONFIG_NAMES:
        return True
    folded = relative.casefold()
    return any(fnmatch.fnmatchcase(folded, pattern.casefold()) for pattern in patterns)


def _discover(
    root: Path,
    *,
    patterns: tuple[str, ...],
    max_depth: int,
    max_files: int,
) -> list[Path]:
    candidates: list[Path] = []
    entry_count = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name.casefold())
        except OSError as exc:
            raise InputError("Workspace directory could not be read safely.") from exc
        entry_count += len(entries)
        if entry_count > MAX_DIRECTORY_ENTRIES:
            raise InputError("Workspace traversal exceeds the directory-entry limit.")
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                is_symlink = entry.is_symlink()
                is_directory = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError as exc:
                raise InputError("Workspace entry type could not be verified.") from exc
            if is_symlink:
                if _matches(relative, entry.name, patterns):
                    try:
                        target = path.resolve(strict=True)
                    except OSError as exc:
                        raise InputError("Workspace config symlink cannot be resolved.") from exc
                    if not target.is_relative_to(root):
                        raise InputError("Workspace config symlink escapes the explicit root.")
                    raise InputError("Workspace config symlinks are not scanned.")
                continue
            if is_directory:
                if entry.name.casefold() in IGNORED_DIRECTORIES:
                    continue
                if depth >= max_depth:
                    raise InputError("Workspace traversal reached the configured depth limit.")
                stack.append((path, depth + 1))
                continue
            if is_file and _matches(relative, entry.name, patterns):
                if path.suffix.casefold() != ".json":
                    raise InputError("Workspace MCP patterns may select only JSON files.")
                candidates.append(path)
                if len(candidates) > max_files:
                    raise InputError("Workspace scan exceeds the configured file-count limit.")
    return sorted(candidates, key=lambda item: item.relative_to(root).as_posix().casefold())


def _strict_json(raw: bytes, relative: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(value)

    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise InputError(f"Workspace config '{relative}' is not strict bounded JSON.") from exc
    if not isinstance(data, dict):
        raise InputError(f"Workspace config '{relative}' must contain a JSON object.")
    return data


def _shape(manifest: dict[str, Any]) -> str:
    if "tools" in manifest:
        return "tools"
    if isinstance(manifest.get("server"), dict) and "tools" in manifest["server"]:
        return "server.tools"
    if "mcpServers" in manifest:
        return "mcpServers"
    return "unknown"


def workspace_scan_document(
    root_value: str | Path,
    policy: dict[str, Any],
    policy_label: str,
    *,
    patterns: list[str] | None = None,
    max_depth: int = 8,
    max_files: int = 100,
    max_total_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    if (
        isinstance(max_depth, bool)
        or not isinstance(max_depth, int)
        or not 0 <= max_depth <= MAX_DEPTH_LIMIT
    ):
        raise InputError(f"Workspace max depth must be between 0 and {MAX_DEPTH_LIMIT}.")
    if (
        isinstance(max_files, bool)
        or not isinstance(max_files, int)
        or not 1 <= max_files <= MAX_FILE_LIMIT
    ):
        raise InputError(f"Workspace max files must be between 1 and {MAX_FILE_LIMIT}.")
    if (
        isinstance(max_total_bytes, bool)
        or not isinstance(max_total_bytes, int)
        or not 1 <= max_total_bytes <= MAX_TOTAL_BYTE_LIMIT
    ):
        raise InputError("Workspace total-byte limit is outside the bounded contract.")
    try:
        root = Path(root_value).resolve(strict=True)
    except OSError as exc:
        raise InputError("Workspace root does not exist.") from exc
    if not root.is_dir():
        raise InputError("Workspace root must resolve to a directory.")
    files = _discover(
        root,
        patterns=_normalize_patterns(patterns),
        max_depth=max_depth,
        max_files=max_files,
    )
    if not files:
        raise InputError("Workspace scan found no matching MCP JSON configs.")

    inventory: list[dict[str, Any]] = []
    report_rows: list[dict[str, Any]] = []
    total_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        try:
            resolved_path = path.resolve(strict=True)
        except OSError as exc:
            raise InputError(f"Workspace config '{relative}' cannot be resolved.") from exc
        if path.is_symlink() or not resolved_path.is_relative_to(root):
            raise InputError(f"Workspace config '{relative}' changed to an unsafe path.")
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_FILE_BYTES + 1)
        except OSError as exc:
            raise InputError(f"Workspace config '{relative}' could not be read.") from exc
        if len(raw) > MAX_FILE_BYTES:
            raise InputError(f"Workspace config '{relative}' exceeds the file byte limit.")
        total_bytes += len(raw)
        if total_bytes > max_total_bytes:
            raise InputError("Workspace configs exceed the configured total-byte limit.")
        manifest = _strict_json(raw, relative)
        evaluations = scan_manifest(manifest, policy)
        entries = manifest_entries(manifest)
        decision, risk_level = aggregate(evaluations)
        counts = {
            name: sum(item.decision == name for item in evaluations) for name in DECISION_RANK
        }
        content_fingerprint = _fingerprint("workspace-config-content-v1", manifest)
        entry_core = {
            "path": relative,
            "shape": _shape(manifest),
            "tool_count": len(entries),
            "decision": decision,
            "risk_level": risk_level,
            "counts": counts,
            "content_fingerprint": content_fingerprint,
        }
        inventory.append(
            {
                **entry_core,
                "entry_fingerprint": _fingerprint("workspace-entry-v1", entry_core),
            }
        )
        unique_reasons = {
            (reason.rule, reason.effect, reason.message)
            for evaluation in evaluations
            for reason in evaluation.reasons
        }
        report_rows.append(
            {
                "subject": relative,
                "decision": decision,
                "risk_level": risk_level,
                "reasons": [
                    {
                        "rule": rule,
                        "effect": effect,
                        "matched": "redacted:workspace-policy-match",
                        "message": message,
                    }
                    for rule, effect, message in sorted(unique_reasons)
                ],
            }
        )
    decision = max((row["decision"] for row in report_rows), key=DECISION_RANK.get)
    risk_level = risk_for(decision)
    summary = {
        "files": len(inventory),
        "tools": sum(entry["tool_count"] for entry in inventory),
        "allow": sum(entry["counts"]["allow"] for entry in inventory),
        "warn": sum(entry["counts"]["warn"] for entry in inventory),
        "deny": sum(entry["counts"]["deny"] for entry in inventory),
        "bytes_read": total_bytes,
    }
    baseline_core = {
        "policy_hash": canonical_policy_hash(policy),
        "inventory": inventory,
    }
    document = {
        "schema_version": 1,
        "kind": "workspace_inventory",
        "source": root.name,
        "policy": policy_label,
        "policy_provenance": policy_provenance(policy),
        "decision": decision,
        "risk_level": risk_level,
        "summary": summary,
        "baseline_fingerprint": _fingerprint("workspace-baseline-v1", baseline_core),
        "inventory": inventory,
        "results": report_rows,
    }
    return attach_receipt(document, policy, report_request_projection(document))


def _validate_inventory_document(data: dict[str, Any]) -> list[dict[str, Any]]:
    if data.get("schema_version") != 1 or data.get("kind") != "workspace_inventory":
        raise InputError("Workspace baseline must be a version 1 inventory document.")
    inventory = data.get("inventory")
    if not isinstance(inventory, list) or not inventory:
        raise InputError("Workspace baseline inventory must be a non-empty array.")
    seen: set[str] = set()
    for entry in inventory:
        if not isinstance(entry, dict) or set(entry) != _ENTRY_FIELDS:
            raise InputError("Workspace baseline entry fields are invalid.")
        path = entry.get("path")
        if (
            not isinstance(path, str)
            or not path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
            or path in seen
        ):
            raise InputError("Workspace baseline contains an invalid relative path.")
        seen.add(path)
        counts = entry.get("counts")
        if (
            entry.get("shape") not in {"tools", "server.tools", "mcpServers"}
            or entry.get("decision") not in DECISION_RANK
            or entry.get("risk_level") != risk_for(entry["decision"])
            or isinstance(entry.get("tool_count"), bool)
            or not isinstance(entry.get("tool_count"), int)
            or entry["tool_count"] <= 0
            or not isinstance(counts, dict)
            or set(counts) != set(DECISION_RANK)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in counts.values()
            )
            or sum(counts.values()) != entry["tool_count"]
            or not isinstance(entry.get("content_fingerprint"), str)
            or not _HASH.fullmatch(entry["content_fingerprint"])
            or not isinstance(entry.get("entry_fingerprint"), str)
            or not _HASH.fullmatch(entry["entry_fingerprint"])
        ):
            raise InputError("Workspace baseline entry values are invalid.")
        core = {key: entry[key] for key in _ENTRY_FIELDS if key != "entry_fingerprint"}
        if entry["entry_fingerprint"] != _fingerprint("workspace-entry-v1", core):
            raise InputError("Workspace baseline entry fingerprint does not match its content.")
    receipt = data.get("receipt")
    if not isinstance(receipt, dict):
        raise InputError("Workspace baseline decision receipt is missing.")
    validate_receipt(receipt)
    policy_hash = receipt.get("policy", {}).get("hash") if isinstance(receipt, dict) else None
    baseline_fingerprint = data.get("baseline_fingerprint")
    if (
        not isinstance(policy_hash, str)
        or not _HASH.fullmatch(policy_hash)
        or not isinstance(baseline_fingerprint, str)
        or not _HASH.fullmatch(baseline_fingerprint)
        or baseline_fingerprint
        != _fingerprint(
            "workspace-baseline-v1", {"policy_hash": policy_hash, "inventory": inventory}
        )
    ):
        raise InputError("Workspace baseline fingerprint does not match its inventory.")
    return inventory


def workspace_diff_document(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    fail_on: str,
) -> dict[str, Any]:
    if fail_on not in {"risk-increase", "never"}:
        raise InputError("Workspace diff fail_on must be risk-increase or never.")
    before_entries = {entry["path"]: entry for entry in _validate_inventory_document(before)}
    after_entries = {entry["path"]: entry for entry in _validate_inventory_document(after)}
    before_policy_hash = before["receipt"]["policy"]["hash"]
    after_policy_hash = after["receipt"]["policy"]["hash"]
    policy_changed = before_policy_hash != after_policy_hash
    added = sorted(set(after_entries) - set(before_entries))
    removed = sorted(set(before_entries) - set(after_entries))
    changed = sorted(
        path
        for path in set(before_entries) & set(after_entries)
        if before_entries[path]["entry_fingerprint"] != after_entries[path]["entry_fingerprint"]
    )
    risk_increases = sorted(
        [
            path
            for path in changed
            if DECISION_RANK[after_entries[path]["decision"]]
            > DECISION_RANK[before_entries[path]["decision"]]
        ]
        + [path for path in added if after_entries[path]["decision"] != "allow"]
    )
    paths = sorted(set(added + removed + changed))
    rows: list[dict[str, Any]] = []
    subjects = paths or (["policy"] if policy_changed else ["workspace"])
    for path in subjects:
        increased = path in risk_increases
        policy_only = path == "policy"
        rows.append(
            {
                "subject": path,
                "decision": ("deny" if increased else ("warn" if path != "workspace" else "allow")),
                "risk_level": "high" if increased else ("medium" if path != "workspace" else "low"),
                "reasons": (
                    [
                        {
                            "rule": (
                                "workspace.risk-increase"
                                if increased
                                else (
                                    "workspace.policy-changed"
                                    if policy_only
                                    else "workspace.changed"
                                )
                            ),
                            "effect": "deny" if increased else "warn",
                            "matched": "redacted:workspace-entry-fingerprint",
                            "message": (
                                "Workspace MCP configuration risk increased."
                                if increased
                                else (
                                    "Workspace policy fingerprint changed."
                                    if policy_only
                                    else "Workspace MCP configuration changed."
                                )
                            ),
                        }
                    ]
                    if path != "workspace"
                    else []
                ),
            }
        )
    gate_failed = fail_on == "risk-increase" and bool(risk_increases)
    decision = "deny" if gate_failed else ("warn" if paths or policy_changed else "allow")
    return {
        "schema_version": 1,
        "kind": "workspace_diff",
        "source": "workspace-baselines",
        "decision": decision,
        "risk_level": "high" if gate_failed else ("medium" if paths else "low"),
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "risk_increases": len(risk_increases),
            "policy_changed": int(policy_changed),
        },
        "changes": {
            "added": added,
            "removed": removed,
            "changed": changed,
            "risk_increases": risk_increases,
            "policy_changed": policy_changed,
        },
        "gate": {"fail_on": fail_on, "failed": gate_failed},
        "comparison_fingerprint": _fingerprint(
            "workspace-diff-v1",
            {
                "before": before.get("baseline_fingerprint"),
                "after": after.get("baseline_fingerprint"),
                "fail_on": fail_on,
            },
        ),
        "results": rows,
    }
