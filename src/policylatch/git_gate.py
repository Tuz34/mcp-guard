from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .models import DECISION_RANK, risk_for
from .receipts import canonical_json, validate_receipt
from .reports import validate_report
from .validation import InputError
from .workspace import DEFAULT_CONFIG_NAMES

MAX_DIFF_BYTES = 2 * 1024 * 1024
MAX_DIFF_LINES = 20_000
MAX_DIFF_LINE_BYTES = 64 * 1024
MAX_DIFF_FILES = 500
MAX_PATH_CHARS = 512
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class DiffChange:
    path: str
    old_path: str | None
    status: str
    category: str
    content_fingerprint: str
    unknown_metadata: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "old_path": self.old_path,
            "status": self.status,
            "category": self.category,
            "content_fingerprint": self.content_fingerprint,
            "unknown_metadata": self.unknown_metadata,
        }


def _fingerprint(label: str, value: Any) -> str:
    try:
        encoded = canonical_json({"contract": label, "value": value}).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise InputError("Git diff value cannot be safely fingerprinted.") from exc
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _tokens(value: str, label: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError as exc:
        raise InputError(f"Git diff {label} contains invalid quoting.") from exc


def _safe_path(value: str, *, prefix: str | None, allow_null: bool = False) -> str | None:
    if value == "/dev/null" and allow_null:
        return None
    if prefix is not None:
        if not value.startswith(prefix):
            raise InputError("Git diff path does not use the expected a/ or b/ prefix.")
        value = value[len(prefix) :]
    path = PurePosixPath(value)
    if (
        not value
        or len(value) > MAX_PATH_CHARS
        or "\x00" in value
        or "\\" in value
        or "//" in value
        or value.startswith("./")
        or value.strip() != value
        or path.is_absolute()
        or ".." in path.parts
        or ":" in value
    ):
        raise InputError("Git diff contains an absolute, traversal, or ambiguous path.")
    return path.as_posix()


def _header_path(line: str, marker: str, prefix: str) -> str | None:
    values = _tokens(line[len(marker) :].strip(), f"{marker.strip()} path")
    if len(values) != 1:
        raise InputError("Git diff file header path is ambiguous.")
    return _safe_path(values[0], prefix=prefix, allow_null=True)


def _category(path: str) -> str:
    parts = tuple(part.casefold() for part in PurePosixPath(path).parts)
    name = parts[-1]
    suffix = PurePosixPath(name).suffix.casefold()
    if name in DEFAULT_CONFIG_NAMES:
        return "mcp-config"
    if suffix in {".yaml", ".yml"} and (
        "policies" in parts or "policy" in name or name == ".policylatch.yaml"
    ):
        return "policy"
    if parts[0] == "examples" or "fixtures" in parts:
        return "fixture"
    return "other"


def _validate_hunks(lines: list[str]) -> int:
    hunk_indexes = [index for index, line in enumerate(lines) if line.startswith("@@")]
    for position, index in enumerate(hunk_indexes):
        match = _HUNK.fullmatch(lines[index])
        if match is None:
            raise InputError("Git diff contains a malformed hunk header.")
        old_expected = int(match.group(2) or 1)
        new_expected = int(match.group(4) or 1)
        old_seen = 0
        new_seen = 0
        end = hunk_indexes[position + 1] if position + 1 < len(hunk_indexes) else len(lines)
        for line in lines[index + 1 : end]:
            if line.startswith("\\ No newline at end of file"):
                continue
            if not line:
                raise InputError("Git diff hunk contains a line without a prefix.")
            prefix = line[0]
            if prefix == " ":
                old_seen += 1
                new_seen += 1
            elif prefix == "-":
                old_seen += 1
            elif prefix == "+":
                new_seen += 1
            else:
                raise InputError("Git diff hunk contains an unsupported line prefix.")
        if old_seen != old_expected or new_seen != new_expected:
            raise InputError("Git diff hunk is truncated or has inconsistent line counts.")
    return len(hunk_indexes)


def _parse_section(lines: list[str]) -> DiffChange:
    header = _tokens(lines[0], "header")
    if len(header) != 4 or header[:2] != ["diff", "--git"]:
        raise InputError("Git diff file header is malformed.")
    old_header = _safe_path(header[2], prefix="a/")
    new_header = _safe_path(header[3], prefix="b/")
    if old_header is None or new_header is None:
        raise InputError("Git diff header paths cannot be null.")

    old_path: str | None = old_header
    new_path: str | None = new_header
    rename_from: str | None = None
    rename_to: str | None = None
    binary = False
    unknown_metadata = False
    old_file_header_seen = False
    new_file_header_seen = False
    body_before_hunks: list[str] = []
    first_hunk = next(
        (index for index, line in enumerate(lines) if line.startswith("@@")), len(lines)
    )
    metadata = lines[1:first_hunk]
    for line in metadata:
        if line.startswith("--- "):
            old_path = _header_path(line, "--- ", "a/")
            old_file_header_seen = True
        elif line.startswith("+++ "):
            new_path = _header_path(line, "+++ ", "b/")
            new_file_header_seen = True
        elif line.startswith("rename from "):
            values = _tokens(line[len("rename from ") :], "rename-from")
            if len(values) != 1:
                raise InputError("Git diff rename-from path is ambiguous.")
            rename_from = _safe_path(values[0], prefix=None)
        elif line.startswith("rename to "):
            values = _tokens(line[len("rename to ") :], "rename-to")
            if len(values) != 1:
                raise InputError("Git diff rename-to path is ambiguous.")
            rename_to = _safe_path(values[0], prefix=None)
        elif line.startswith("Binary files ") or line == "GIT binary patch":
            binary = True
        elif line.startswith(
            (
                "index ",
                "new file mode ",
                "deleted file mode ",
                "old mode ",
                "new mode ",
                "similarity index ",
                "dissimilarity index ",
            )
        ):
            pass
        elif line:
            body_before_hunks.append(line)
            unknown_metadata = True

    hunk_count = _validate_hunks(lines[first_hunk:]) if first_hunk < len(lines) else 0
    if (old_file_header_seen or new_file_header_seen) and not (
        old_file_header_seen and new_file_header_seen and hunk_count
    ):
        raise InputError("Git diff text file headers are incomplete or missing a hunk.")
    if hunk_count and (old_path not in {None, old_header} or new_path not in {None, new_header}):
        raise InputError("Git diff file headers do not match the diff --git paths.")
    if (rename_from is None) != (rename_to is None):
        raise InputError("Git diff rename metadata is incomplete.")
    if rename_from is not None and (rename_from != old_header or rename_to != new_header):
        raise InputError("Git diff rename metadata does not match its header paths.")

    if binary:
        status = "binary"
    elif rename_from is not None:
        status = "renamed"
    elif old_path is None:
        status = "added"
    elif new_path is None:
        status = "deleted"
    else:
        status = "modified"
    effective_path = new_header if status != "deleted" else old_header
    prior_path = old_header if status == "renamed" else None
    if not binary and not hunk_count and rename_from is None and not metadata:
        raise InputError("Git diff section has no bounded change metadata or hunks.")
    return DiffChange(
        path=effective_path,
        old_path=prior_path,
        status=status,
        category=_category(effective_path),
        content_fingerprint=_fingerprint("git-diff-section-v1", lines),
        unknown_metadata=unknown_metadata or bool(body_before_hunks),
    )


def parse_unified_diff(raw: bytes) -> list[DiffChange]:
    if not raw:
        raise InputError("Git diff input is empty.")
    if len(raw) > MAX_DIFF_BYTES:
        raise InputError("Git diff exceeds the total byte limit.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError("Git diff must be valid UTF-8 text.") from exc
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized or "\x00" in normalized:
        raise InputError("Git diff contains an unsupported control character.")
    lines = normalized.splitlines()
    if len(lines) > MAX_DIFF_LINES:
        raise InputError("Git diff exceeds the line-count limit.")
    if any(len(line.encode("utf-8")) > MAX_DIFF_LINE_BYTES for line in lines):
        raise InputError("Git diff contains an oversized line.")
    starts = [index for index, line in enumerate(lines) if line.startswith("diff --git ")]
    if not starts or starts[0] != 0:
        raise InputError("Git diff must begin with a diff --git file header.")
    if len(starts) > MAX_DIFF_FILES:
        raise InputError("Git diff exceeds the changed-file limit.")
    changes = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        changes.append(_parse_section(lines[start:end]))
    return changes


def _gate_reason(rule: str, effect: str, message: str) -> dict[str, str]:
    return {
        "rule": rule,
        "effect": effect,
        "matched": "redacted:git-diff-fingerprint",
        "message": message,
    }


def git_check_document(
    changes: list[DiffChange],
    *,
    manifest_evidence: list[dict[str, Any]] | None,
    policy_evidence: dict[str, Any] | None,
    fail_on: str,
) -> dict[str, Any]:
    if fail_on not in {"warn", "deny", "never"}:
        raise InputError("Git gate fail_on must be warn, deny, or never.")
    manifest_evidence = manifest_evidence or []
    mcp_changes = [change for change in changes if change.category == "mcp-config"]
    current_mcp = [change for change in mcp_changes if change.status != "deleted"]
    policy_changes = [change for change in changes if change.category == "policy"]
    if manifest_evidence and not current_mcp:
        raise InputError("Manifest evidence was supplied without a current MCP config change.")
    if policy_evidence is not None and not policy_changes:
        raise InputError("Policy evidence was supplied without a policy change.")

    def valid_manifest_report(report: dict[str, Any]) -> bool:
        try:
            validate_report(report)
            receipt = report.get("receipt")
            if not isinstance(receipt, dict):
                return False
            validate_receipt(receipt)
        except (InputError, ValueError):
            return False
        return report.get("kind") == "manifest_scan" and report.get("decision") == "allow"

    manifest_names = sorted(
        PurePosixPath(str(report.get("source", "")).replace("\\", "/")).name.casefold()
        for report in manifest_evidence
    )
    changed_manifest_names = sorted(
        PurePosixPath(change.path).name.casefold() for change in current_mcp
    )
    manifest_evidence_valid = (
        len(manifest_evidence) == len(current_mcp)
        and manifest_names == changed_manifest_names
        and all(valid_manifest_report(report) for report in manifest_evidence)
    )
    policy_report_valid = False
    if isinstance(policy_evidence, dict):
        try:
            validate_report(policy_evidence)
        except ValueError:
            pass
        else:
            policy_report_valid = policy_evidence.get("kind") == "policy_diff"
    policy_evidence_valid = (
        len(policy_changes) == 1
        and policy_report_valid
        and policy_evidence.get("policies", {}).get("after", {}).get("label")
        == PurePosixPath(policy_changes[0].path).name
        and isinstance(policy_evidence.get("gate"), dict)
        and policy_evidence["gate"].get("failed") is False
        and isinstance(policy_evidence.get("comparison_fingerprint"), str)
        and _HASH.fullmatch(policy_evidence["comparison_fingerprint"])
    )

    rows: list[dict[str, Any]] = []
    for change in changes:
        reasons: list[dict[str, str]] = []

        if change.status == "binary":
            reasons.append(
                _gate_reason(
                    "git-diff.binary", "deny", "Binary diff content cannot be policy-reviewed."
                )
            )
        if change.status == "renamed":
            reasons.append(
                _gate_reason("git-diff.rename", "warn", "A renamed path requires explicit review.")
            )
        if change.unknown_metadata:
            reasons.append(
                _gate_reason(
                    "git-diff.unknown-metadata", "warn", "Diff metadata needs explicit review."
                )
            )
        if change.category == "mcp-config":
            if change.status == "deleted":
                reasons.append(
                    _gate_reason(
                        "git-check.mcp-config-deleted", "warn", "An MCP config was deleted."
                    )
                )
            elif not manifest_evidence_valid:
                reasons.append(
                    _gate_reason(
                        "git-check.manifest-evidence-required",
                        "deny",
                        "Every current MCP config change needs one explicit clean manifest scan.",
                    )
                )
        elif change.category == "policy":
            if not policy_evidence_valid:
                reasons.append(
                    _gate_reason(
                        "git-check.policy-evidence-required",
                        "deny",
                        "One policy change needs an explicit passing before/after simulation.",
                    )
                )
        elif change.category == "fixture":
            reasons.append(
                _gate_reason(
                    "git-check.fixture-changed", "warn", "A synthetic policy fixture changed."
                )
            )
        decision = (
            "deny"
            if any(reason["effect"] == "deny" for reason in reasons)
            else ("warn" if reasons else "allow")
        )
        rows.append(
            {
                "subject": change.path,
                "decision": decision,
                "risk_level": risk_for(decision),
                "reasons": reasons,
            }
        )
    decision = max((row["decision"] for row in rows), key=DECISION_RANK.get)
    threshold = {"warn": 1, "deny": 2, "never": 3}[fail_on]
    gate_failed = DECISION_RANK[decision] >= threshold
    manifest_summaries = []
    for report in manifest_evidence:
        fingerprint = report.get("receipt", {}).get("receipt_fingerprint")
        manifest_summaries.append(
            {
                "decision": report.get("decision")
                if report.get("decision") in DECISION_RANK
                else "invalid",
                "receipt_fingerprint": (
                    fingerprint
                    if isinstance(fingerprint, str) and _HASH.fullmatch(fingerprint)
                    else None
                ),
            }
        )
    policy_gate = policy_evidence.get("gate", {}) if isinstance(policy_evidence, dict) else {}
    policy_comparison = (
        policy_evidence.get("comparison_fingerprint") if isinstance(policy_evidence, dict) else None
    )
    evidence = {
        "manifest_scans": manifest_summaries,
        "policy_diff": (
            {
                "gate_failed": policy_gate.get("failed"),
                "comparison_fingerprint": (
                    policy_comparison
                    if isinstance(policy_comparison, str) and _HASH.fullmatch(policy_comparison)
                    else None
                ),
            }
            if isinstance(policy_evidence, dict)
            else None
        ),
    }
    return {
        "schema_version": 1,
        "kind": "git_diff_gate",
        "source": "provided-unified.diff",
        "decision": decision,
        "risk_level": risk_for(decision),
        "summary": {
            "files": len(changes),
            "mcp_configs": len(mcp_changes),
            "current_mcp_configs": len(current_mcp),
            "policies": len(policy_changes),
            "fixtures": sum(change.category == "fixture" for change in changes),
            "binary": sum(change.status == "binary" for change in changes),
        },
        "changes": [change.to_dict() for change in changes],
        "evidence": evidence,
        "gate": {"fail_on": fail_on, "failed": gate_failed},
        "diff_fingerprint": _fingerprint(
            "git-diff-gate-v1", [change.content_fingerprint for change in changes]
        ),
        "results": rows,
    }


def git_integration_snippet(kind: str) -> str:
    if kind == "pre-commit":
        return (
            "# Review before manually merging into .pre-commit-config.yaml.\n"
            "# This user-installed hook invokes Git; PolicyLatch itself never invokes Git.\n"
            "repos:\n"
            "  - repo: local\n"
            "    hooks:\n"
            "      - id: policylatch-git-gate\n"
            "        name: PolicyLatch supplied-diff gate\n"
            "        language: system\n"
            "        pass_filenames: false\n"
            "        entry: bash -c 'git diff --cached --no-ext-diff --binary | "
            "policylatch git-check --diff - --fail-on warn'\n"
        )
    if kind == "github-actions":
        return (
            "# Review and replace evidence placeholders before committing this step.\n"
            "- name: Build bounded diff input\n"
            "  shell: bash\n"
            "  run: git diff --no-ext-diff --binary "
            '"${{ github.event.pull_request.base.sha }}" "${{ github.sha }}" '
            "> policylatch.diff\n"
            "- name: PolicyLatch supplied-diff gate\n"
            "  shell: bash\n"
            "  run: policylatch git-check --diff policylatch.diff --fail-on warn\n"
        )
    raise InputError("Git integration snippet kind must be pre-commit or github-actions.")
