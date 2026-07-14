from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from .gateway import GatewayResult
from .receipts import canonical_json
from .validation import InputError

MAX_APPROVAL_LINE_CHARS = 128
MAX_GRANT_TTL_SECONDS = 300
MAX_GRANT_USES = 20
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_NON_APPROVABLE_RULES = frozenset({"gateway.tasks.unsupported"})


def _fingerprint(label: str, value: Any) -> str:
    encoded = canonical_json({"contract": label, "value": value}).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True)
class ApprovalRequest:
    document: dict[str, Any]
    request_fingerprint: str
    scope_fingerprint: str
    grant_allowed: bool


@dataclass(frozen=True)
class ApprovalResponse:
    approved: bool
    grant_ttl_seconds: int
    grant_max_uses: int


@dataclass(frozen=True)
class ApprovalOutcome:
    approved: bool
    source: str


def build_approval_request(
    request: dict[str, Any],
    result: GatewayResult,
    *,
    upstream_fingerprint: str,
    policy_hash: str,
    timeout_seconds: float,
) -> ApprovalRequest:
    if result.evaluation.decision != "warn":
        raise InputError("Approval requests are valid only for warn decisions.")
    if any(reason.rule in _NON_APPROVABLE_RULES for reason in result.evaluation.reasons):
        raise InputError("This warning category is not eligible for approval.")
    if not 0.05 <= timeout_seconds <= 300:
        raise InputError("Approval request timeout is outside the bounded contract.")
    if not _HASH.fullmatch(upstream_fingerprint) or not _HASH.fullmatch(policy_hash):
        raise InputError("Approval request provenance fingerprints are invalid.")
    params = request.get("params")
    semantic_request = {
        "method": "tools/call",
        "params": params if isinstance(params, dict) else {},
    }
    semantic_fingerprint = _fingerprint("approval-semantic-request-v1", semantic_request)
    scope = {
        "upstream_fingerprint": upstream_fingerprint,
        "policy_hash": policy_hash,
        "tool_fingerprint": _fingerprint("approval-tool-v1", result.call.name),
        "capabilities": sorted(set(result.capabilities)),
        "target_class": "+".join(sorted(set(result.capabilities))),
        "semantic_request_fingerprint": semantic_fingerprint,
    }
    scope_fingerprint = _fingerprint("approval-scope-v1", scope)
    core = {
        "schema_version": 1,
        "kind": "approval_request",
        "decision": "warn",
        "scope": {**scope, "scope_fingerprint": scope_fingerprint},
        "rules": sorted({reason.rule for reason in result.evaluation.reasons}),
        "timeout_seconds": timeout_seconds,
        "grant_allowed": True,
    }
    request_fingerprint = _fingerprint("approval-request-v1", core)
    return ApprovalRequest(
        document={**core, "request_fingerprint": request_fingerprint},
        request_fingerprint=request_fingerprint,
        scope_fingerprint=scope_fingerprint,
        grant_allowed=True,
    )


def build_result_approval_request(
    request: dict[str, Any],
    scan_report: dict[str, Any],
    *,
    upstream_fingerprint: str,
    policy_hash: str,
    timeout_seconds: float,
) -> ApprovalRequest:
    if scan_report.get("postflight_outcome") not in {"review", "block-next-step"}:
        raise InputError("Result approval requires a review or block-next-step outcome.")
    if not 0.05 <= timeout_seconds <= 300:
        raise InputError("Approval request timeout is outside the bounded contract.")
    if not _HASH.fullmatch(upstream_fingerprint) or not _HASH.fullmatch(policy_hash):
        raise InputError("Approval request provenance fingerprints are invalid.")
    correlation = scan_report.get("correlation")
    receipt = scan_report.get("receipt")
    if not isinstance(correlation, dict) or not isinstance(receipt, dict):
        raise InputError("Result approval correlation is unavailable.")
    result_fingerprint = correlation.get("result_fingerprint")
    tool_fingerprint = correlation.get("tool_fingerprint")
    receipt_fingerprint = receipt.get("receipt_fingerprint")
    if not all(
        isinstance(value, str) and _HASH.fullmatch(value)
        for value in (result_fingerprint, tool_fingerprint, receipt_fingerprint)
    ):
        raise InputError("Result approval fingerprints are invalid.")
    params = request.get("params")
    semantic_request_fingerprint = _fingerprint(
        "approval-semantic-request-v1",
        {"method": "tools/call", "params": params if isinstance(params, dict) else {}},
    )
    scope = {
        "upstream_fingerprint": upstream_fingerprint,
        "policy_hash": policy_hash,
        "tool_fingerprint": tool_fingerprint,
        "capabilities": ["tool-result"],
        "target_class": "tool-result",
        "semantic_request_fingerprint": semantic_request_fingerprint,
        "result_fingerprint": result_fingerprint,
        "result_receipt_fingerprint": receipt_fingerprint,
    }
    scope_fingerprint = _fingerprint("result-approval-scope-v1", scope)
    grant_allowed = scan_report["postflight_outcome"] == "review"
    core = {
        "schema_version": 1,
        "kind": "approval_request",
        "decision": scan_report.get("decision"),
        "scope": {**scope, "scope_fingerprint": scope_fingerprint},
        "rules": sorted(
            {
                reason["rule"]
                for reason in scan_report.get("reasons", [])
                if isinstance(reason, dict) and isinstance(reason.get("rule"), str)
            }
        ),
        "timeout_seconds": timeout_seconds,
        "grant_allowed": grant_allowed,
    }
    request_fingerprint = _fingerprint("result-approval-request-v1", core)
    return ApprovalRequest(
        document={**core, "request_fingerprint": request_fingerprint},
        request_fingerprint=request_fingerprint,
        scope_fingerprint=scope_fingerprint,
        grant_allowed=grant_allowed,
    )


def parse_approval_response(
    data: dict[str, Any], *, expected_request_fingerprint: str
) -> ApprovalResponse:
    if set(data) != {
        "schema_version",
        "kind",
        "request_fingerprint",
        "decision",
        "grant",
    }:
        raise InputError("Approval response fields do not match schema version 1.")
    if data.get("schema_version") != 1 or data.get("kind") != "approval_response":
        raise InputError("Approval response contract is invalid.")
    if data.get("request_fingerprint") != expected_request_fingerprint:
        raise InputError("Approval response does not match the pending request fingerprint.")
    if not _HASH.fullmatch(expected_request_fingerprint):
        raise InputError("Approval response request fingerprint is invalid.")
    decision = data.get("decision")
    if decision not in {"approve", "deny"}:
        raise InputError("Approval response decision must be approve or deny.")
    grant = data.get("grant")
    if grant is None:
        ttl_seconds = 0
        max_uses = 0
    elif (
        not isinstance(grant, dict)
        or set(grant) != {"ttl_seconds", "max_uses"}
        or isinstance(grant.get("ttl_seconds"), bool)
        or isinstance(grant.get("max_uses"), bool)
        or not isinstance(grant.get("ttl_seconds"), int)
        or not isinstance(grant.get("max_uses"), int)
        or not 1 <= grant["ttl_seconds"] <= MAX_GRANT_TTL_SECONDS
        or not 1 <= grant["max_uses"] <= MAX_GRANT_USES
    ):
        raise InputError("Approval grant TTL or use count is outside the bounded contract.")
    else:
        ttl_seconds = grant["ttl_seconds"]
        max_uses = grant["max_uses"]
    if decision == "deny" and grant is not None:
        raise InputError("A denied approval response cannot create a grant.")
    return ApprovalResponse(
        approved=decision == "approve",
        grant_ttl_seconds=ttl_seconds,
        grant_max_uses=max_uses,
    )


@dataclass
class _Grant:
    expires_at: float
    remaining_uses: int


class SessionGrantStore:
    def __init__(self) -> None:
        self._grants: dict[str, _Grant] = {}

    def consume(self, scope_fingerprint: str, *, now: float) -> bool:
        grant = self._grants.get(scope_fingerprint)
        if grant is None:
            return False
        if now >= grant.expires_at or grant.remaining_uses <= 0:
            self._grants.pop(scope_fingerprint, None)
            return False
        grant.remaining_uses -= 1
        if grant.remaining_uses == 0:
            self._grants.pop(scope_fingerprint, None)
        return True

    def add(
        self,
        scope_fingerprint: str,
        *,
        now: float,
        ttl_seconds: int,
        max_uses: int,
    ) -> None:
        self._grants[scope_fingerprint] = _Grant(
            expires_at=now + ttl_seconds,
            remaining_uses=max_uses,
        )


class TerminalApprovalProvider:
    def __init__(
        self,
        input_stream: TextIO | None,
        output_stream: TextIO,
        *,
        timeout_seconds: float,
        clock=time.monotonic,
    ) -> None:
        if not 0.05 <= timeout_seconds <= 300:
            raise InputError("Approval timeout must be between 0.05 and 300 seconds.")
        self._input = input_stream
        self._output = output_stream
        self._timeout_seconds = timeout_seconds
        self._clock = clock
        self._closed = input_stream is None
        self._owns_input = False
        self._grants = SessionGrantStore()

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    @classmethod
    def from_console(cls, output_stream: TextIO, *, timeout_seconds: float):
        console_path = Path("CONIN$") if os.name == "nt" else Path("/dev/tty")
        try:
            input_stream = console_path.open("r", encoding="utf-8")
        except OSError:
            input_stream = None
        provider = cls(input_stream, output_stream, timeout_seconds=timeout_seconds)
        provider._owns_input = input_stream is not None
        return provider

    def close(self) -> None:
        if self._owns_input and self._input is not None:
            with suppress(OSError):
                self._input.close()
        self._closed = True

    def authorize(self, approval: ApprovalRequest) -> ApprovalOutcome:
        now = self._clock()
        if self._grants.consume(approval.scope_fingerprint, now=now):
            return ApprovalOutcome(True, "session-grant")
        if self._closed or self._input is None:
            return ApprovalOutcome(False, "closed-input")
        self._output.write(canonical_json(approval.document) + "\n")
        self._output.write("PolicyLatch approval [approve | deny | grant <ttl-seconds> <uses>]: ")
        self._output.flush()
        line = self._readline_with_timeout()
        if line is None:
            self._closed = True
            return ApprovalOutcome(False, "timeout-or-closed")
        response = self._response_from_line(line, approval.request_fingerprint)
        try:
            parsed = parse_approval_response(
                response,
                expected_request_fingerprint=approval.request_fingerprint,
            )
        except InputError:
            return ApprovalOutcome(False, "invalid-response")
        if parsed.approved and parsed.grant_max_uses:
            if not approval.grant_allowed:
                return ApprovalOutcome(False, "grant-not-allowed")
            self._grants.add(
                approval.scope_fingerprint,
                now=self._clock(),
                ttl_seconds=parsed.grant_ttl_seconds,
                max_uses=parsed.grant_max_uses,
            )
        return ApprovalOutcome(parsed.approved, "explicit-approval" if parsed.approved else "deny")

    def _readline_with_timeout(self) -> str | None:
        finished = threading.Event()
        result: list[str] = []

        def read() -> None:
            try:
                value = self._input.readline(MAX_APPROVAL_LINE_CHARS + 1) if self._input else ""
                result.append(value)
            except BaseException:  # pragma: no cover - defensive console boundary
                result.append("")
            finally:
                finished.set()

        threading.Thread(target=read, daemon=True).start()
        if not finished.wait(self._timeout_seconds) or not result or not result[0]:
            return None
        if len(result[0]) > MAX_APPROVAL_LINE_CHARS:
            return ""
        return result[0].strip().casefold()

    @staticmethod
    def _response_from_line(line: str, request_fingerprint: str) -> dict[str, Any]:
        parts = line.split()
        decision = "deny"
        grant = None
        if parts == ["approve"]:
            decision = "approve"
        elif len(parts) == 3 and parts[0] == "grant":
            try:
                ttl_seconds = int(parts[1])
                max_uses = int(parts[2])
            except ValueError:
                pass
            else:
                decision = "approve"
                grant = {"ttl_seconds": ttl_seconds, "max_uses": max_uses}
        return {
            "schema_version": 1,
            "kind": "approval_response",
            "request_fingerprint": request_fingerprint,
            "decision": decision,
            "grant": grant,
        }
