from __future__ import annotations

import hashlib
import json
import queue
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from .approval import TerminalApprovalProvider, build_approval_request
from .gateway import MAX_GATEWAY_REQUEST_BYTES, evaluate_mcp_request
from .receipts import canonical_json, canonical_policy_hash
from .validation import InputError

MAX_UPSTREAM_ARGV = 32
MAX_UPSTREAM_ARG_CHARS = 4096
MAX_SERVER_ID_CHARS = 128
MAX_SESSION_MESSAGES = 10_000
MAX_UPSTREAM_NOTIFICATIONS = 64
MAX_STDERR_BYTES = 64 * 1024
MCP_PROTOCOL_VERSION = "2025-11-25"
CONTROL_METHODS = frozenset({"initialize", "notifications/initialized", "ping", "tools/list"})


class RuntimeGatewayError(InputError):
    """Raised when the stdio forwarding boundary cannot continue safely."""


@dataclass(frozen=True)
class UpstreamConfig:
    server_id: str
    argv: tuple[str, ...]
    cwd: str | None


def parse_upstream_config(data: dict[str, Any], source: str | Path) -> UpstreamConfig:
    if set(data) != {"schema_version", "server_id", "argv", "cwd"}:
        raise RuntimeGatewayError("Upstream config fields do not match schema version 1.")
    if data.get("schema_version") != 1:
        raise RuntimeGatewayError("Only upstream config schema version 1 is supported.")
    server_id = data.get("server_id")
    if (
        not isinstance(server_id, str)
        or not server_id.strip()
        or len(server_id) > MAX_SERVER_ID_CHARS
    ):
        raise RuntimeGatewayError(
            f"Upstream config server_id must be 1-{MAX_SERVER_ID_CHARS} characters."
        )
    argv = data.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > MAX_UPSTREAM_ARGV
        or not all(
            isinstance(item, str)
            and item
            and "\x00" not in item
            and len(item) <= MAX_UPSTREAM_ARG_CHARS
            for item in argv
        )
    ):
        raise RuntimeGatewayError(
            f"Upstream config argv must contain 1-{MAX_UPSTREAM_ARGV} bounded strings."
        )
    cwd_value = data.get("cwd")
    cwd: str | None
    if cwd_value is None:
        cwd = None
    elif not isinstance(cwd_value, str) or not cwd_value.strip() or "\x00" in cwd_value:
        raise RuntimeGatewayError("Upstream config cwd must be null or a non-empty path.")
    else:
        config_dir = Path(source).resolve().parent
        candidate = Path(cwd_value)
        cwd_path = candidate if candidate.is_absolute() else config_dir / candidate
        try:
            resolved = cwd_path.resolve(strict=True)
        except OSError as exc:
            raise RuntimeGatewayError("Upstream config cwd does not exist.") from exc
        if not resolved.is_dir():
            raise RuntimeGatewayError("Upstream config cwd must resolve to a directory.")
        cwd = str(resolved)
    return UpstreamConfig(server_id=server_id.strip(), argv=tuple(argv), cwd=cwd)


def upstream_identity(config: UpstreamConfig) -> str:
    projection = {
        "contract": "stdio-upstream-v1",
        "server_id": config.server_id,
        "argv": list(config.argv),
        "cwd": config.cwd,
    }
    digest = hashlib.sha256(canonical_json(projection).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class _LineReader:
    def __init__(self, stream: BinaryIO, *, max_bytes: int):
        self._stream = stream
        self._max_bytes = max_bytes
        self._queue: queue.Queue[bytes | BaseException] = queue.Queue(
            maxsize=MAX_UPSTREAM_NOTIFICATIONS
        )
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self) -> None:
        while True:
            try:
                raw = self._stream.readline(self._max_bytes + 1)
            except BaseException as exc:  # pragma: no cover - defensive stream boundary
                self._queue.put(exc)
                return
            self._queue.put(raw)
            if not raw:
                return

    def next(self, timeout_seconds: float) -> bytes:
        try:
            value = self._queue.get(timeout=timeout_seconds)
        except queue.Empty as exc:
            raise RuntimeGatewayError("Upstream response timed out.") from exc
        if isinstance(value, BaseException):
            raise RuntimeGatewayError("Could not read upstream stdout.") from value
        if len(value) > self._max_bytes:
            raise RuntimeGatewayError("Upstream response exceeds the message byte limit.")
        if value and not value.endswith(b"\n"):
            raise RuntimeGatewayError("Upstream response is not newline-delimited.")
        return value


class _StderrDrainer:
    def __init__(self, stream: BinaryIO):
        self.bytes_seen = 0
        self.truncated = False
        self._stream = stream
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        while True:
            chunk = self._stream.read(4096)
            if not chunk:
                return
            self.bytes_seen += len(chunk)
            if self.bytes_seen > MAX_STDERR_BYTES:
                self.truncated = True


def _parse_json_line(raw: bytes, label: str) -> dict[str, Any]:
    if len(raw) > MAX_GATEWAY_REQUEST_BYTES:
        raise RuntimeGatewayError(f"{label} exceeds the message byte limit.")
    if not raw.endswith(b"\n"):
        raise RuntimeGatewayError(f"{label} is not newline-delimited.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RuntimeGatewayError(f"{label} is not a valid bounded UTF-8 JSON object.") from exc
    if not isinstance(data, dict):
        raise RuntimeGatewayError(f"{label} must be a JSON object.")
    return data


def _request_id(message: dict[str, Any]) -> str | int | None:
    value = message.get("id")
    if isinstance(value, bool) or (value is not None and not isinstance(value, (str, int))):
        raise RuntimeGatewayError("JSON-RPC request id must be a string, integer, or null.")
    return value


def _validate_control_message(message: dict[str, Any], state: str) -> tuple[str, bool]:
    if message.get("jsonrpc") != "2.0":
        raise RuntimeGatewayError("Runtime messages must use JSON-RPC 2.0.")
    method = message.get("method")
    if method not in CONTROL_METHODS:
        raise RuntimeGatewayError("Runtime gateway received an unsupported MCP method.")
    params = message.get("params", {})
    if not isinstance(params, dict):
        raise RuntimeGatewayError("Runtime control params must be an object when provided.")
    notification = "id" not in message
    if method == "initialize" and (state != "new" or notification):
        raise RuntimeGatewayError("MCP initialize must be one request at session start.")
    if method == "initialize" and params.get("protocolVersion") != MCP_PROTOCOL_VERSION:
        raise RuntimeGatewayError(
            f"Runtime gateway requires MCP protocol revision {MCP_PROTOCOL_VERSION}."
        )
    if method == "initialize" and not isinstance(params.get("capabilities"), dict):
        raise RuntimeGatewayError("MCP initialize capabilities must be an object.")
    if method == "initialize" and not isinstance(params.get("clientInfo"), dict):
        raise RuntimeGatewayError("MCP initialize clientInfo must be an object.")
    if method == "notifications/initialized" and (state != "initialized" or not notification):
        raise RuntimeGatewayError("MCP initialized notification is out of sequence.")
    if method in {"tools/list"} and state != "ready":
        raise RuntimeGatewayError("MCP tools/list requires an initialized session.")
    return method, notification


def _write_bytes_bounded(
    stream: BinaryIO,
    payload: bytes,
    *,
    timeout_seconds: float,
    label: str,
) -> None:
    finished = threading.Event()
    errors: list[BaseException] = []

    def write_all() -> None:
        try:
            view = memoryview(payload)
            while view:
                written = stream.write(view)
                if not isinstance(written, int) or written <= 0:
                    raise OSError(f"{label} stopped accepting bytes.")
                view = view[written:]
            stream.flush()
        except BaseException as exc:  # pragma: no cover - defensive stream boundary
            errors.append(exc)
        finally:
            finished.set()

    threading.Thread(target=write_all, daemon=True).start()
    if not finished.wait(timeout_seconds):
        raise RuntimeGatewayError(f"{label} write timed out.")
    if errors:
        raise RuntimeGatewayError(f"Could not write {label.lower()}.") from errors[0]


def _write_message(
    stream: BinaryIO,
    message: dict[str, Any],
    *,
    timeout_seconds: float,
) -> None:
    encoded = (canonical_json(message) + "\n").encode("utf-8")
    if len(encoded) > MAX_GATEWAY_REQUEST_BYTES:
        raise RuntimeGatewayError("Gateway output exceeds the message byte limit.")
    _write_bytes_bounded(
        stream,
        encoded,
        timeout_seconds=timeout_seconds,
        label="Client output",
    )


def _local_error(
    request_id: str | int | None,
    *,
    code: int,
    message: str,
    decision: str = "deny",
    rules: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
            "data": {
                "decision": decision,
                "forwarded": False,
                "rules": sorted(set(rules or [])),
            },
        },
    }


def _read_correlated_response(
    reader: _LineReader,
    client_output: BinaryIO,
    request_id: str | int | None,
    timeout_seconds: float,
) -> dict[str, Any]:
    for _ in range(MAX_UPSTREAM_NOTIFICATIONS + 1):
        raw = reader.next(timeout_seconds)
        if not raw:
            raise RuntimeGatewayError("Upstream closed stdout before responding.")
        response = _parse_json_line(raw, "Upstream response")
        if response.get("jsonrpc") != "2.0":
            raise RuntimeGatewayError("Upstream response must use JSON-RPC 2.0.")
        if "method" in response and "id" not in response:
            _write_message(client_output, response, timeout_seconds=timeout_seconds)
            continue
        if response.get("id") != request_id:
            raise RuntimeGatewayError("Upstream response id does not match the request.")
        if ("result" in response) == ("error" in response):
            raise RuntimeGatewayError("Upstream response must contain exactly one result or error.")
        return response
    raise RuntimeGatewayError("Upstream emitted too many notifications before its response.")


def _validate_initialize_response(response: dict[str, Any]) -> None:
    result = response.get("result")
    if not isinstance(result, dict) or result.get("protocolVersion") != MCP_PROTOCOL_VERSION:
        raise RuntimeGatewayError(
            f"Upstream did not negotiate MCP protocol revision {MCP_PROTOCOL_VERSION}."
        )
    if not isinstance(result.get("capabilities"), dict):
        raise RuntimeGatewayError("Upstream initialize capabilities must be an object.")


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.stdin is not None:
        with suppress(OSError):
            process.stdin.close()
    if process.poll() is None:
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            with suppress(OSError):
                stream.close()


def run_stdio_gateway(
    client_input: BinaryIO,
    client_output: BinaryIO,
    policy: dict[str, Any],
    config: UpstreamConfig,
    *,
    timeout_seconds: float,
    enabled: bool,
    approval_provider: TerminalApprovalProvider | None = None,
) -> dict[str, Any]:
    if not enabled:
        raise RuntimeGatewayError("Runtime forwarding requires enabled=True.")
    if not 0.05 <= timeout_seconds <= 300:
        raise RuntimeGatewayError("Runtime timeout must be between 0.05 and 300 seconds.")
    try:
        process = subprocess.Popen(
            list(config.argv),
            cwd=config.cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            bufsize=0,
        )
    except OSError as exc:
        raise RuntimeGatewayError("Could not start the explicit upstream argv.") from exc
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _stop_process(process)
        raise RuntimeGatewayError("Upstream stdio pipes are unavailable.")

    reader = _LineReader(process.stdout, max_bytes=MAX_GATEWAY_REQUEST_BYTES)
    stderr = _StderrDrainer(process.stderr)
    state = "new"
    seen_ids: set[str | int] = set()
    summary = {
        "schema_version": 1,
        "kind": "stdio_gateway_session",
        "upstream_fingerprint": upstream_identity(config),
        "policy_hash": canonical_policy_hash(policy),
        "forwarded": 0,
        "blocked": 0,
        "approved": 0,
        "grant_reuses": 0,
        "control_messages": 0,
        "protocol_errors": 0,
        "stderr_truncated": False,
        "child_cleaned_up": False,
    }
    try:
        for _ in range(MAX_SESSION_MESSAGES):
            raw = client_input.readline(MAX_GATEWAY_REQUEST_BYTES + 1)
            if not raw:
                break
            request_id: str | int | None = None
            try:
                message = _parse_json_line(raw, "Client request")
                request_id = _request_id(message)
                if request_id is not None:
                    if request_id in seen_ids:
                        raise RuntimeGatewayError(
                            "Runtime request id was already used in this session."
                        )
                    seen_ids.add(request_id)
                method = message.get("method")
                if method == "tools/call":
                    if "id" not in message:
                        raise RuntimeGatewayError(
                            "MCP tools/call notifications are not supported by this gateway."
                        )
                    if state != "ready":
                        raise RuntimeGatewayError(
                            "MCP tools/call requires a completed initialize lifecycle."
                        )
                    result = evaluate_mcp_request(message, policy)
                    approved = False
                    if result.evaluation.decision == "warn" and approval_provider is not None:
                        try:
                            approval = build_approval_request(
                                message,
                                result,
                                upstream_fingerprint=summary["upstream_fingerprint"],
                                policy_hash=summary["policy_hash"],
                                timeout_seconds=approval_provider.timeout_seconds,
                            )
                        except InputError as exc:
                            if any(
                                reason.rule == "gateway.tasks.unsupported"
                                for reason in result.evaluation.reasons
                            ):
                                approval = None
                            else:
                                raise RuntimeGatewayError(
                                    "Approval request could not be safely data-minimized."
                                ) from exc
                        if approval is None:
                            outcome = None
                        else:
                            outcome = approval_provider.authorize(approval)
                        approved = outcome.approved if outcome is not None else False
                        if approved and outcome is not None:
                            summary["approved"] += 1
                            if outcome.source == "session-grant":
                                summary["grant_reuses"] += 1
                    if result.evaluation.decision != "allow" and not approved:
                        summary["blocked"] += 1
                        _write_message(
                            client_output,
                            _local_error(
                                request_id,
                                code=-32041,
                                message="PolicyLatch did not allow this MCP tool call.",
                                decision=result.evaluation.decision,
                                rules=[reason.rule for reason in result.evaluation.reasons],
                            ),
                            timeout_seconds=timeout_seconds,
                        )
                        continue
                    notification = False
                else:
                    method, notification = _validate_control_message(message, state)
                    summary["control_messages"] += 1

                _write_bytes_bounded(
                    process.stdin,
                    raw,
                    timeout_seconds=timeout_seconds,
                    label="Upstream stdin",
                )
                summary["forwarded"] += 1
                if notification:
                    if method == "notifications/initialized":
                        state = "ready"
                    continue
                response = _read_correlated_response(
                    reader, client_output, request_id, timeout_seconds
                )
                if method == "initialize":
                    _validate_initialize_response(response)
                _write_message(client_output, response, timeout_seconds=timeout_seconds)
                if method == "initialize":
                    state = "initialized"
            except RuntimeGatewayError as exc:
                summary["protocol_errors"] += 1
                with suppress(RuntimeGatewayError):
                    _write_message(
                        client_output,
                        _local_error(request_id, code=-32042, message=str(exc)),
                        timeout_seconds=timeout_seconds,
                    )
                break
        else:
            raise RuntimeGatewayError("Runtime session exceeds the message-count limit.")
    finally:
        _stop_process(process)
        summary["stderr_truncated"] = stderr.truncated
        summary["child_cleaned_up"] = process.poll() is not None
    return summary
