from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .adapters import (
    RUNTIMES,
    adapter_config_document,
    adapter_decision_document,
    config_target,
    hook_response,
    safe_policy_label,
    validate_adapter_config,
)
from .evaluator import evaluate_action
from .gateway import MAX_GATEWAY_REQUEST_BYTES, evaluate_mcp_request
from .gateway_trace import GatewayTraceError, gateway_trace_document, load_gateway_trace
from .html_report import html_report
from .models import aggregate
from .policy import PolicyError, load_policy, load_profile, policy_provenance
from .policy_draft import (
    policy_coverage_document,
    policy_draft_document,
    policy_draft_yaml,
)
from .policy_tooling import (
    lint_policy_document,
    load_policy_fixtures,
    policy_test_document,
)
from .profiles import profile_names
from .reports import json_report, markdown_report, validate_report
from .sarif_report import sarif_report
from .scanners import scan_manifest
from .schemas import SCHEMA_KINDS, export_schema
from .validation import InputError
from .windows_audit import parse_windows_audit_record, parse_windows_setting_action
from .windows_compare import compare_windows_snapshots
from .windows_history import append_audit_record, filter_audit_history, load_audit_history
from .windows_history_report import (
    history_document,
    history_html_report,
    history_json_report,
)
from .windows_providers import (
    WindowsProviderError,
    collect_windows_snapshot,
    parse_observed_windows_snapshot,
)
from .windows_registry import RegistryKeyPresenceProvider
from .windows_service import ServiceSummaryProvider
from .windows_settings import (
    FirewallProfileProvider,
    FirewallRulePresenceProvider,
    LongPathsPolicyProvider,
)

EXIT_CODES = {"allow": 0, "warn": 1, "deny": 2}
MAX_JSON_INPUT_BYTES = 8 * 1024 * 1024


def _read_json(path: str, *, max_bytes: int | None = None) -> dict[str, Any]:
    effective_max = MAX_JSON_INPUT_BYTES if max_bytes is None else max_bytes
    input_label = "stdin" if path == "-" else str(Path(path))
    if path == "-":
        raw = sys.stdin.buffer.read(effective_max + 1)
    else:
        try:
            with Path(path).open("rb") as handle:
                raw = handle.read(effective_max + 1)
        except OSError as exc:
            raise InputError(f"Could not read JSON input '{input_label}': {exc}") from exc
    if len(raw) > effective_max:
        raise InputError(f"JSON input '{input_label}' exceeds the {effective_max}-byte limit.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InputError(f"JSON input '{input_label}' must be valid UTF-8.") from exc
    except json.JSONDecodeError as exc:
        raise InputError(
            f"Invalid JSON in '{input_label}' at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except RecursionError as exc:
        raise InputError(f"JSON input '{input_label}' is nested too deeply.") from exc
    if not isinstance(data, dict):
        raise InputError("JSON input must be an object.")
    return data


def _write(content: str, output: str | None) -> None:
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        print(f"Wrote {output_path}", file=sys.stderr)
    else:
        print(content, end="")


def _write_new(content: str, output: str | None, *, force: bool) -> None:
    if output and Path(output).exists() and not force:
        raise InputError(f"Output '{output}' already exists; pass --force to replace it.")
    _write(content, output)


def _add_policy_selector(parser: argparse.ArgumentParser) -> None:
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--policy", help="Load an explicit local YAML policy file.")
    selector.add_argument(
        "--profile", choices=profile_names(), help="Use a built-in policy profile."
    )


def _selected_policy(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    if getattr(args, "profile", None):
        return load_profile(args.profile), f"profile:{args.profile}"
    return load_policy(args.policy), Path(args.policy).name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="policylatch",
        description="Local permission decisions for MCP tool calls and AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for command, input_flag, help_text in [
        ("check", "--action", "Evaluate an agent action JSON file."),
        ("scan", "--mcp-config", "Scan an MCP config or tool manifest JSON file."),
    ]:
        child = sub.add_parser(command, help=help_text)
        child.add_argument(input_flag, required=True)
        _add_policy_selector(child)
        child.add_argument(
            "--format", choices=["json", "markdown", "html", "sarif"], default="json"
        )
        child.add_argument("--output", help="Write the report to this path instead of stdout.")
    gateway = sub.add_parser(
        "gateway-check",
        help="Evaluate one MCP tools/call request in no-forward dry-run mode.",
    )
    gateway.add_argument("--request", required=True)
    _add_policy_selector(gateway)
    gateway.add_argument("--format", choices=["json", "markdown", "html", "sarif"], default="json")
    gateway.add_argument("--output", help="Write the report to this path instead of stdout.")
    replay = sub.add_parser(
        "gateway-replay",
        help="Evaluate a bounded synthetic MCP tools/call JSONL trace without forwarding.",
    )
    replay.add_argument("--input", required=True)
    _add_policy_selector(replay)
    replay.add_argument("--format", choices=["json", "markdown", "html", "sarif"], default="json")
    replay.add_argument("--output", help="Write the report to this path instead of stdout.")
    adapter_check = sub.add_parser(
        "adapter-check",
        help="Evaluate a saved Claude Code or Codex PreToolUse event without forwarding.",
    )
    adapter_check.add_argument("--runtime", choices=RUNTIMES, required=True)
    adapter_check.add_argument("--input", required=True)
    _add_policy_selector(adapter_check)
    adapter_check.add_argument(
        "--format", choices=["json", "markdown", "html", "sarif"], default="json"
    )
    adapter_check.add_argument("--output")
    adapter_hook = sub.add_parser(
        "adapter-hook",
        help="Read one PreToolUse event and emit the runtime-specific hook response.",
    )
    adapter_hook.add_argument("--runtime", choices=RUNTIMES, required=True)
    adapter_hook.add_argument("--input", default="-")
    _add_policy_selector(adapter_hook)
    adapter_hook.add_argument("--output")
    adapter_config = sub.add_parser(
        "adapter-config",
        help="Generate a review-first hook configuration snippet; no config is installed.",
    )
    adapter_config.add_argument("--runtime", choices=RUNTIMES, required=True)
    _add_policy_selector(adapter_config)
    adapter_config.add_argument("--platform", choices=["posix", "windows"])
    adapter_config.add_argument("--output")
    adapter_doctor = sub.add_parser(
        "adapter-doctor", help="Validate one saved PolicyLatch hook configuration snippet."
    )
    adapter_doctor.add_argument("--runtime", choices=RUNTIMES, required=True)
    adapter_doctor.add_argument("--config", required=True)
    adapter_doctor.add_argument("--output")
    policy_test = sub.add_parser(
        "policy-test", help="Run synthetic expected-decision fixtures against a policy."
    )
    policy_test.add_argument("--fixtures", required=True)
    _add_policy_selector(policy_test)
    policy_test.add_argument("--format", choices=["json", "sarif"], default="json")
    policy_test.add_argument("--output")
    policy_lint = sub.add_parser(
        "policy-lint", help="Report semantic policy findings without changing the policy."
    )
    _add_policy_selector(policy_lint)
    policy_lint.add_argument("--format", choices=["json", "sarif"], default="json")
    policy_lint.add_argument("--output")
    schema = sub.add_parser("schema", help="Export a versioned PolicyLatch JSON Schema.")
    schema.add_argument("--kind", choices=SCHEMA_KINDS, required=True)
    schema.add_argument("--output")
    policy_init = sub.add_parser(
        "policy-init", help="Generate a non-enforceable policy draft or check policy coverage."
    )
    policy_init.add_argument("--mcp-config", required=True)
    policy_init.add_argument("--check", action="store_true")
    selector = policy_init.add_mutually_exclusive_group()
    selector.add_argument("--policy")
    selector.add_argument("--profile", choices=profile_names())
    policy_init.add_argument("--format", choices=["json", "sarif"], default="json")
    policy_init.add_argument("--output")
    policy_init.add_argument("--force", action="store_true")
    report = sub.add_parser("report", help="Convert a saved JSON result into a report.")
    report.add_argument("--input", required=True)
    report.add_argument(
        "--format", choices=["json", "markdown", "html", "sarif"], default="markdown"
    )
    report.add_argument("--output", help="Write the report to this path instead of stdout.")
    doctor = sub.add_parser(
        "doctor",
        help="Validate and summarize a resolved local policy or built-in profile.",
    )
    _add_policy_selector(doctor)
    doctor.add_argument("--format", choices=["json", "markdown"], default="json")
    doctor.add_argument("--output")
    explain = sub.add_parser(
        "explain",
        help="Explain rule provenance in a saved PolicyLatch decision report.",
    )
    explain.add_argument("--input", required=True)
    explain.add_argument("--format", choices=["json", "markdown"], default="markdown")
    explain.add_argument("--output")
    audit_append = sub.add_parser(
        "audit-append", help="Append a validated Windows audit record to local JSONL history."
    )
    audit_append.add_argument("--input", required=True)
    audit_append.add_argument("--history", required=True)
    audit_append.add_argument("--enable-history", action="store_true")
    audit_report = sub.add_parser(
        "audit-report", help="Render filtered local Windows audit JSONL history."
    )
    audit_report.add_argument("--input", required=True)
    audit_report.add_argument("--format", choices=["json", "html"], default="html")
    audit_report.add_argument("--output")
    audit_report.add_argument("--category")
    audit_report.add_argument("--state", dest="verification_state")
    audit_report.add_argument("--from", dest="from_timestamp")
    audit_report.add_argument("--to", dest="to_timestamp")
    snapshot = sub.add_parser(
        "windows-snapshot",
        help="Explicitly collect one read-only, summary-only Windows snapshot.",
    )
    snapshot.add_argument(
        "--provider",
        required=True,
        choices=["registry-key", "service", "firewall", "firewall-rule", "long-paths"],
    )
    snapshot.add_argument("--target", required=True)
    snapshot.add_argument("--output")
    snapshot.add_argument("--enable-windows-audit", action="store_true")
    compare = sub.add_parser(
        "windows-compare",
        help="Compare two saved summary-only Windows snapshots.",
    )
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--proposed")
    compare.add_argument("--output")
    return parser


def _action_document(
    source: str,
    policy: dict[str, Any],
    policy_label: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    evaluation = evaluate_action(data, policy)
    return {
        "schema_version": 1,
        "kind": "action_evaluation",
        "source": source,
        "policy": policy_label,
        "policy_provenance": policy_provenance(policy),
        **evaluation.to_dict(),
    }


def _scan_document(
    source: str,
    policy: dict[str, Any],
    policy_label: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    evaluations = scan_manifest(data, policy)
    decision, risk_level = aggregate(evaluations)
    counts = {name: sum(item.decision == name for item in evaluations) for name in EXIT_CODES}
    return {
        "schema_version": 1,
        "kind": "manifest_scan",
        "source": source,
        "policy": policy_label,
        "policy_provenance": policy_provenance(policy),
        "decision": decision,
        "risk_level": risk_level,
        "summary": {"total": len(evaluations), **counts},
        "results": [result.to_dict() for result in evaluations],
    }


def _gateway_document(
    source: str,
    policy: dict[str, Any],
    policy_label: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    return {
        "policy": policy_label,
        "policy_provenance": policy_provenance(policy),
        **evaluate_mcp_request(data, policy).to_dict(source=Path(source).name),
    }


def _doctor_document(policy: dict[str, Any], policy_label: str) -> dict[str, Any]:
    rule_counts = {
        section: sum(len(patterns) for patterns in values.values())
        for section, values in policy.get("rules", {}).items()
    }
    return {
        "schema_version": 1,
        "kind": "policy_doctor",
        "status": "ok",
        "policy": policy_label,
        "default_decision": policy["default_decision"],
        "rule_counts": rule_counts,
        "policy_provenance": policy_provenance(policy),
        "network_access": False,
        "files_modified": False,
    }


def _doctor_markdown(payload: dict[str, Any]) -> str:
    provenance = payload["policy_provenance"]
    lines = [
        "# PolicyLatch doctor",
        "",
        f"Status: **{payload['status'].upper()}**",
        f"Policy: `{payload['policy']}`",
        f"Default decision: **{payload['default_decision'].upper()}**",
        "",
        "## Resolved sources",
        "",
    ]
    lines.extend(f"- `{source}`" for source in provenance["sources"])
    lines.extend(["", "## Rule counts", ""])
    lines.extend(
        f"- `{section}`: {count}" for section, count in sorted(payload["rule_counts"].items())
    )
    lines.extend(["", "> Offline validation only; no files were modified.", ""])
    return "\n".join(lines)


def _explain_document(payload: dict[str, Any]) -> dict[str, Any]:
    rows = validate_report(payload)
    provenance = payload.get("policy_provenance")
    if not isinstance(provenance, dict):
        raise InputError("Saved report does not contain policy_provenance.")
    rule_sources = provenance.get("rule_sources")
    if not isinstance(rule_sources, dict):
        raise InputError("Saved report policy_provenance does not contain rule_sources.")
    findings = []
    for row in rows:
        for reason in row.get("reasons", []):
            findings.append(
                {
                    "subject": row.get("subject", "action"),
                    "rule": reason["rule"],
                    "effect": reason["effect"],
                    "source": rule_sources.get(reason["rule"], "default-or-runtime-rule"),
                    "message": reason["message"],
                }
            )
    return {
        "schema_version": 1,
        "kind": "policy_explanation",
        "decision": payload["decision"],
        "risk_level": payload["risk_level"],
        "policy": payload.get("policy", "unknown"),
        "policy_provenance": provenance,
        "findings": findings,
    }


def _explain_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# PolicyLatch explanation",
        "",
        f"Decision: **{payload['decision'].upper()}**",
        f"Policy: `{payload['policy']}`",
        "",
        "## Rule provenance",
        "",
    ]
    if payload["findings"]:
        for finding in payload["findings"]:
            lines.append(
                f"- **{finding['effect'].upper()}** `{finding['rule']}` from "
                f"`{finding['source']}`: {finding['message']}"
            )
    else:
        lines.append("No warn or deny finding; the resolved default decision applied.")
    lines.append("")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    if args.command == "policy-init":
        manifest = _read_json(args.mcp_config)
        if args.check:
            if not (args.policy or args.profile):
                raise InputError("policy-init --check requires --policy or --profile.")
            if args.force:
                raise InputError("policy-init --check does not accept --force.")
            policy, label = _selected_policy(args)
            payload = policy_coverage_document(manifest, policy, label, args.mcp_config)
            validate_report(payload)
            renderer = json_report if args.format == "json" else sarif_report
            _write(renderer(payload), args.output)
            return EXIT_CODES[payload["decision"]]
        if args.policy or args.profile:
            raise InputError("Policy selectors are only valid with policy-init --check.")
        if args.format != "json":
            raise InputError("Draft generation emits YAML; --format is only valid with --check.")
        draft = policy_draft_document(manifest, args.mcp_config)
        _write_new(policy_draft_yaml(draft), args.output, force=args.force)
        return 0
    if args.command == "schema":
        _write(json_report(export_schema(args.kind)), args.output)
        return 0
    if args.command == "policy-lint":
        policy, label = _selected_policy(args)
        payload = lint_policy_document(policy, label)
        validate_report(payload)
        renderer = json_report if args.format == "json" else sarif_report
        _write(renderer(payload), args.output)
        return EXIT_CODES[payload["decision"]]
    if args.command == "policy-test":
        policy, label = _selected_policy(args)
        payload = policy_test_document(
            load_policy_fixtures(args.fixtures),
            policy,
            label,
            args.fixtures,
        )
        validate_report(payload)
        renderer = json_report if args.format == "json" else sarif_report
        _write(renderer(payload), args.output)
        return EXIT_CODES[payload["decision"]]
    if args.command == "adapter-config":
        policy = None
        if args.policy:
            load_policy(args.policy)
            policy = str(Path(args.policy).resolve())
        payload = adapter_config_document(
            args.runtime,
            policy=policy,
            profile=args.profile,
            platform=args.platform,
        )
        _write(json_report(payload), args.output)
        print(
            f"Review and manually merge this snippet into {config_target(args.runtime)}.",
            file=sys.stderr,
        )
        return 0
    if args.command == "adapter-doctor":
        payload = validate_adapter_config(args.runtime, _read_json(args.config))
        _write(json_report(payload), args.output)
        return 0
    if args.command in {"adapter-check", "adapter-hook"}:
        data = _read_json(args.input, max_bytes=MAX_GATEWAY_REQUEST_BYTES)
        policy, label = _selected_policy(args)
        payload = adapter_decision_document(
            args.runtime,
            data,
            policy,
            label if args.profile else safe_policy_label(args.policy),
        )
        if args.command == "adapter-hook":
            _write(json_report(hook_response(args.runtime, payload)), args.output)
            return 0
        validate_report(payload)
        rendered = {
            "json": json_report,
            "markdown": markdown_report,
            "html": html_report,
            "sarif": sarif_report,
        }[args.format](payload)
        _write(rendered, args.output)
        return EXIT_CODES[payload["decision"]]
    if args.command == "windows-compare":
        before = parse_observed_windows_snapshot(_read_json(args.before))
        after = parse_observed_windows_snapshot(_read_json(args.after))
        proposed = None
        if args.proposed:
            data = _read_json(args.proposed)
            proposed = (
                parse_windows_setting_action(data)
                if "action_type" in data
                else parse_windows_audit_record(data)
            )
        record = compare_windows_snapshots(before, after, proposed=proposed)
        _write(json_report(record.to_dict()), args.output)
        return 0
    if args.command == "windows-snapshot":
        providers = {
            "registry-key": RegistryKeyPresenceProvider,
            "service": ServiceSummaryProvider,
            "firewall": FirewallProfileProvider,
            "firewall-rule": FirewallRulePresenceProvider,
            "long-paths": LongPathsPolicyProvider,
        }
        snapshot = collect_windows_snapshot(
            providers[args.provider](),
            args.target,
            enabled=args.enable_windows_audit,
        )
        _write(json_report(snapshot.to_dict()), args.output)
        return 0
    if args.command == "audit-append":
        data = _read_json(args.input)
        record = (
            parse_windows_setting_action(data)
            if "action_type" in data
            else parse_windows_audit_record(data)
        )
        append_audit_record(args.history, record, enabled=args.enable_history)
        print(f"Appended {args.history}", file=sys.stderr)
        return 0
    if args.command == "audit-report":
        records = filter_audit_history(
            load_audit_history(args.input),
            category=args.category,
            verification_state=args.verification_state,
            from_timestamp=args.from_timestamp,
            to_timestamp=args.to_timestamp,
        )
        filters = {
            "category": args.category,
            "verification_state": args.verification_state,
            "from_timestamp": args.from_timestamp,
            "to_timestamp": args.to_timestamp,
        }
        payload = history_document(records, source=args.input, filters=filters)
        renderer = history_json_report if args.format == "json" else history_html_report
        _write(renderer(payload), args.output)
        return 0
    if args.command == "doctor":
        policy, label = _selected_policy(args)
        payload = _doctor_document(policy, label)
        rendered = json_report(payload) if args.format == "json" else _doctor_markdown(payload)
        _write(rendered, args.output)
        return 0
    if args.command == "explain":
        payload = _explain_document(_read_json(args.input))
        rendered = json_report(payload) if args.format == "json" else _explain_markdown(payload)
        _write(rendered, args.output)
        return 0
    if args.command == "gateway-replay":
        policy, label = _selected_policy(args)
        payload = gateway_trace_document(
            load_gateway_trace(args.input, policy),
            source=args.input,
            policy=label,
        )
        payload["policy_provenance"] = policy_provenance(policy)
    elif args.command == "report":
        payload = _read_json(args.input)
    elif args.command == "check":
        data = _read_json(args.action)
        policy, label = _selected_policy(args)
        payload = _action_document(args.action, policy, label, data)
    elif args.command == "gateway-check":
        data = _read_json(args.request, max_bytes=MAX_GATEWAY_REQUEST_BYTES)
        policy, label = _selected_policy(args)
        payload = _gateway_document(args.request, policy, label, data)
    else:
        data = _read_json(args.mcp_config)
        policy, label = _selected_policy(args)
        payload = _scan_document(args.mcp_config, policy, label, data)

    validate_report(payload)
    decision = payload["decision"]
    renderers = {
        "json": json_report,
        "markdown": markdown_report,
        "html": html_report,
        "sarif": sarif_report,
    }
    rendered = renderers[args.format](payload)
    _write(rendered, args.output)
    return EXIT_CODES[decision]


def main(argv: list[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except (
        GatewayTraceError,
        InputError,
        PolicyError,
        WindowsProviderError,
        OSError,
        ValueError,
    ) as exc:
        print(f"policylatch: error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
