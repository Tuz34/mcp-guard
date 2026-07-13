from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .evaluator import evaluate_action
from .html_report import html_report
from .models import aggregate
from .policy import PolicyError, load_policy
from .reports import json_report, markdown_report, validate_report
from .scanners import scan_manifest
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


def _read_json(path: str) -> dict[str, Any]:
    input_path = Path(path)
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"Could not read JSON input '{input_path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(
            f"Invalid JSON in '{input_path}' at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Pre-flight policy checks for MCP tools and AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for command, input_flag, help_text in [
        ("check", "--action", "Evaluate an agent action JSON file."),
        ("scan", "--mcp-config", "Scan an MCP config or tool manifest JSON file."),
    ]:
        child = sub.add_parser(command, help=help_text)
        child.add_argument(input_flag, required=True)
        child.add_argument("--policy", required=True)
        child.add_argument("--format", choices=["json", "markdown", "html"], default="json")
        child.add_argument("--output", help="Write the report to this path instead of stdout.")
    report = sub.add_parser("report", help="Convert a saved JSON result into a report.")
    report.add_argument("--input", required=True)
    report.add_argument("--format", choices=["json", "markdown", "html"], default="markdown")
    report.add_argument("--output", help="Write the report to this path instead of stdout.")
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


def _action_document(source: str, policy_path: str, data: dict[str, Any]) -> dict[str, Any]:
    policy = load_policy(policy_path)
    evaluation = evaluate_action(data, policy)
    return {
        "schema_version": 1,
        "kind": "action_evaluation",
        "source": source,
        "policy": policy_path,
        **evaluation.to_dict(),
    }


def _scan_document(source: str, policy_path: str, data: dict[str, Any]) -> dict[str, Any]:
    policy = load_policy(policy_path)
    evaluations = scan_manifest(data, policy)
    decision, risk_level = aggregate(evaluations)
    counts = {name: sum(item.decision == name for item in evaluations) for name in EXIT_CODES}
    return {
        "schema_version": 1,
        "kind": "manifest_scan",
        "source": source,
        "policy": policy_path,
        "decision": decision,
        "risk_level": risk_level,
        "summary": {"total": len(evaluations), **counts},
        "results": [result.to_dict() for result in evaluations],
    }


def run(args: argparse.Namespace) -> int:
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
    if args.command == "report":
        payload = _read_json(args.input)
    elif args.command == "check":
        data = _read_json(args.action)
        payload = _action_document(args.action, args.policy, data)
    else:
        data = _read_json(args.mcp_config)
        payload = _scan_document(args.mcp_config, args.policy, data)

    validate_report(payload)
    decision = payload["decision"]
    renderers = {"json": json_report, "markdown": markdown_report, "html": html_report}
    rendered = renderers[args.format](payload)
    _write(rendered, args.output)
    return EXIT_CODES[decision]


def main(argv: list[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except (InputError, PolicyError, WindowsProviderError, OSError, ValueError) as exc:
        print(f"mcp-guard: error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
