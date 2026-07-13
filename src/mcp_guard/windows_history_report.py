# ruff: noqa: E501

from __future__ import annotations

import json
from html import escape
from typing import Any

from .windows_audit import VERIFICATION_STATES, WINDOWS_CATEGORIES, WindowsAuditRecord


def history_document(
    records: list[WindowsAuditRecord],
    *,
    source: str,
    filters: dict[str, str | None] | None = None,
) -> dict[str, Any]:
    applied = {key: value for key, value in (filters or {}).items() if value is not None}
    counts = {
        state: sum(record.verification_state == state for record in records)
        for state in sorted(VERIFICATION_STATES)
    }
    return {
        "schema_version": 1,
        "kind": "windows_audit_history",
        "source": source,
        "summary": {"total": len(records), **counts},
        "filters": applied,
        "records": [record.to_dict() for record in records],
    }


def _text(value: Any) -> str:
    return escape(str(value), quote=True)


def _validate_history_document(data: dict[str, Any]) -> list[dict[str, Any]]:
    if data.get("schema_version") != 1 or data.get("kind") != "windows_audit_history":
        raise ValueError("Expected a version 1 windows_audit_history document.")
    records = data.get("records")
    if not isinstance(records, list):
        raise ValueError("Windows audit history records must be an array.")
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"Windows audit history record {index} must be an object.")
        if record.get("verification_state") not in VERIFICATION_STATES:
            raise ValueError(f"Windows audit history record {index} has an invalid state.")
        if record.get("category") not in WINDOWS_CATEGORIES:
            raise ValueError(f"Windows audit history record {index} has an invalid category.")
    return records


def history_json_report(data: dict[str, Any]) -> str:
    _validate_history_document(data)
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def history_html_report(data: dict[str, Any]) -> str:
    """Render compact, script-free audit history after static CLI filtering."""

    records = _validate_history_document(data)
    summary = data.get("summary", {})
    filters = data.get("filters", {})
    if not isinstance(summary, dict) or not isinstance(filters, dict):
        raise ValueError("Windows audit history summary and filters must be objects.")

    filter_items = (
        "".join(
            f"<li><span>{_text(name.replace('_', ' '))}</span><strong>{_text(value)}</strong></li>"
            for name, value in filters.items()
        )
        or "<li><span>Filters</span><strong>none</strong></li>"
    )

    rows: list[str] = []
    for record in records:
        before = record.get("before", {})
        after = record.get("after", {})
        before_present = before.get("present") if isinstance(before, dict) else None
        after_present = after.get("present") if isinstance(after, dict) else None
        presence = f"{before_present} → {after_present}"
        identity = (
            " / ".join(
                _text(value)
                for value in (record.get("actor"), record.get("tool"))
                if value is not None
            )
            or "—"
        )
        rows.append(
            f"""<tr>
              <td><time>{_text(record.get("timestamp", ""))}</time></td>
              <td><span class="badge state-{_text(record.get("verification_state", ""))}">{_text(record.get("verification_state", ""))}</span></td>
              <td>{_text(record.get("category", ""))}</td>
              <th scope="row">{_text(record.get("target", ""))}</th>
              <td>{_text(record.get("operation", ""))}</td>
              <td>{_text(record.get("change", ""))}<small>{_text(presence)}</small></td>
              <td>{identity}<small>{_text(record.get("source", ""))}</small></td>
            </tr>"""
        )
    table_body = "".join(rows) or (
        '<tr><td colspan="7" class="empty">No records match the selected filters.</td></tr>'
    )

    return f"""<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark light">
  <title>mcp-guard Windows audit history</title>
  <style>
    :root {{ color-scheme:dark;--bg:#0b0f14;--panel:#111821;--line:#2a3746;--text:#edf3f8;--muted:#9eacba;--proposed:#79c0ff;--observed:#f0b84b;--verified:#57d27d;font:13px/1.45 Inter,system-ui,sans-serif; }}
    * {{ box-sizing:border-box; }} body {{ margin:0;background:var(--bg);color:var(--text); }} main {{ width:min(1180px,calc(100% - 24px));margin:auto;padding:22px 0 36px; }}
    header {{ display:flex;justify-content:space-between;gap:18px;align-items:flex-end;margin-bottom:12px; }} h1 {{ margin:0;font-size:1.5rem; }} p {{ margin:3px 0 0;color:var(--muted); }}
    .metrics,.filters {{ display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px;padding:0;list-style:none; }} .metrics li,.filters li {{ display:flex;gap:8px;padding:6px 9px;border:1px solid var(--line);border-radius:8px;background:var(--panel); }}
    .metrics span,.filters span,small {{ color:var(--muted); }} .table-wrap {{ overflow:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel); }} table {{ width:100%;border-collapse:collapse;text-align:left; }}
    th,td {{ padding:8px 9px;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap; }} thead th {{ color:var(--muted);font-size:.69rem;text-transform:uppercase;letter-spacing:.05em; }} tbody th {{ font-weight:550; }} tbody tr:last-child>* {{ border-bottom:0; }}
    small {{ display:block;margin-top:2px;max-width:32ch;overflow-wrap:anywhere;white-space:normal; }} .badge {{ display:inline-block;border:1px solid currentColor;border-radius:999px;padding:2px 6px;font-size:.69rem;font-weight:750;text-transform:uppercase; }}
    .state-proposed {{ color:var(--proposed); }} .state-observed {{ color:var(--observed); }} .state-verified {{ color:var(--verified); }} .empty {{ padding:28px;color:var(--muted);text-align:center; }} footer {{ margin-top:10px;color:var(--muted);font-size:.76rem; }}
    @media(max-width:700px) {{ header {{ display:block; }} main {{ width:calc(100% - 12px);padding-top:12px; }} }} @media(prefers-color-scheme:light) {{ :root {{ color-scheme:light;--bg:#f3f6f9;--panel:#fff;--line:#ced8e2;--text:#17212b;--muted:#566574;--proposed:#0969da;--observed:#8a5b00;--verified:#187a3b; }} }} @media print {{ :root {{ color-scheme:light;--bg:#fff;--panel:#fff;--line:#bbb;--text:#111;--muted:#555; }} main {{ width:100%;padding:0; }} }}
  </style>
</head><body><main>
  <header><div><h1>Windows audit history</h1><p>Summary-only proposed, observed, and verified records</p></div><p><strong>Source</strong><br>{_text(data.get("source", ""))}</p></header>
  <ul class="metrics" aria-label="History summary"><li><span>Total</span><strong>{_text(summary.get("total", len(records)))}</strong></li><li><span>Proposed</span><strong>{_text(summary.get("proposed", 0))}</strong></li><li><span>Observed</span><strong>{_text(summary.get("observed", 0))}</strong></li><li><span>Verified</span><strong>{_text(summary.get("verified", 0))}</strong></li></ul>
  <ul class="filters" aria-label="Applied filters">{filter_items}</ul>
  <div class="table-wrap"><table><thead><tr><th>Timestamp</th><th>State</th><th>Category</th><th>Target</th><th>Operation</th><th>Change</th><th>Actor / source</th></tr></thead><tbody>{table_body}</tbody></table></div>
  <footer>Static local report. Filters are applied during generation. No scripts, telemetry, or external assets.</footer>
</main></body></html>
"""
