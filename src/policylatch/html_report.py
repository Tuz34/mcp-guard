# ruff: noqa: E501

from __future__ import annotations

from html import escape
from typing import Any

from .reports import validate_report


def _text(value: Any) -> str:
    return escape(str(value), quote=True)


def _count(rows: list[dict[str, Any]], decision: str) -> int:
    return sum(row["decision"] == decision for row in rows)


def html_report(data: dict[str, Any]) -> str:
    """Render a self-contained, script-free HTML report."""
    rows = validate_report(data)
    decision = data["decision"]
    risk_level = data["risk_level"]
    source = data.get("source", "action")

    result_rows = "\n".join(
        f"""<tr>
          <th scope="row">{_text(item.get("subject", "action"))}</th>
          <td><span class="badge badge-{_text(item["decision"])}">{_text(item["decision"]).upper()}</span></td>
          <td>{_text(item["risk_level"])}</td>
          <td>{len(item.get("reasons", []))}</td>
        </tr>"""
        for item in rows
    )

    finding_items: dict[str, list[str]] = {"deny": [], "warn": []}
    for item in rows:
        for reason in item.get("reasons", []):
            finding_items[reason["effect"]].append(
                f"""<li class="finding-item finding-{_text(reason["effect"])}">
          <div class="finding-main">
            <code>{_text(reason["rule"])}</code>
            <span>{_text(reason["message"])}</span>
          </div>
          <div class="finding-meta">
            <span>{_text(item.get("subject", "action"))}</span>
            <span aria-hidden="true">·</span>
            <code>{_text(reason["matched"])}</code>
          </div>
        </li>"""
            )

    finding_groups: list[str] = []
    group_labels = {
        "deny": "Blocked",
        "warn": "Needs review",
    }
    for effect in ("deny", "warn"):
        items = finding_items[effect]
        if items:
            heading = group_labels[effect]
            finding_groups.append(
                f"""<section class="finding-group" aria-labelledby="{effect}-findings-heading">
          <h3 id="{effect}-findings-heading">{heading} <span class="muted">({len(items)})</span></h3>
          <ul class="finding-list">{"".join(items)}</ul>
        </section>"""
            )
    findings = "\n".join(finding_groups) or (
        '<div class="empty-state"><strong>No policy findings.</strong>'
        "<span>The policy did not produce a warn or deny reason.</span></div>"
    )
    finding_count = sum(len(items) for items in finding_items.values())
    receipt = data.get("receipt")
    receipt_fingerprint = receipt.get("receipt_fingerprint") if isinstance(receipt, dict) else None
    receipt_html = (
        f"<span>Receipt: <code>{_text(receipt_fingerprint)}</code></span>"
        if isinstance(receipt_fingerprint, str)
        else ""
    )
    outcome = data.get("postflight_outcome")
    outcome_html = (
        f"<span>Outcome: <strong>{_text(outcome)}</strong></span>"
        if isinstance(outcome, str)
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>PolicyLatch report - {_text(decision).upper()}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0b0f14;
      --surface: #111821;
      --surface-raised: #17212d;
      --border: #2a3746;
      --text: #edf3f8;
      --muted: #9eacba;
      --allow: #57d27d;
      --warn: #f0b84b;
      --deny: #ff6b65;
      --focus: #79c0ff;
      --radius: 14px;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        radial-gradient(circle at 85% -10%, rgba(67, 120, 178, .18), transparent 34rem),
        var(--bg);
      color: var(--text);
      font-size: 14px;
      line-height: 1.55;
    }}
    main {{ width: min(980px, calc(100% - 28px)); margin: 0 auto; padding: 28px 0 44px; }}
    header {{ display: flex; justify-content: space-between; gap: 20px; align-items: flex-start; margin-bottom: 18px; }}
    .brand {{ display: flex; align-items: center; gap: 9px; font-weight: 800; letter-spacing: -.02em; }}
    .brand-mark {{ display: grid; place-items: center; width: 28px; height: 28px; border: 1px solid #3c5268; border-radius: 8px; background: #152434; color: var(--focus); }}
    h1 {{ margin: 9px 0 3px; font-size: clamp(1.65rem, 3vw, 2.35rem); line-height: 1.08; letter-spacing: -.04em; }}
    h2 {{ margin: 0 0 8px; font-size: .9rem; letter-spacing: 0; }}
    p {{ margin: 0; }}
    .eyebrow, .muted {{ color: var(--muted); }}
    .source {{ max-width: 52ch; overflow-wrap: anywhere; }}
    .panel {{ background: color-mix(in srgb, var(--surface) 94%, transparent); border: 1px solid var(--border); border-radius: 11px; box-shadow: 0 10px 32px rgba(0, 0, 0, .16); }}
    .decision {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1px; overflow: hidden; margin-bottom: 12px; background: var(--border); }}
    .decision > div {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; background: var(--surface); padding: 9px 12px; }}
    .metric-value {{ font-size: .95rem; font-weight: 760; }}
    .section {{ padding: 12px 14px; margin-top: 12px; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; }}
    th, td {{ padding: 7px 8px; border-bottom: 1px solid var(--border); font-size: .84rem; }}
    thead th {{ color: var(--muted); font-size: .7rem; text-transform: uppercase; letter-spacing: .06em; }}
    tbody th {{ font-weight: 520; }}
    tbody tr:last-child th, tbody tr:last-child td {{ border-bottom: 0; }}
    .badge {{ display: inline-flex; align-items: center; border: 1px solid currentColor; border-radius: 999px; padding: 3px 8px; font-size: .72rem; font-weight: 800; letter-spacing: .06em; }}
    .badge-allow {{ color: var(--allow); background: rgba(87, 210, 125, .08); }}
    .badge-warn {{ color: var(--warn); background: rgba(240, 184, 75, .08); }}
    .badge-deny {{ color: var(--deny); background: rgba(255, 107, 101, .08); }}
    h3 {{ margin: 0; font-size: 1rem; letter-spacing: -.01em; }}
    .finding-groups {{ display: grid; gap: 18px; }}
    .finding-group h3 {{ margin-bottom: 8px; }}
    .finding-list {{ display: grid; gap: 1px; margin: 0; padding: 0; overflow: hidden; border: 1px solid var(--border); border-radius: 11px; background: var(--border); list-style: none; }}
    .finding-item {{ display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; align-items: center; padding: 11px 14px; border-left: 3px solid var(--muted); background: var(--surface-raised); }}
    .finding-warn {{ border-left-color: var(--warn); }}
    .finding-deny {{ border-left-color: var(--deny); }}
    .finding-main {{ display: flex; gap: 9px; align-items: baseline; min-width: 0; }}
    .finding-main span {{ color: var(--muted); font-size: .84rem; }}
    .finding-meta {{ display: flex; gap: 7px; align-items: center; color: var(--muted); font-size: .78rem; white-space: nowrap; }}
    code {{ color: #b9d9f7; font: .88em ui-monospace, SFMono-Regular, Consolas, monospace; overflow-wrap: anywhere; }}
    .empty-state {{ display: flex; flex-direction: column; gap: 4px; grid-column: 1 / -1; padding: 22px; border: 1px dashed var(--border); border-radius: 11px; color: var(--muted); }}
    footer {{ display: flex; justify-content: space-between; gap: 20px; margin-top: 16px; padding: 2px; color: var(--muted); font-size: .78rem; }}
    @media (max-width: 760px) {{
      main {{ width: min(100% - 16px, 980px); padding-top: 18px; }}
      header {{ display: block; }}
      .decision {{ grid-template-columns: repeat(3, 1fr); }}
      .finding-item {{ grid-template-columns: 1fr; gap: 5px; }}
      .finding-main {{ display: grid; gap: 3px; }}
      footer {{ flex-direction: column; }}
    }}
    @media (prefers-color-scheme: light) {{
      :root {{ color-scheme: light; --bg: #f3f6f9; --surface: #ffffff; --surface-raised: #f8fafc; --border: #ced8e2; --text: #17212b; --muted: #566574; --allow: #187a3b; --warn: #8a5b00; --deny: #b42318; --focus: #0969da; }}
      body {{ background: radial-gradient(circle at 85% -10%, rgba(67, 120, 178, .12), transparent 34rem), var(--bg); }}
      .panel {{ box-shadow: 0 16px 40px rgba(34, 54, 74, .09); }}
      code {{ color: #075ea8; }}
    }}
    @media print {{
      :root {{ color-scheme: light; --bg: #fff; --surface: #fff; --surface-raised: #fff; --border: #bbb; --text: #111; --muted: #555; }}
      body {{ background: #fff; }}
      main {{ width: 100%; padding: 0; }}
      .panel {{ box-shadow: none; break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <div class="brand"><span class="brand-mark" aria-hidden="true">P</span>PolicyLatch</div>
        <h1>Permission report</h1>
        <p class="eyebrow">Pre-flight policy evaluation for MCP tools and AI agents</p>
      </div>
      <p class="source muted"><strong>Source</strong><br>{_text(source)}</p>
    </header>

    <section class="decision panel" aria-label="Decision summary">
      <div><span class="muted">Allow</span><strong class="metric-value">{_count(rows, "allow")}</strong></div>
      <div><span class="muted">Warn</span><strong class="metric-value">{_count(rows, "warn")}</strong></div>
      <div><span class="muted">Deny</span><strong class="metric-value">{_count(rows, "deny")}</strong></div>
    </section>

    <section class="section panel" aria-labelledby="results-heading">
      <h2 id="results-heading">Evaluated subjects <span class="muted">({len(rows)})</span></h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th scope="col">Subject</th><th scope="col">Decision</th><th scope="col">Risk</th><th scope="col">Findings</th></tr></thead>
          <tbody>{result_rows}</tbody>
        </table>
      </div>
    </section>

    <section class="section panel" aria-labelledby="findings-heading">
      <h2 id="findings-heading">Policy findings <span class="muted">({finding_count})</span></h2>
      <div class="finding-groups">{findings}</div>
    </section>

    <footer>
      <span>Risk: <strong>{_text(risk_level)}</strong></span>
      {outcome_html}
      {receipt_html}
      <span>Static local report. No scripts, telemetry, or external assets.</span>
    </footer>
  </main>
</body>
</html>
"""
