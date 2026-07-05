from __future__ import annotations

from datetime import datetime, timezone
from html import escape as html_escape

from .inventory import InventoryResult
from .models import SEVERITY_ORDER, Finding, ScanResult


def render_audit_report(
    scan_result: ScanResult,
    inventory_result: InventoryResult,
    *,
    fmt: str = "markdown",
) -> str:
    if fmt == "markdown":
        return render_markdown_report(scan_result, inventory_result)
    if fmt == "html":
        return render_html_report(scan_result, inventory_result)
    raise ValueError(f"unknown report output format: {fmt}")


def render_markdown_report(scan_result: ScanResult, inventory_result: InventoryResult) -> str:
    findings = scan_result.sorted_findings()
    items = inventory_result.sorted_items()
    summary = scan_result.summary()
    inventory_summary = inventory_result.summary()

    lines = [
        "# Agentic Risk Report",
        "",
        f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Root: `{scan_result.root}`",
        f"- Risk score: `{scan_result.risk_score()}/100`",
        "- Findings: "
        + (
            ", ".join(
                f"`{severity}: {summary[severity]}`"
                for severity in ("critical", "high", "medium", "low", "info")
                if summary[severity]
            )
            if summary["total"]
            else "`none`"
        ),
        "- Attack surfaces: "
        + (
            ", ".join(f"`{key}: {value}`" for key, value in sorted(inventory_summary.items()) if key != "total")
            if inventory_summary["total"]
            else "`none`"
        ),
        "",
        "## Executive Summary",
        "",
        executive_summary(scan_result, inventory_result),
        "",
        "## Priority Findings",
        "",
    ]

    if findings:
        lines.extend(render_finding_table(findings))
    else:
        lines.append("No findings were detected with the current rule set and configuration.")

    lines.extend(["", "## Attack Surface Inventory", ""])
    if items:
        lines.extend(
            [
                "| Category | Path | Detail | Signals |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in items:
            signals = ", ".join(item.signals) if item.signals else ""
            lines.append(
                f"| `{escape_table(item.category)}` | `{escape_table(item.path)}` | "
                f"{escape_table(item.detail)} | {escape_table(signals)} |"
            )
    else:
        lines.append("No agentic attack surfaces were detected.")

    lines.extend(["", "## Recommended Next Actions", ""])
    for action in recommended_actions(scan_result, inventory_result):
        lines.append(f"- {action}")

    lines.extend(
        [
            "",
            "## Reproduce",
            "",
            "```bash",
            "agentic-risk-scan scan . --format markdown --fail-on high",
            "agentic-risk-scan inventory . --format markdown",
            "agentic-risk-scan report . --output agentic-risk-report.md",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def render_html_report(scan_result: ScanResult, inventory_result: InventoryResult) -> str:
    findings = scan_result.sorted_findings()
    items = inventory_result.sorted_items()
    summary = scan_result.summary()
    inventory_summary = inventory_result.summary()
    generated_at = datetime.now(timezone.utc).isoformat()
    actions = recommended_actions(scan_result, inventory_result)

    finding_rows = "\n".join(
        "<tr>"
        f"<td><span class=\"severity {severity_class(finding.severity)}\">{html(finding.severity)}</span></td>"
        f"<td><code>{html(finding.rule_id)}</code></td>"
        f"<td><code>{html(finding.location.display())}</code></td>"
        f"<td>{html(finding.message)}</td>"
        f"<td>{html(finding.remediation)}</td>"
        "</tr>"
        for finding in findings
    )
    if not finding_rows:
        finding_rows = (
            "<tr><td colspan=\"5\" class=\"empty\">"
            "No findings were detected with the current rule set and configuration."
            "</td></tr>"
        )

    inventory_rows = "\n".join(
        "<tr>"
        f"<td><code>{html(item.category)}</code></td>"
        f"<td><code>{html(item.path)}</code></td>"
        f"<td>{html(item.detail)}</td>"
        f"<td>{html(', '.join(item.signals))}</td>"
        "</tr>"
        for item in items
    )
    if not inventory_rows:
        inventory_rows = "<tr><td colspan=\"4\" class=\"empty\">No agentic attack surfaces were detected.</td></tr>"

    action_items = "\n".join(f"<li>{html(action)}</li>" for action in actions)
    severity_summary = (
        " ".join(
            f"<span class=\"metric\"><strong>{summary[severity]}</strong>{html(severity)}</span>"
            for severity in ("critical", "high", "medium", "low", "info")
            if summary[severity]
        )
        or "<span class=\"metric\"><strong>0</strong>findings</span>"
    )
    surface_summary = (
        " ".join(
            f"<span class=\"metric\"><strong>{value}</strong>{html(key)}</span>"
            for key, value in sorted(inventory_summary.items())
            if key != "total"
        )
        or "<span class=\"metric\"><strong>0</strong>surfaces</span>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agentic Risk Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fb;
      --panel: #ffffff;
      --ink: #18202f;
      --muted: #5c667a;
      --line: #dce2ee;
      --critical: #8f1230;
      --high: #b23817;
      --medium: #8b6200;
      --low: #2b6f77;
      --info: #3e5f9a;
      --accent: #2457a6;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    header {{
      margin-bottom: 24px;
      border-bottom: 1px solid var(--line);
      padding-bottom: 20px;
    }}
    h1, h2 {{ margin: 0; letter-spacing: 0; }}
    h1 {{ font-size: 32px; line-height: 1.15; }}
    h2 {{ margin-top: 28px; margin-bottom: 12px; font-size: 20px; }}
    p {{ margin: 8px 0; }}
    code {{
      border: 1px solid var(--line);
      border-radius: 4px;
      background: #f4f6fa;
      padding: 1px 4px;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 12px;
    }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      margin-top: 18px;
    }}
    .metric {{
      display: inline-flex;
      align-items: baseline;
      gap: 6px;
      min-height: 34px;
      margin: 4px 6px 4px 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      padding: 6px 10px;
      color: var(--muted);
      white-space: nowrap;
    }}
    .metric strong {{
      color: var(--ink);
      font-size: 18px;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 16px;
      margin: 14px 0;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      border: 1px solid var(--line);
      background: var(--panel);
      table-layout: fixed;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }}
    th {{
      background: #eef2f8;
      color: #2f3a4d;
      font-size: 12px;
      text-transform: uppercase;
    }}
    .severity {{
      display: inline-block;
      min-width: 70px;
      border-radius: 999px;
      padding: 2px 8px;
      color: white;
      text-align: center;
      font-weight: 700;
      font-size: 12px;
    }}
    .severity-critical {{ background: var(--critical); }}
    .severity-high {{ background: var(--high); }}
    .severity-medium {{ background: var(--medium); }}
    .severity-low {{ background: var(--low); }}
    .severity-info {{ background: var(--info); }}
    .empty {{ color: var(--muted); }}
    ul {{ margin: 8px 0 0 20px; padding: 0; }}
    li {{ margin: 6px 0; }}
    pre {{
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #101828;
      color: #eef4ff;
      padding: 14px;
    }}
    pre code {{
      border: 0;
      background: transparent;
      color: inherit;
      padding: 0;
    }}
    a {{ color: var(--accent); }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Agentic Risk Report</h1>
      <p>Generated <code>{html(generated_at)}</code> for <code>{html(str(scan_result.root))}</code></p>
      <div class="meta">
        <div>{severity_summary}</div>
        <div>{surface_summary}</div>
        <div><span class="metric"><strong>{scan_result.risk_score()}</strong>risk score</span></div>
      </div>
    </header>

    <section class="panel">
      <h2>Executive Summary</h2>
      <p>{html(executive_summary(scan_result, inventory_result))}</p>
    </section>

    <section>
      <h2>Priority Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Rule</th><th>Location</th><th>Issue</th><th>Fix</th></tr>
        </thead>
        <tbody>
          {finding_rows}
        </tbody>
      </table>
    </section>

    <section>
      <h2>Attack Surface Inventory</h2>
      <table>
        <thead>
          <tr><th>Category</th><th>Path</th><th>Detail</th><th>Signals</th></tr>
        </thead>
        <tbody>
          {inventory_rows}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Recommended Next Actions</h2>
      <ul>
        {action_items}
      </ul>
    </section>

    <section>
      <h2>Reproduce</h2>
      <pre><code>agentic-risk-scan scan . --format markdown --fail-on high
agentic-risk-scan inventory . --format markdown
agentic-risk-scan report . --format html --output agentic-risk-report.html</code></pre>
    </section>
  </main>
</body>
</html>
"""


def executive_summary(scan_result: ScanResult, inventory_result: InventoryResult) -> str:
    findings = scan_result.findings
    surfaces = inventory_result.items
    high_or_worse = [
        finding
        for finding in findings
        if finding.rank >= SEVERITY_ORDER["high"]
    ]
    if high_or_worse:
        return (
            f"`{len(high_or_worse)}` high-or-worse finding(s) were found across "
            f"`{len(surfaces)}` agentic attack surface(s). Review these before "
            "granting agents write tokens, secrets, network access, or persistent tool approvals."
        )
    if findings:
        return (
            f"`{len(findings)}` lower-severity finding(s) were found across "
            f"`{len(surfaces)}` agentic attack surface(s). These are suitable for triage, "
            "baseline decisions, or policy hardening before stricter CI enforcement."
        )
    if surfaces:
        return (
            f"No findings were detected, but `{len(surfaces)}` agentic attack surface(s) "
            "are present. Keep the inventory under review as agent workflows and settings change."
        )
    return "No findings or known agentic attack surfaces were detected."


def render_finding_table(findings: list[Finding]) -> list[str]:
    lines = [
        "| Severity | Rule | Location | Issue | Fix |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        lines.append(
            f"| `{finding.severity}` | `{finding.rule_id}` | `{escape_table(finding.location.display())}` | "
            f"{escape_table(finding.message)} | {escape_table(finding.remediation)} |"
        )
    return lines


def recommended_actions(scan_result: ScanResult, inventory_result: InventoryResult) -> list[str]:
    findings = scan_result.findings
    rule_ids = {finding.rule_id for finding in findings}
    categories = {item.category for item in inventory_result.items}
    actions: list[str] = []

    if any(finding.rank >= SEVERITY_ORDER["high"] for finding in findings):
        actions.append("Fix critical and high findings before enabling write-back, secret access, or privileged runners.")
    elif findings:
        actions.append("Triage medium and low findings, then decide whether to baseline known exceptions.")
    else:
        actions.append("Keep the scan in CI so future agent workflow or config changes are reviewed automatically.")

    if any(rule_id.startswith("GHA") for rule_id in rule_ids) or "github-actions" in categories:
        actions.append("Review GitHub Actions trust boundaries: untrusted triggers, token scopes, secrets, OIDC, and runner isolation.")
    if any(rule_id.startswith("CFG") for rule_id in rule_ids) or "agent-config" in categories:
        actions.append("Review committed agent client settings for sandboxing, approvals, broad tool grants, hooks, and secret handling.")
    if any(rule_id.startswith("MCP") for rule_id in rule_ids) or "mcp" in categories:
        actions.append("Review MCP server launch paths, package pins, runtime permissions, and inline environment values.")
    if any(rule_id.startswith("AGENT") for rule_id in rule_ids) or "agent-instructions" in categories:
        actions.append("Review agent instruction files like code, especially changes to tool policy or hidden prompt text.")
    if any(rule_id.startswith("PKG") for rule_id in rule_ids) or "package-scripts" in categories:
        actions.append("Review npm lifecycle scripts and remote dependency specs before agents install or execute packages.")

    return dedupe(actions)


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def escape_table(value: str) -> str:
    return " ".join(value.split()).replace("|", "\\|")


def html(value: object) -> str:
    return html_escape(str(value), quote=True)


def severity_class(severity: str) -> str:
    if severity in {"critical", "high", "medium", "low", "info"}:
        return f"severity-{severity}"
    return "severity-info"
