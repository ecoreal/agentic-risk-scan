from __future__ import annotations

from datetime import datetime, timezone

from .inventory import InventoryResult
from .models import SEVERITY_ORDER, Finding, ScanResult


def render_audit_report(scan_result: ScanResult, inventory_result: InventoryResult) -> str:
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
