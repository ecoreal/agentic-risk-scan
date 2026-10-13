from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .models import Finding, ScanResult, SEVERITY_ORDER
from .registry import RULES, RULE_BY_ID, RuleInfo


def render(result: ScanResult, *, fmt: str) -> str:
    if fmt == "text":
        return render_text(result)
    if fmt == "json":
        return render_json(result)
    if fmt == "markdown":
        return render_markdown(result)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "github":
        return render_github_annotations(result)
    raise ValueError(f"unknown output format: {fmt}")


def render_text(result: ScanResult) -> str:
    summary = result.summary()
    lines = [
        "Agentic Risk Scan",
        f"root: {result.root}",
        f"risk score: {result.risk_score()}/100",
        "findings: "
        + ", ".join(
            f"{severity}={summary[severity]}"
            for severity in ("critical", "high", "medium", "low", "info")
            if summary[severity]
        )
        if summary["total"]
        else "findings: none",
        f"scanned files: {result.scanned_files}, skipped files: {result.skipped_files}",
    ]

    if not result.findings:
        return "\n".join(lines) + "\n"

    for finding in result.sorted_findings():
        lines.extend(
            [
                "",
                f"[{finding.severity.upper()}] {finding.rule_id} {finding.title}",
                f"  at: {finding.location.display()}",
                f"  why: {finding.message}",
            ]
        )
        if finding.evidence:
            lines.append(f"  evidence: {finding.evidence}")
        if finding.remediation:
            lines.append(f"  fix: {finding.remediation}")
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    payload = {
        "schema": "agentic-risk-scan-result-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(result.root),
        "summary": result.summary(),
        "risk_score": result.risk_score(),
        "scanned_files": result.scanned_files,
        "skipped_files": result.skipped_files,
        "findings": [finding.to_dict() for finding in result.sorted_findings()],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_markdown(result: ScanResult) -> str:
    summary = result.summary()
    lines = [
        "# Agentic Risk Scan Report",
        "",
        f"- Root: `{result.root}`",
        f"- Risk score: `{result.risk_score()}/100`",
        f"- Scanned files: `{result.scanned_files}`",
        f"- Skipped files: `{result.skipped_files}`",
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
    ]

    for finding in result.sorted_findings():
        lines.extend(
            [
                "",
                f"## {finding.severity.upper()} {finding.rule_id}: {finding.title}",
                "",
                f"- Location: `{finding.location.display()}`",
                f"- Message: {finding.message}",
            ]
        )
        if finding.evidence:
            lines.append(f"- Evidence: `{finding.evidence}`")
        if finding.remediation:
            lines.append(f"- Remediation: {finding.remediation}")
    return "\n".join(lines) + "\n"


def render_sarif(result: ScanResult) -> str:
    # Declare the full shipped rule taxonomy, not just the rules that fired:
    # GitHub code scanning keys the Security-tab rule list and help links off
    # driver.rules, and a stable taxonomy keeps successive SARIF uploads
    # attributable to the same rule ids.
    rules = {rule.rule_id: sarif_rule_from_registry(rule) for rule in RULES}
    sarif_results = [sarif_result(finding) for finding in result.sorted_findings()]
    payload: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentic-risk-scan",
                        "informationUri": "https://github.com/ecoreal/agentic-risk-scan",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def sarif_rule_from_registry(rule: RuleInfo) -> dict[str, Any]:
    return {
        "id": rule.rule_id,
        "name": rule.title,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": f"{rule.category}: {rule.title}"},
        "helpUri": rule.help_uri,
        "help": {"text": f"See {rule.help_uri} for remediation guidance."},
        "properties": {
            "tags": list(rule.tags),
            "security-severity": str(security_severity(rule.severity)),
        },
    }


def sarif_result(finding: Finding) -> dict[str, Any]:
    region: dict[str, int] = {}
    if finding.location.line is not None:
        region["startLine"] = finding.location.line
    if finding.location.column is not None:
        region["startColumn"] = finding.location.column

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": {"text": f"{finding.title}: {finding.message}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.path},
                    "region": region or {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"agenticRiskScan": finding.fingerprint()},
    }
    return result


def sarif_level(severity: str) -> str:
    if SEVERITY_ORDER[severity] >= SEVERITY_ORDER["high"]:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def security_severity(severity: str) -> float:
    # Registry severities can be ranges like "medium/high"; GitHub's scale
    # wants one number, so take the upper bound.
    parts = str(severity).split("/")
    return max(_SECURITY_SEVERITY_SCALE.get(part, 0.0) for part in parts)


_SECURITY_SEVERITY_SCALE = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.5,
}


def render_github_annotations(result: ScanResult) -> str:
    if not result.findings:
        return ""
    lines: list[str] = []
    for finding in result.sorted_findings():
        command = "error" if finding.rank >= SEVERITY_ORDER["high"] else "warning"
        location = f"file={escape_annotation_property(finding.location.path)}"
        if finding.location.line is not None:
            location += f",line={finding.location.line}"
        title = escape_annotation_property(f"{finding.rule_id} {finding.title}")
        message = escape_annotation_data(f"{finding.message} Fix: {finding.remediation}".strip())
        lines.append(f"::{command} {location},title={title}::{message}")
    return "\n".join(lines) + "\n"


def escape_annotation_property(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def escape_annotation_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
