from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .models import Finding, ScanResult, SEVERITY_ORDER


def render(result: ScanResult, *, fmt: str) -> str:
    if fmt == "text":
        return render_text(result)
    if fmt == "json":
        return render_json(result)
    if fmt == "markdown":
        return render_markdown(result)
    if fmt == "sarif":
        return render_sarif(result)
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
    rules = {}
    sarif_results = []
    for finding in result.sorted_findings():
        rules[finding.rule_id] = sarif_rule(finding)
        sarif_results.append(sarif_result(finding))
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


def sarif_rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.message},
        "help": {"text": finding.remediation or finding.message},
        "properties": {
            "tags": list(finding.tags),
            "security-severity": str(security_severity(finding.severity)),
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
    return {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 2.5,
        "info": 0.5,
    }[severity]
