from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import ProjectConfig
from .inventory import InventoryResult
from .models import SEVERITY_ORDER, ScanResult


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    message: str
    recommendation: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = {
            "name": self.name,
            "status": self.status,
            "message": self.message,
        }
        if self.detail:
            data["detail"] = self.detail
        if self.recommendation:
            data["recommendation"] = self.recommendation
        return data


@dataclass
class DoctorResult:
    root: Path
    maturity: str
    checks: list[DoctorCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "agentic-risk-doctor-v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "root": str(self.root),
            "maturity": self.maturity,
            "summary": self.summary(),
            "checks": [check.to_dict() for check in self.checks],
        }

    def summary(self) -> dict[str, int]:
        counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
        for check in self.checks:
            counts[check.status] = counts.get(check.status, 0) + 1
        counts["total"] = len(self.checks)
        return counts


def diagnose_repository(
    root: Path,
    *,
    project_config: ProjectConfig,
    scan_result: ScanResult,
    inventory_result: InventoryResult,
) -> DoctorResult:
    checks = [
        config_check(project_config),
        workflow_check(root),
        report_artifact_check(root),
        baseline_check(root, project_config),
        findings_check(scan_result),
        inventory_check(inventory_result),
    ]
    return DoctorResult(root=root.resolve(), maturity=maturity(checks), checks=checks)


def config_check(project_config: ProjectConfig) -> DoctorCheck:
    if project_config.path:
        return DoctorCheck(
            name="project-config",
            status="pass",
            message="Project config is present.",
            detail=project_config.path.as_posix(),
        )
    return DoctorCheck(
        name="project-config",
        status="warn",
        message="No project config was found.",
        recommendation="Run agentic-risk-scan init-config and review the generated defaults.",
    )


def workflow_check(root: Path) -> DoctorCheck:
    workflows = scanner_workflows(root)
    if workflows:
        return DoctorCheck(
            name="ci-workflow",
            status="pass",
            message="GitHub Actions integration was found.",
            detail=", ".join(path.as_posix() for path in workflows),
        )
    return DoctorCheck(
        name="ci-workflow",
        status="warn",
        message="No agentic-risk-scan GitHub Actions workflow was found.",
        recommendation="Run agentic-risk-scan init-ci --report-artifact to add CI scanning and report artifacts.",
    )


def report_artifact_check(root: Path) -> DoctorCheck:
    workflows = scanner_workflows(root)
    if not workflows:
        return DoctorCheck(
            name="report-artifact",
            status="warn",
            message="No report artifact workflow was found.",
            recommendation="Run agentic-risk-scan init-ci --report-artifact.",
        )
    report_workflows = []
    for workflow in workflows:
        text = read_text(root / workflow)
        if "command: report" in text and "actions/upload-artifact" in text:
            report_workflows.append(workflow)
    if report_workflows:
        return DoctorCheck(
            name="report-artifact",
            status="pass",
            message="HTML report artifact workflow is configured.",
            detail=", ".join(path.as_posix() for path in report_workflows),
        )
    return DoctorCheck(
        name="report-artifact",
        status="info",
        message="CI scanning is configured, but report artifacts are not enabled.",
        recommendation="Run agentic-risk-scan init-ci --report-artifact --force or add command: report artifact steps manually.",
    )


def baseline_check(root: Path, project_config: ProjectConfig) -> DoctorCheck:
    candidates = []
    if project_config.baseline:
        candidates.append(project_config.baseline)
    candidates.append(root / ".agentic-risk-baseline.json")
    existing = [path for path in candidates if path.is_file()]
    if existing:
        return DoctorCheck(
            name="baseline",
            status="pass",
            message="A finding baseline is present.",
            detail=", ".join(path.as_posix() for path in existing),
        )
    return DoctorCheck(
        name="baseline",
        status="info",
        message="No baseline file was found.",
        recommendation="For existing repositories, create one with agentic-risk-scan scan . --update-baseline .agentic-risk-baseline.json --fail-on none.",
    )


def findings_check(scan_result: ScanResult) -> DoctorCheck:
    summary = scan_result.summary()
    high_or_worse = summary["critical"] + summary["high"]
    if high_or_worse:
        return DoctorCheck(
            name="current-findings",
            status="fail",
            message=f"{high_or_worse} high-or-worse finding(s) are present.",
            detail=format_findings_summary(summary),
            recommendation="Fix high and critical findings before enabling write-back, secrets, privileged runners, or persistent agent approvals.",
        )
    if summary["total"]:
        return DoctorCheck(
            name="current-findings",
            status="warn",
            message=f"{summary['total']} lower-severity finding(s) are present.",
            detail=format_findings_summary(summary),
            recommendation="Triage medium and low findings, then baseline reviewed exceptions.",
        )
    return DoctorCheck(
        name="current-findings",
        status="pass",
        message="No findings were detected with the current rule set and configuration.",
    )


def inventory_check(inventory_result: InventoryResult) -> DoctorCheck:
    summary = inventory_result.summary()
    if summary["total"]:
        return DoctorCheck(
            name="attack-surface-inventory",
            status="info",
            message=f"{summary['total']} agentic attack surface(s) were inventoried.",
            detail=", ".join(
                f"{key}={value}"
                for key, value in sorted(summary.items())
                if key != "total"
            ),
            recommendation="Review inventory when adding new agent workflows, settings, MCP servers, or package scripts.",
        )
    return DoctorCheck(
        name="attack-surface-inventory",
        status="pass",
        message="No known agentic attack surfaces were detected.",
    )


def maturity(checks: list[DoctorCheck]) -> str:
    by_name = {check.name: check for check in checks}
    if any(check.status == "fail" for check in checks):
        return "needs-attention"
    if by_name["ci-workflow"].status == "pass" and by_name["report-artifact"].status == "pass":
        return "reporting"
    if by_name["ci-workflow"].status == "pass":
        return "monitoring"
    if by_name["project-config"].status == "pass":
        return "configured"
    return "not-installed"


def scanner_workflows(root: Path) -> list[Path]:
    workflow_root = root / ".github" / "workflows"
    if not workflow_root.is_dir():
        return []
    matches: list[Path] = []
    for workflow in sorted(workflow_root.glob("*.y*ml")):
        text = read_text(workflow)
        if "agentic-risk-scan" in text or "ecoreal/agentic-risk-scan" in text:
            matches.append(workflow.relative_to(root))
    return matches


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def format_findings_summary(summary: dict[str, int]) -> str:
    return ", ".join(
        f"{severity}={summary[severity]}"
        for severity in ("critical", "high", "medium", "low", "info")
        if summary.get(severity)
    )


def render_doctor(result: DoctorResult, *, fmt: str) -> str:
    if fmt == "text":
        return render_doctor_text(result)
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"
    if fmt == "markdown":
        return render_doctor_markdown(result)
    raise ValueError(f"unknown doctor output format: {fmt}")


def render_doctor_text(result: DoctorResult) -> str:
    lines = [
        "Agentic Risk Doctor",
        f"root: {result.root}",
        f"maturity: {result.maturity}",
    ]
    for check in result.checks:
        lines.extend(["", f"[{check.status.upper()}] {check.name}", f"  {check.message}"])
        if check.detail:
            lines.append(f"  detail: {check.detail}")
        if check.recommendation:
            lines.append(f"  next: {check.recommendation}")
    return "\n".join(lines) + "\n"


def render_doctor_markdown(result: DoctorResult) -> str:
    lines = [
        "# Agentic Risk Doctor",
        "",
        f"- Root: `{result.root}`",
        f"- Maturity: `{result.maturity}`",
        "",
        "| Status | Check | Message | Next step |",
        "| --- | --- | --- | --- |",
    ]
    for check in result.checks:
        lines.append(
            f"| `{check.status}` | `{check.name}` | {escape_table(check.message)}"
            f"{detail_suffix(check)} | {escape_table(check.recommendation)} |"
        )
    return "\n".join(lines) + "\n"


def detail_suffix(check: DoctorCheck) -> str:
    if not check.detail:
        return ""
    return f"<br><small>{escape_table(check.detail)}</small>"


def escape_table(value: str) -> str:
    return " ".join(value.split()).replace("|", "\\|")
