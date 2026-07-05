from __future__ import annotations

from pathlib import Path


DEFAULT_WORKFLOW_PATH = Path(".github/workflows/agentic-risk-scan.yml")


def render_workflow(*, mode: str = "both", fail_on: str = "high", report_artifact: bool = False) -> str:
    if mode not in {"pr", "full", "both"}:
        raise ValueError(f"unknown workflow mode: {mode}")
    if mode == "pr":
        return workflow_header("pull_request") + "jobs:\n" + pr_job(fail_on, report_artifact=report_artifact)
    if mode == "full":
        return workflow_header("push_schedule") + "jobs:\n" + full_job(fail_on, report_artifact=report_artifact)
    return (
        workflow_header("both")
        + "jobs:\n"
        + pr_job(fail_on, report_artifact=report_artifact)
        + "\n"
        + full_job(fail_on, report_artifact=report_artifact)
    )


def write_workflow(
    path: Path,
    *,
    mode: str,
    fail_on: str,
    report_artifact: bool = False,
    force: bool = False,
) -> None:
    if path.exists() and not force:
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_workflow(mode=mode, fail_on=fail_on, report_artifact=report_artifact), encoding="utf-8")


def workflow_header(kind: str) -> str:
    if kind == "pull_request":
        trigger = """on:
  pull_request:
"""
    elif kind == "push_schedule":
        trigger = """on:
  push:
    branches: [main]
  schedule:
    - cron: "17 4 * * 1"
"""
    else:
        trigger = """on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 4 * * 1"
"""
    return f"""name: agentic-risk-scan

{trigger}
permissions:
  contents: read
  security-events: write

"""


def pr_job(fail_on: str, *, report_artifact: bool = False) -> str:
    report_steps = pr_report_steps() if report_artifact else ""
    return f"""  pr-agentic-risk:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Fetch base branch
        run: |
          git fetch origin "${{{{ github.base_ref }}}}:refs/remotes/origin/${{{{ github.base_ref }}}}" --depth=1
      - uses: ecoreal/agentic-risk-scan@v0
        with:
          format: github
          fail_on: {fail_on}
          changed_from: origin/${{{{ github.base_ref }}}}
{report_steps}
"""


def full_job(fail_on: str, *, report_artifact: bool = False) -> str:
    report_steps = full_report_steps() if report_artifact else ""
    return f"""  full-agentic-risk:
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ecoreal/agentic-risk-scan@v0
        with:
          format: sarif
          output: agentic-risk.sarif
          fail_on: {fail_on}
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentic-risk.sarif
{report_steps}
"""


def pr_report_steps() -> str:
    return """      - uses: ecoreal/agentic-risk-scan@v0
        if: always()
        with:
          command: report
          format: html
          output: agentic-risk-pr-report.html
          fail_on: none
          changed_from: origin/${{ github.base_ref }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: agentic-risk-pr-report
          path: agentic-risk-pr-report.html
"""


def full_report_steps() -> str:
    return """      - uses: ecoreal/agentic-risk-scan@v0
        if: always()
        with:
          command: report
          format: html
          output: agentic-risk-full-report.html
          fail_on: none
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: agentic-risk-full-report
          path: agentic-risk-full-report.html
"""
