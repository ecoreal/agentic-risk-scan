from __future__ import annotations

from pathlib import Path


DEFAULT_WORKFLOW_PATH = Path(".github/workflows/agentic-risk-scan.yml")


def render_workflow(*, mode: str = "both", fail_on: str = "high") -> str:
    if mode not in {"pr", "full", "both"}:
        raise ValueError(f"unknown workflow mode: {mode}")
    if mode == "pr":
        return workflow_header("pull_request") + "jobs:\n" + pr_job(fail_on)
    if mode == "full":
        return workflow_header("push_schedule") + "jobs:\n" + full_job(fail_on)
    return workflow_header("both") + "jobs:\n" + pr_job(fail_on) + "\n" + full_job(fail_on)


def write_workflow(path: Path, *, mode: str, fail_on: str, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_workflow(mode=mode, fail_on=fail_on), encoding="utf-8")


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


def pr_job(fail_on: str) -> str:
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
"""


def full_job(fail_on: str) -> str:
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
"""
