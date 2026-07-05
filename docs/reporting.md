# Reporting Guide

`agentic-risk-scan report` creates a single review artifact that combines scan
findings, attack-surface inventory, an executive summary, recommended next
actions, and reproduction commands.

## Local Reports

Markdown is useful for PR comments and issue bodies:

```bash
agentic-risk-scan report . --output agentic-risk-report.md --fail-on high
```

HTML is useful for demos, CI artifacts, and security review packets:

```bash
agentic-risk-scan report . --format html --output agentic-risk-report.html --fail-on high
```

Reports honor the same controls as `scan`, including project config, baselines,
changed-file scans, inline ignores, disabled rules, and fail thresholds.

## GitHub Actions Artifact

```yaml
name: agentic-risk-report

on:
  pull_request:

permissions:
  contents: read

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: ecoreal/agentic-risk-scan@v0
        with:
          command: report
          format: html
          output: agentic-risk-report.html
          fail_on: high
          changed_from: origin/${{ github.base_ref }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: agentic-risk-report
          path: agentic-risk-report.html
```

Use Markdown instead when another workflow step will post the report body into a
pull request comment.
