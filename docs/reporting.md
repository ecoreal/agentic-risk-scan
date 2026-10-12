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

Generate a ready-to-use workflow:

```bash
agentic-risk-scan init-ci --report-artifact
```

Or write the workflow manually:

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
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0
      - uses: ecoreal/agentic-risk-scan@v0
        with:
          command: report
          format: html
          output: agentic-risk-report.html
          fail_on: high
          changed_from: origin/${{ github.base_ref }}
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        if: always()
        with:
          name: agentic-risk-report
          path: agentic-risk-report.html
```

Use Markdown instead when another workflow step will post the report body into a
pull request comment.
