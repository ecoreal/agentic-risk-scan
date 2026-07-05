# Adoption Guide

This guide is for maintainers and platform teams introducing
`agentic-risk-scan` into repositories that already use, or plan to use, AI
agents.

## 1. Diagnose The Repository

```bash
agentic-risk-scan doctor .
```

Doctor checks whether the repository has scanner config, CI integration, HTML
report artifacts, baselines, current findings, and agentic attack surfaces.

## 2. Inventory Agentic Attack Surfaces

```bash
agentic-risk-scan inventory . --format markdown
```

Review GitHub Actions workflows, agent instruction files, Claude/Codex/Gemini
settings, MCP configs, and npm package scripts before enforcing policy.

## 3. Add Config And CI

```bash
agentic-risk-scan init-config
agentic-risk-scan init-ci --report-artifact
```

The generated workflow runs pull-request checks, full scans, SARIF upload, and
HTML report artifact upload.

## 4. Baseline Existing Findings

For an existing repository, adopt without blocking all historical findings at
once:

```bash
agentic-risk-scan scan . --update-baseline .agentic-risk-baseline.json --fail-on none
agentic-risk-scan scan . --baseline .agentic-risk-baseline.json --fail-on high
```

Review the baseline in code review and remove entries as risks are fixed.

## 5. Enforce On New Changes

Use changed-file scans for pull requests:

```bash
agentic-risk-scan scan . --changed-from origin/main --format github --fail-on high
```

Use full scans on push and schedule for drift detection:

```bash
agentic-risk-scan scan . --format sarif --output agentic-risk.sarif --fail-on high
```

Run `agentic-risk-scan doctor .` again after setup. A mature rollout should show
CI integration and report artifacts as configured, and should have no current
high-or-worse findings.
