# Agentic Risk Scan

[![CI](https://github.com/ecoreal/agentic-risk-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/ecoreal/agentic-risk-scan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Static security scanner for AI agent workflows, MCP configs, and committed agent
instructions.

AI agents are now part of the software supply chain. They read PR titles, issue
comments, prompt files, MCP configs, package scripts, and workflow artifacts.
`agentic-risk-scan` looks for the repository patterns that make those inputs
dangerous: write-capable GitHub tokens, untrusted shell interpolation, hidden
Unicode prompt text, download-and-execute MCP servers, inline secrets, and risky
install scripts.

It is dependency-free, works on Python 3.10+, and is designed for CI, code review,
and quick local audits.

Read the deeper context:

- [Research notes](docs/research.md)
- [Project brief](docs/project-brief.md)
- [Threat model](docs/threat-model.md)

## Quick Start

```bash
python3 -m pip install -e .
agentic-risk-scan scan .
```

Run without installing:

```bash
PYTHONPATH=src python3 -m agentic_risk_scan scan .
```

Generate SARIF for GitHub code scanning:

```bash
agentic-risk-scan scan . --format sarif --output agentic-risk.sarif --fail-on high
```

Emit GitHub workflow annotations:

```bash
agentic-risk-scan scan . --format github --fail-on high
```

Scan only files changed in a pull request:

```bash
agentic-risk-scan scan . --changed-from origin/main --format github
```

Create a starter config:

```bash
agentic-risk-scan init-config
```

Create a ready-to-use GitHub Actions workflow:

```bash
agentic-risk-scan init-ci
```

## What It Finds

- `pull_request_target` workflows that check out untrusted PR code.
- AI or agent-like GitHub Actions with write tokens on issue, comment, PR, or
  workflow-run triggers.
- Shell commands that interpolate `github.event.*` text from PRs, issues,
  comments, discussions, or manual inputs.
- Secret and OIDC exposure in untrusted-trigger workflows.
- Self-hosted runner use from untrusted triggers.
- Prompt-injection phrases and hidden Unicode in `AGENTS.md`, `CLAUDE.md`,
  `.github/copilot-instructions.md`, `.cursor/rules/*`, and similar files.
- Risky committed agent client settings in `.claude/settings.json`,
  `.codex/config.toml`, and `.gemini/settings.json`, including broad tool
  grants, disabled approvals, full-access permission profiles, literal
  secret-like values, and secret-redaction bypasses.
- MCP servers launched through shell wrappers, runtime downloads, unpinned `npx`,
  broad runtime flags, temporary paths, or inline secret-like values.
- npm install lifecycle scripts with `curl | sh`, `eval`, inline interpreters,
  secret-printing, or remote tarball dependencies.

## Example

```bash
PYTHONPATH=src python3 -m agentic_risk_scan scan examples/unsafe-ai-pr-bot --fail-on none
```

Sample output:

```text
Agentic Risk Scan
root: /path/to/examples/unsafe-ai-pr-bot
risk score: 100/100
findings: critical=1, high=11, medium=3, low=1
scanned files: 4, skipped files: 0

[CRITICAL] GHA001 pull_request_target checks out untrusted PR code
  at: .github/workflows/unsafe.yml:16
  why: This workflow runs with target-repository privileges and checks out code from the pull request head.
```

## GitHub Actions

Generate this workflow automatically:

```bash
agentic-risk-scan init-ci --mode both
```

```yaml
name: agentic-risk-scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install "git+https://github.com/ecoreal/agentic-risk-scan@v0"
      - run: agentic-risk-scan scan . --format sarif --output agentic-risk.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentic-risk.sarif
```

Or use this repository as a composite action:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: ecoreal/agentic-risk-scan@v0
  with:
    format: github
    fail_on: high
    changed_from: origin/main
```

## Configuration

`agentic-risk-scan` auto-loads `.agentic-risk-scan.json` from the scan path or a
parent directory.

```json
{
  "$schema": "https://raw.githubusercontent.com/ecoreal/agentic-risk-scan/main/docs/config.schema.json",
  "fail_on": "high",
  "exclude": ["examples/fixtures/**"],
  "disabled_rules": ["PKG004"],
  "severity_overrides": {
    "AGENT005": "low"
  },
  "suppressions": [
    {
      "rule_id": "AGENT005",
      "path": "AGENTS.md",
      "reason": "Tool access is constrained by a separate sandbox policy."
    }
  ]
}
```

CLI flags override or extend config values:

```bash
agentic-risk-scan scan . --config security/agentic-risk.json
agentic-risk-scan scan . --exclude "examples/**" --disable-rule PKG004
agentic-risk-scan scan . --changed AGENTS.md --changed .github/workflows/agent.yml
```

Inline ignores are supported for reviewed exceptions:

```md
<!-- agentic-risk-scan: disable-next-line AGENT005 -->
allowed-tools: *
```

```yaml
run: echo "${{ github.event.issue.title }}" # agentic-risk-scan: ignore GHA003
```

## Baselines

Create a baseline when adopting the scanner in an existing repository:

```bash
agentic-risk-scan scan . --update-baseline .agentic-risk-baseline.json --fail-on none
```

Then fail only on new findings:

```bash
agentic-risk-scan scan . --baseline .agentic-risk-baseline.json --fail-on high
```

## Output Formats

```bash
agentic-risk-scan scan . --format text
agentic-risk-scan scan . --format json
agentic-risk-scan scan . --format markdown
agentic-risk-scan scan . --format sarif
agentic-risk-scan scan . --format github
```

## Pull Request Mode

Full-repository scans are useful for scheduled audits. Pull request checks often
need a tighter signal. Use `--changed` for explicit paths, or `--changed-from`
to let the scanner ask git for changed files:

```bash
agentic-risk-scan scan . --changed AGENTS.md --fail-on medium
agentic-risk-scan scan . --changed-from origin/main --changed-to HEAD --format github
```

Deleted files are ignored by default. The default git diff filter is `ACMR`
which covers added, copied, modified, and renamed files.

In GitHub Actions, set `actions/checkout` to `fetch-depth: 0` or fetch the base
branch before using `--changed-from origin/main`.

See [docs/rules.md](docs/rules.md) for the rule reference.
See [docs/threat-model.md](docs/threat-model.md) for the scanner threat model.

## Design Principles

- No dependency chain for the scanner itself.
- Useful before a full security program exists.
- Findings explain the input boundary, the risky privilege, and the fix.
- Rules favor high-signal agentic workflow risks over generic linting.

## Roadmap

- More agent ecosystem config coverage.
- Taint tracking for workflow artifacts and generated patches.
- npm, PyPI, Homebrew, and container releases.

## Contributing

Issues with minimal vulnerable and fixed examples are the most useful
contributions. Rule changes should include tests and should avoid flagging the
safe example repository.
