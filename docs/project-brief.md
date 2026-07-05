# Project Brief

## One-line Pitch

Agentic Risk Scan catches risky AI agent workflow, MCP, and instruction-file
patterns before they merge.

## Audience

- Maintainers adding AI PR bots, issue bots, or code-review agents.
- Security engineers reviewing `pull_request_target`, MCP, or agent config.
- Platform teams rolling out AI coding assistants across many repositories.
- Open-source maintainers who want lightweight CI checks without another
  dependency chain.

## Problem

AI agents read untrusted repository content and then often receive powerful
capabilities:

- GitHub workflow tokens with write permissions.
- Repository or environment secrets.
- OIDC cloud federation.
- Self-hosted runner access.
- MCP tools that can read files, call APIs, or execute commands.
- Agent instruction files that influence behavior across a repository.

Traditional scanners usually look at only one slice: secrets, dependencies,
workflow syntax, or broad repository posture. Agentic Risk Scan looks at the
handoff between untrusted agent input and privileged automation.

## What Makes It Different

- Dependency-free Python CLI.
- Rules are narrow and reviewable.
- Finds issues across GitHub Actions, agent instructions, MCP, and npm scripts.
- Covers risky committed agent settings for Claude Code, Codex, and Gemini CLI.
- Explains why the pattern matters and how to fix it.
- Works in CI with SARIF or GitHub annotations.
- Supports PR-only scans with `--changed` and `--changed-from`.
- Supports real adoption controls: baselines, suppressions, inline ignores, and
  severity overrides.

## Demo Narrative

Run the unsafe example:

```bash
PYTHONPATH=src python3 -m agentic_risk_scan scan examples/unsafe-ai-pr-bot --fail-on none
```

The scanner reports:

- `pull_request_target` checking out untrusted PR code.
- Write-capable workflow token on an agent-like workflow.
- Secret and OIDC exposure.
- Self-hosted runner access from untrusted events.
- Shell interpolation of issue or PR text.
- Prompt-injection text in `AGENTS.md`.
- Shell-wrapped MCP server with an inline secret.
- npm lifecycle script using download-and-execute behavior.

Run the unsafe agent config example:

```bash
PYTHONPATH=src python3 -m agentic_risk_scan scan examples/unsafe-agent-configs --fail-on none
```

The scanner reports broad Claude Code permissions, risky Claude hooks, literal
secret-like config values, Codex danger-full-access settings, disabled
approvals, network-enabled sandboxing, broad writable roots, full-access
permission profiles, disabled Gemini tool sandboxing, secret-redaction bypasses,
and automatic approval settings.

Then run the safe example:

```bash
PYTHONPATH=src python3 -m agentic_risk_scan scan examples/safe-agent-workflow --fail-on high
```

It returns no findings.

## Adoption Recipes

### Full audit

```bash
agentic-risk-scan scan . --format sarif --output agentic-risk.sarif
```

### Pull request check

```bash
agentic-risk-scan scan . --changed-from origin/main --format github
```

In GitHub Actions, use `actions/checkout` with `fetch-depth: 0` or fetch the
base branch before running this command.

Generate a workflow instead of writing it by hand:

```bash
agentic-risk-scan init-ci --mode both
```

### Existing repository rollout

```bash
agentic-risk-scan scan . --update-baseline .agentic-risk-baseline.json --fail-on none
agentic-risk-scan scan . --baseline .agentic-risk-baseline.json --fail-on high
```

## Roadmap Toward A Star-worthy Project

- Rule packs for more agent ecosystems: Codex, Claude, Cursor, Roo, Cline,
  Goose, and Copilot.
- Optional YAML-aware workflow parsing while keeping dependency-free mode.
- Autofix suggestions for common workflow permission patterns.
- GitHub App or reusable workflow wrapper for organization-wide rollout.
- Public rule playground with unsafe and fixed examples.
- Real-world finding gallery with sanitized case studies.

## Ethical Growth Strategy

The project should earn stars through utility, not fake engagement:

- Clear README and one-command demo.
- Useful examples that reproduce real risks.
- Short release notes with concrete improvements.
- Issues labeled for rule requests and false positives.
- Comparisons that fairly explain where the tool fits.
- Blog-style writeups about agent workflow security failures and fixes.
