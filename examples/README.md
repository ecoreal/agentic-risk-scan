# Examples

This directory contains small repositories for scanner demos and regression
testing.

## `unsafe-ai-pr-bot`

Contains intentionally risky patterns:

- `pull_request_target` with PR head checkout.
- Write-capable workflow token.
- Secret and OIDC exposure.
- Self-hosted runner use.
- Shell interpolation of GitHub comment text.
- Prompt-injection text in `AGENTS.md`.
- Shell-wrapped MCP server with inline secret.
- npm lifecycle script with `curl | bash`.

Run:

```bash
PYTHONPATH=../src python3 -m agentic_risk_scan scan unsafe-ai-pr-bot --fail-on none
PYTHONPATH=../src python3 -m agentic_risk_scan report unsafe-ai-pr-bot --format html --output unsafe-ai-pr-bot-report.html --fail-on none
```

## `safe-agent-workflow`

Shows a low-privilege pattern for PR-time agent analysis.

Run:

```bash
PYTHONPATH=../src python3 -m agentic_risk_scan scan safe-agent-workflow --fail-on high
```

## `unsafe-agent-configs`

Contains risky committed agent client settings:

- Claude Code broad `Bash(*)` and `Write(*)` permissions.
- Claude Code hook commands that download shell code and print a token.
- Codex `danger-full-access` sandbox mode.
- Codex `approval_policy = "never"`.
- Codex network-enabled workspace sandbox with broad writable roots.
- Codex full-access permission profile and secret-like environment value.
- Gemini CLI tool sandboxing disabled.
- Gemini CLI secret-redaction bypass and automatic approval settings.

Run:

```bash
PYTHONPATH=../src python3 -m agentic_risk_scan scan unsafe-agent-configs --fail-on none
```

## `safe-agent-configs`

Shows narrower agent client settings that should not trigger findings.

Run:

```bash
PYTHONPATH=../src python3 -m agentic_risk_scan scan safe-agent-configs --fail-on high
```
