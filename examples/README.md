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
```

## `safe-agent-workflow`

Shows a low-privilege pattern for PR-time agent analysis.

Run:

```bash
PYTHONPATH=../src python3 -m agentic_risk_scan scan safe-agent-workflow --fail-on high
```

