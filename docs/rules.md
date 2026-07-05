# Rule Reference

Agentic Risk Scan uses lightweight static rules. The goal is to catch dangerous
repository patterns early, not to prove exploitability.

This file is intentionally readable in code review. Machine-readable rule
metadata is available with:

```bash
agentic-risk-scan rules --format json
agentic-risk-scan rules --format markdown
```

## GitHub Actions

| Rule | Default severity | Description |
| --- | --- | --- |
| <a id="gha001"></a>`GHA001` | critical | `pull_request_target` checks out untrusted PR head code. |
| <a id="gha002"></a>`GHA002` | high | AI or agent workflow has write-capable token on an untrusted trigger. |
| <a id="gha003"></a>`GHA003` | high | Untrusted GitHub event text is interpolated into shell. |
| <a id="gha004"></a>`GHA004` | medium | Dangerous shell pattern appears in a workflow with untrusted triggers. |
| <a id="gha005"></a>`GHA005` | medium/high | Secrets are referenced from an untrusted-trigger workflow. |
| <a id="gha006"></a>`GHA006` | high | Untrusted events can reach a self-hosted runner. |
| <a id="gha007"></a>`GHA007` | high | OIDC token minting is enabled on an untrusted-trigger workflow. |

## Agent Instructions

| Rule | Default severity | Description |
| --- | --- | --- |
| <a id="agent001"></a>`AGENT001` | high | Bidirectional Unicode control character in agent instructions. |
| <a id="agent002"></a>`AGENT002` | medium | Zero-width Unicode character in agent instructions. |
| <a id="agent003"></a>`AGENT003` | high | Prompt-injection phrase in committed agent instructions. |
| <a id="agent004"></a>`AGENT004` | high | Dangerous command embedded in agent instructions. |
| <a id="agent005"></a>`AGENT005` | medium | Agent instruction file requests broad tool access. |

## Agent Config

| Rule | Default severity | Description |
| --- | --- | --- |
| <a id="cfg000"></a>`CFG000` | low | Agent settings file is invalid JSON. |
| <a id="cfg001"></a>`CFG001` | medium/high | Agent configuration grants broad tool permission. |
| <a id="cfg002"></a>`CFG002` | high | Agent configuration allows dangerous shell command. |
| <a id="cfg003"></a>`CFG003` | medium | Agent configuration grants broad filesystem access. |
| <a id="cfg004"></a>`CFG004` | high | Agent hook runs dangerous shell command. |
| <a id="cfg005"></a>`CFG005` | medium | Agent hook may expose secret environment values. |
| <a id="cfg006"></a>`CFG006` | medium | Agent tool sandboxing is disabled. |
| <a id="cfg007"></a>`CFG007` | high | Codex sandbox is disabled. |
| <a id="cfg008"></a>`CFG008` | high | Codex approvals are disabled. |
| <a id="cfg009"></a>`CFG009` | medium | Codex workspace sandbox allows network access. |
| <a id="cfg010"></a>`CFG010` | medium | Codex writable roots include broad filesystem path. |
| <a id="cfg011"></a>`CFG011` | high | Codex permission profile grants full access. |
| <a id="cfg012"></a>`CFG012` | high | Agent configuration stores literal secret-like value. |
| <a id="cfg013"></a>`CFG013` | medium | Agent configuration weakens secret redaction. |
| <a id="cfg014"></a>`CFG014` | medium | Gemini automatic or persistent tool approval is enabled. |

## MCP

| Rule | Default severity | Description |
| --- | --- | --- |
| <a id="mcp000"></a>`MCP000` | low | MCP-like config is invalid JSON. |
| <a id="mcp001"></a>`MCP001` | high | MCP server starts through a shell wrapper. |
| <a id="mcp002"></a>`MCP002` | high | MCP server uses download-and-execute bootstrap. |
| <a id="mcp003"></a>`MCP003` | medium | MCP server uses inline interpreter execution. |
| <a id="mcp004"></a>`MCP004` | medium | MCP server requests broad runtime access. |
| <a id="mcp005"></a>`MCP005` | high | MCP server executable is loaded from a temporary path. |
| <a id="mcp006"></a>`MCP006` | low | MCP server has overly broad working directory. |
| <a id="mcp007"></a>`MCP007` | high | MCP config contains an inline secret-like value. |
| <a id="mcp008"></a>`MCP008` | medium | MCP server uses an unpinned `npx` package. |

## Package Scripts

| Rule | Default severity | Description |
| --- | --- | --- |
| <a id="pkg001"></a>`PKG001` | high | Install lifecycle script runs dangerous shell behavior. |
| <a id="pkg002"></a>`PKG002` | medium | npm script contains dangerous shell behavior. |
| <a id="pkg003"></a>`PKG003` | medium | npm script may expose secret environment values. |
| <a id="pkg004"></a>`PKG004` | low | Dependency is installed from a remote URL. |
