# Rule Reference

Agentic Risk Scan uses lightweight static rules. The goal is to catch dangerous
repository patterns early, not to prove exploitability.

## GitHub Actions

| Rule | Default severity | Description |
| --- | --- | --- |
| `GHA001` | critical | `pull_request_target` checks out untrusted PR head code. |
| `GHA002` | high | AI or agent workflow has write-capable token on an untrusted trigger. |
| `GHA003` | high | Untrusted GitHub event text is interpolated into shell. |
| `GHA004` | medium | Dangerous shell pattern appears in a workflow with untrusted triggers. |
| `GHA005` | medium/high | Secrets are referenced from an untrusted-trigger workflow. |
| `GHA006` | high | Untrusted events can reach a self-hosted runner. |
| `GHA007` | high | OIDC token minting is enabled on an untrusted-trigger workflow. |

## Agent Instructions

| Rule | Default severity | Description |
| --- | --- | --- |
| `AGENT001` | high | Bidirectional Unicode control character in agent instructions. |
| `AGENT002` | medium | Zero-width Unicode character in agent instructions. |
| `AGENT003` | high | Prompt-injection phrase in committed agent instructions. |
| `AGENT004` | high | Dangerous command embedded in agent instructions. |
| `AGENT005` | medium | Agent instruction file requests broad tool access. |

## MCP

| Rule | Default severity | Description |
| --- | --- | --- |
| `MCP000` | low | MCP-like config is invalid JSON. |
| `MCP001` | high | MCP server starts through a shell wrapper. |
| `MCP002` | high | MCP server uses download-and-execute bootstrap. |
| `MCP003` | medium | MCP server uses inline interpreter execution. |
| `MCP004` | medium | MCP server requests broad runtime access. |
| `MCP005` | high | MCP server executable is loaded from a temporary path. |
| `MCP006` | low | MCP server has overly broad working directory. |
| `MCP007` | high | MCP config contains an inline secret-like value. |
| `MCP008` | medium | MCP server uses an unpinned `npx` package. |

## Package Scripts

| Rule | Default severity | Description |
| --- | --- | --- |
| `PKG001` | high | Install lifecycle script runs dangerous shell behavior. |
| `PKG002` | medium | npm script contains dangerous shell behavior. |
| `PKG003` | medium | npm script may expose secret environment values. |
| `PKG004` | low | Dependency is installed from a remote URL. |

