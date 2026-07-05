from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    severity: str
    title: str
    category: str
    tags: tuple[str, ...]

    @property
    def help_uri(self) -> str:
        anchor = self.rule_id.lower()
        return f"https://github.com/ecoreal/agentic-risk-scan/blob/main/docs/rules.md#{anchor}"


RULES: tuple[RuleInfo, ...] = (
    RuleInfo("GHA001", "critical", "pull_request_target checks out untrusted PR code", "GitHub Actions", ("github-actions", "untrusted-code", "write-token")),
    RuleInfo("GHA002", "high", "AI agent workflow has write-capable token on untrusted trigger", "GitHub Actions", ("github-actions", "agent", "permissions")),
    RuleInfo("GHA003", "high", "Untrusted GitHub event data is interpolated into shell", "GitHub Actions", ("github-actions", "shell-injection")),
    RuleInfo("GHA004", "medium", "Dangerous shell pattern in untrusted workflow", "GitHub Actions", ("github-actions", "shell")),
    RuleInfo("GHA005", "medium/high", "Secrets are available in workflow with untrusted trigger", "GitHub Actions", ("github-actions", "secrets")),
    RuleInfo("GHA006", "high", "Untrusted trigger can reach a self-hosted runner", "GitHub Actions", ("github-actions", "runner")),
    RuleInfo("GHA007", "high", "OIDC token can be minted from untrusted workflow", "GitHub Actions", ("github-actions", "oidc", "cloud")),
    RuleInfo("AGENT001", "high", "Bidirectional control character in agent instructions", "Agent Instructions", ("agent-instructions", "unicode")),
    RuleInfo("AGENT002", "medium", "Zero-width character in agent instructions", "Agent Instructions", ("agent-instructions", "unicode")),
    RuleInfo("AGENT003", "high", "Prompt-injection phrase in agent instructions", "Agent Instructions", ("agent-instructions", "prompt-injection")),
    RuleInfo("AGENT004", "high", "Dangerous command embedded in agent instructions", "Agent Instructions", ("agent-instructions", "shell")),
    RuleInfo("AGENT005", "medium", "Agent instructions request broad tool access", "Agent Instructions", ("agent-instructions", "permissions")),
    RuleInfo("CFG000", "low", "Agent settings file is invalid JSON", "Agent Config", ("agent-config", "json")),
    RuleInfo("CFG001", "medium/high", "Agent configuration grants broad tool permission", "Agent Config", ("agent-config", "permissions")),
    RuleInfo("CFG002", "high", "Agent configuration allows dangerous shell command", "Agent Config", ("agent-config", "shell")),
    RuleInfo("CFG003", "medium", "Agent configuration grants broad filesystem access", "Agent Config", ("agent-config", "filesystem")),
    RuleInfo("CFG004", "high", "Agent hook runs dangerous shell command", "Agent Config", ("agent-config", "hooks", "shell")),
    RuleInfo("CFG005", "medium", "Agent hook may expose secret environment values", "Agent Config", ("agent-config", "hooks", "secrets")),
    RuleInfo("CFG006", "medium", "Agent tool sandboxing is disabled", "Agent Config", ("agent-config", "sandbox")),
    RuleInfo("CFG007", "high", "Codex sandbox is disabled", "Agent Config", ("agent-config", "codex", "sandbox")),
    RuleInfo("CFG008", "high", "Codex approvals are disabled", "Agent Config", ("agent-config", "codex", "approval")),
    RuleInfo("CFG009", "medium", "Codex workspace sandbox allows network access", "Agent Config", ("agent-config", "codex", "network")),
    RuleInfo("CFG010", "medium", "Codex writable roots include broad filesystem path", "Agent Config", ("agent-config", "codex", "filesystem")),
    RuleInfo("CFG011", "high", "Codex permission profile grants full access", "Agent Config", ("agent-config", "codex", "permissions")),
    RuleInfo("CFG012", "high", "Agent configuration stores literal secret-like value", "Agent Config", ("agent-config", "secrets")),
    RuleInfo("CFG013", "medium", "Agent configuration weakens secret redaction", "Agent Config", ("agent-config", "secrets", "redaction")),
    RuleInfo("CFG014", "medium", "Gemini automatic or persistent tool approval is enabled", "Agent Config", ("agent-config", "gemini", "approval")),
    RuleInfo("MCP000", "low", "MCP config is invalid JSON", "MCP", ("mcp", "json")),
    RuleInfo("MCP001", "high", "MCP server starts through a shell wrapper", "MCP", ("mcp", "shell")),
    RuleInfo("MCP002", "high", "MCP server uses download-and-execute bootstrap", "MCP", ("mcp", "supply-chain")),
    RuleInfo("MCP003", "medium", "MCP server uses inline interpreter execution", "MCP", ("mcp", "inline-code")),
    RuleInfo("MCP004", "medium", "MCP server requests broad runtime access", "MCP", ("mcp", "permissions")),
    RuleInfo("MCP005", "high", "MCP server executable is loaded from a temporary path", "MCP", ("mcp", "path")),
    RuleInfo("MCP006", "low", "MCP server has overly broad working directory", "MCP", ("mcp", "filesystem")),
    RuleInfo("MCP007", "high", "MCP config contains inline secret-like environment value", "MCP", ("mcp", "secrets")),
    RuleInfo("MCP008", "medium", "MCP server uses unpinned npx package", "MCP", ("mcp", "supply-chain")),
    RuleInfo("PKG001", "high", "Install lifecycle script runs dangerous shell behavior", "Package Scripts", ("package", "supply-chain")),
    RuleInfo("PKG002", "medium", "npm script contains dangerous shell behavior", "Package Scripts", ("package", "shell")),
    RuleInfo("PKG003", "medium", "npm script may expose secret environment values", "Package Scripts", ("package", "secrets")),
    RuleInfo("PKG004", "low", "Dependency is installed from a remote URL", "Package Scripts", ("package", "supply-chain")),
)

RULE_BY_ID = {rule.rule_id: rule for rule in RULES}
