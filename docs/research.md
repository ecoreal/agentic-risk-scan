# Research Notes

Agentic Risk Scan is built around a narrow thesis: AI agents are becoming part
of the software supply chain, but many repositories still expose those agents to
untrusted GitHub events, broad workflow tokens, committed instruction files, MCP
servers, and package scripts without a dedicated review gate.

## Signals

### AI coding is no longer a side channel

GitHub's 2025 Octoverse report describes AI as a major force in developer
workflows and highlights broad adoption of AI coding activity across public and
private development. That matters because agent-reviewed PRs, issue-triggered
automation, generated patches, and autonomous workflow steps all increase the
amount of repository automation that consumes untrusted text.

Source: [GitHub Octoverse 2025](https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/)

### GitHub Actions already treats contexts as an untrusted boundary

GitHub's own Actions security guidance warns that several contexts and events
must be treated as untrusted input. That maps directly to AI agent workflows:
agents commonly read PR bodies, issue comments, branch names, workflow inputs,
and generated artifacts, then use privileged tokens to comment, label, push, or
open follow-up PRs.

Sources:

- [GitHub Actions secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Secure use of `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)

### MCP moves local tool execution into config

The Model Context Protocol security guidance emphasizes user consent, tool
permissions, and safe handling of data exposed through tools. Repository-scoped
MCP configuration creates a review problem: a small JSON change can alter what
an agent starts, what paths it can reach, and whether it downloads code at
runtime.

Source: [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

### Agent client settings have become security policy

Claude Code, Codex, and Gemini CLI all support committed or project-scoped
settings that influence tool permissions, sandboxing, approvals, hooks, and
environment handling. That makes configuration review part of agent security:
a small settings change can widen shell access, persist approvals, disable
redaction, or keep secret-like environment variables visible to tool execution.

Sources:

- [Claude Code settings](https://docs.anthropic.com/en/docs/claude-code/settings)
- [Codex config reference](https://developers.openai.com/codex/config-reference)
- [Gemini CLI configuration](https://geminicli.com/docs/reference/configuration/)

### Prompt injection is now a first-class application risk

OWASP's LLM security work treats prompt injection and agent/tool behavior as
core risks. For repositories, the practical version is not only a chat prompt:
it is `AGENTS.md`, `.cursor/rules`, `.github/copilot-instructions.md`, issue
comments, PR titles, workflow inputs, and MCP tool descriptions.

Source: [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## Gap In Existing Tools

| Tool class | Strong at | Gap this project targets |
| --- | --- | --- |
| GitHub Actions linters | Workflow syntax and known Actions anti-patterns | Agent-specific trust boundaries, instruction files, and MCP configs. |
| Secret scanners | Finding leaked tokens | Explaining why a workflow exposes secrets to untrusted agent-controlled input. |
| Repo posture scanners | Broad supply-chain hygiene | High-signal checks for AI agent workflow adoption. |
| Runtime hardening | Observing or constraining live workflow execution | Pre-review static checks before a risky workflow merges. |

Agentic Risk Scan intentionally stays small: dependency-free Python, readable
rules, SARIF/GitHub annotations, and PR-only scanning. It is meant to be adopted
before a team has a mature AI security program.

## Product Requirements From The Research

- **Zero-friction install:** no runtime dependency chain for the scanner itself.
- **PR-native signal:** full scans for audits, changed-file scans for pull
  requests.
- **Security-review language:** every finding must explain the untrusted input,
  the privilege boundary, and the remediation.
- **Governance support:** baselines, suppressions, inline ignores, severity
  overrides, machine-readable rule metadata.
- **Platform outputs:** text for humans, JSON for automation, Markdown for
  reports, SARIF for code scanning, GitHub annotations for PR checks.
- **Ecosystem coverage:** GitHub Actions, agent instruction files, MCP config,
  committed agent client settings, and package lifecycle scripts.

## Why This Can Earn Stars

Developers star projects that are timely, useful in one command, and easy to
explain. This project has a concise pitch:

> Scan the files AI agents trust before those agents get write tokens, secrets,
> tools, or a runner.

The strongest adoption path is not a broad security platform. It is a small
tool that AI-heavy repos can paste into CI and immediately see whether an agent
workflow has crossed a trust boundary.
