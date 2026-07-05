# Threat Model

Agentic Risk Scan focuses on repository-level configuration that changes the
blast radius of AI agents.

## Assets

- GitHub workflow tokens and repository write permissions.
- Repository and environment secrets.
- Cloud credentials reachable through GitHub OIDC.
- Self-hosted runner filesystem and network access.
- Developer workstations that load MCP or agent instruction files.

## Untrusted Inputs

- Pull request titles, bodies, branch names, and fork code.
- Issue, discussion, and comment bodies.
- Workflow dispatch inputs.
- Agent instruction files changed by contributors.
- MCP config changed by contributors.
- Package scripts that run during install, publish, or agent setup.

## Abuse Cases

- A PR modifies code that is checked out by `pull_request_target`.
- A comment injects shell syntax into a workflow step.
- An agent instruction file hides text with Unicode controls.
- An MCP server downloads and executes code at runtime.
- A package `postinstall` script runs when an agent prepares a workspace.

## Out Of Scope

- Runtime monitoring of agent decisions.
- Proving exploitability for every finding.
- Full dependency vulnerability management.
- Secret scanning for arbitrary file contents.

This project intentionally catches high-signal static patterns before they reach
runtime.

