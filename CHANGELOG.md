# Changelog

## 0.5.0

- Added agent client config rules for Claude Code settings, Codex config, and
  Gemini CLI settings.
- Added detection for broad tool permissions, dangerous allowed shell commands,
  risky hooks, disabled sandboxing, disabled approvals, network-enabled Codex
  sandboxes, broad writable roots, full-access Codex permission profiles,
  literal secret-like config values, secret-redaction bypasses, and Gemini
  automatic or persistent approvals.
- Added tests for risky and safe agent config examples.

## 0.4.0

- Added `init-ci` to generate a ready-to-use GitHub Actions workflow.
- Added workflow generation modes for PR-only, full scan, or both.
- Added tests for generated workflow output and overwrite behavior.

## 0.3.0

- Added pull-request friendly changed-file scanning with `--changed`.
- Added git-based diff scanning with `--changed-from`, `--changed-to`, and
  `--diff-filter`.
- Added composite Action inputs for changed-file scans.
- Added research notes and project brief docs.

## 0.2.0

- Added centralized rule metadata registry.
- Added `agentic-risk-scan rules --format json|markdown`.
- Added GitHub workflow annotation output with `--format github`.
- Added inline ignore comments for reviewed exceptions.
- Added config-level severity overrides.
- Added SARIF rule help links.

## 0.1.0

- Initial dependency-free Python CLI.
- GitHub Actions agent-risk rules.
- Agent instruction file rules.
- MCP configuration rules.
- npm package script rules.
- Text, JSON, Markdown, and SARIF output.
- Baseline creation and filtering.
