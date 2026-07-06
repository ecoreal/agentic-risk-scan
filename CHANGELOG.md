# Changelog

## Unreleased

- Added a PyPI publish workflow using OIDC Trusted Publishing, triggered on
  published GitHub releases, with separate build and publish jobs and a
  protected `pypi` environment for the `id-token: write` step.
- Added `docs/releasing.md` documenting the one-time PyPI Trusted Publishing
  setup and the tag-and-release flow.
- Expanded the README example with real multi-rule scan output (GitHub Actions
  and MCP findings) and a clean safe-example contrast.
- Added a README "Why This vs a Generic SAST Tool" section mapping the agentic
  attack surface (PR/comment injection, MCP download-and-execute, hidden-Unicode
  instructions, over-privileged agent config) to concrete rule IDs.

## 0.10.0

- Added `agentic-risk-scan doctor` to diagnose scanner adoption and current
  agentic risk posture.
- Doctor output covers project config, GitHub Actions integration, HTML report
  artifacts, baselines, current findings, and attack-surface inventory.
- Added text, JSON, and Markdown doctor output plus tests for adoption checks,
  report artifact detection, findings posture, and output files.
- Added an adoption guide for rolling the scanner into existing repositories.

## 0.9.0

- Added `agentic-risk-scan init-ci --report-artifact` to generate GitHub
  Actions workflows that upload standalone HTML report artifacts.
- Report artifact workflows now produce PR-scoped reports and full-repository
  reports with `if: always()` so reviewers can inspect results even when the
  scan fails the job.
- Added tests for report artifact workflow generation while preserving the
  default SARIF/GitHub annotation workflow output.

## 0.8.0

- Added `agentic-risk-scan report --format html` for a standalone HTML report
  suitable for CI artifacts, security reviews, and demos.
- Added HTML report tests for severity styling, finding content, and inventory
  content.
- Extended the composite GitHub Action with `command: scan|report|inventory`
  so workflows can generate scan results, Markdown/HTML reports, or inventory
  files without custom shell glue.

## 0.7.0

- Added `agentic-risk-scan report` to generate a combined Markdown report with
  scan findings, attack-surface inventory, executive summary, recommended next
  actions, and reproduction commands.
- Added report support for project config, baselines, changed-file scans,
  inline ignores, output files, and fail thresholds.
- Added tests for report content, output file creation, and CI-style failure
  behavior.

## 0.6.0

- Added `agentic-risk-scan inventory` to enumerate repository agentic attack
  surfaces even when there are no findings.
- Added text, JSON, and Markdown inventory output for GitHub Actions workflows,
  agent instruction files, agent client configs, MCP configs, and package
  scripts.
- Improved nested agent config path handling so `.claude/settings.json`,
  `.codex/config.toml`, and `.gemini/settings.json` are treated as structured
  config files even inside fixture or example directories.

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
