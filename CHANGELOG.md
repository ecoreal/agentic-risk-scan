# Changelog

## Unreleased

- Scoped `GHA004`'s dangerous-shell arms: `--exec` flags and package-runner
  subcommands (`pnpm exec turbo build`) no longer count as shell `exec`
  builtins, and inline interpreter scripts (`node -e ...`) only flag when
  the script consumes an attacker-influencable input sink
  (argv/stdin/env/child_process/...). A fixed
  `node -e "JSON.parse(readFileSync('manifest.json'))"` validation step is
  common CI and no longer a finding. Measured on next.js (3 GHA004 -> 1),
  ai-toolbox (1 -> 0), each case pinned by tests.
- Two agent-instruction precision fixes, both found by cross-scanning the
  author's own workspace: `AGENT005` treated the opening `**` of markdown
  bold (`Recommended tools: **Figma**`) as a `*` tool grant, and `AGENT003`
  flagged benign prose where `leak` met the bare word `prompt` (`prompts
  leak into training`). Wildcards now require a value boundary
  (end/whitespace/comment) and not a preceding `*`; the leak pattern
  requires a secret-like object, with `system prompt` / `hidden
  instructions` covering the real payload cases. Each direction pinned by
  tests; rigor's tree goes from 2 findings to 0.
- `PKG002` no longer flags `eval`/`exec` when they appear inside script file
  names: the `\b` boundary treated the hyphen in `skill-eval.mjs` as a word
  boundary (found scanning `modelcontextprotocol/inspector`'s package.json,
  2 false positives). Standalone `eval`/`exec` commands still flag.
- Extended `docs/evaluation.md` with two larger trees (`vercel/next.js`,
  768 files, ~1s scan; `getsentry/sentry-javascript`, 386 files) and the
  precision notes those runs produced.
- `AGENT003` now reports a quoted phrase inside explanatory prose at `info`
  instead of `high`: security guidance that says `do not follow "ignore
  previous instructions"` and detector reference tables that cite attack
  strings are mentions, not payloads. Raw unquoted payload lines and
  phrase-only quoted lines stay `high`. Measured on getsentry/sentry-
  javascript's `.agents/skills` tree: 8 high downgraded to info, 0 raw
  payloads downgraded (each case pinned by a test).
- Corrected the `CFG006` message: `security.toolSandboxing` defaults to
  `false` in Gemini CLI upstream, so an explicit `false` is a documented
  decision, not a hidden weakening. The finding now says that and points to
  enabling it as the hardening action (verified against gemini-cli's
  `docs/cli/sandbox.md` settings reference).
- Added `docs/evaluation.md`: measured scan results for five real, maintainer-
  run repositories (official MCP servers, claude-code-action, GitHub's MCP
  server, LangChain MCP adapters, OpenAI agents SDK), with the review context
  for each non-low finding. The corpus also documents the trigger-detection
  false-positive class it caught before release.
- Fixed trigger detection fabricating untrusted events: any bare `name:`-like
  line (`issues: write` under `permissions:`, a `jobs:` key) previously counted
  as a trigger, so schedule-only workflows picked up `issues`/`pull_request`
  and then tripped GHA002/GHA005/GHA009. Triggers are now read structurally
  from the `on:` block only (mapping, inline list, and scalar forms).
  Measured on modelcontextprotocol/servers + anthropics/claude-code-action
  (25 workflows): 3 files had spurious untrusted triggers before, 0 after,
  with no missed real triggers. Regression tests pin both directions.
- Added `GHA009`: verification, scan, lint, or install steps in an
  untrusted-trigger workflow that set `continue-on-error: true` are flagged
  (medium). A failing security scan or missing hardening step is silently
  skipped, so later steps act on an unverified environment — the fail-open
  pattern behind several "scanner silently did nothing" incidents.
- Added `CFG015`: Claude Code settings that set `permissions.defaultMode` to
  `bypassPermissions` (high) or `acceptEdits` (medium) are flagged. A
  committed settings file flipping the default mode disables the interactive
  permission prompts for every contributor checking out the repository.
- Added an HTML-report escaping regression test: scanned paths (attacker-
  influencable via directory/file names in a PR) are HTML-escaped before
  they reach the report markup, and the test pins that behavior.
- `GHA003` now treats `github.event.workflow_run.head_branch` and
  `github.event.workflow_run.head_commit.message` as untrusted shell input.
  For `workflow_run` chains the upstream run can originate from a fork, and
  the consuming workflow usually holds write permissions, so interpolating
  those fields into `run:` blocks is shell injection.
- Added registry/doc sync tests: every rule in the shipped registry must be
  documented in `docs/rules.md` (and vice versa) with a matching anchor id, so
  the README-linked rule reference and per-finding help URIs cannot drift.
- Agent-skill instruction files are now scanned: `AGENT001`-`AGENT005` apply
  to `.claude/skills/**/SKILL.md` and `skills/**/SKILL.md` in addition to the
  existing instruction basenames and markers. Skills are a common distribution
  vector for hidden-Unicode, injection phrasing, and download-and-execute
  instructions (compare `mcp-scan`, which scans MCP servers and skills).
- `AGENT003` now matches real-world override phrasing that inserts an article,
  e.g. "ignore the previous instructions" (previously only the article-less
  "ignore previous instructions" matched), and the adjective list gained
  `prior`/`preceding`. Regression tests cover the article variants for both
  `ignore` and `disregard`.
- Fixed `--changed-from`/`--changed` scanning the entire repository when git
  reported no changed files: an empty changed-file set was treated the same as
  "no filter configured", so a PR with only unrelated changes (or only
  deletions) scanned everything. `ScanConfig.changed_paths` now uses `None` for
  "no path filter" and `()` for "nothing changed", with regression tests for the
  empty-diff and deletions-only cases.
- Added `MCP010`, `MCP011`, and `MCP012` for remote (HTTP/SSE) MCP servers:
  plaintext `http://` transport, link-local/cloud-metadata targets (SSRF against
  the instance metadata service), and committed secret headers such as a literal
  `Authorization: Bearer ...` value.
- Added `MCP009` to flag MCP servers that set code-injecting environment
  variables (`NODE_OPTIONS`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`,
  `PYTHONSTARTUP`, `BASH_ENV`, `GIT_SSH_COMMAND`, and path-hijacking variables
  such as `PYTHONPATH`/`NODE_PATH`), which let a committed config run attacker
  code before the server binary starts.
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
- Added direct tests for 13 previously-untested rules (GHA004-GHA007, MCP000,
  MCP003-MCP006, MCP008, PKG002, CFG000, AGENT002), bringing every rule under
  direct test coverage. Test count rose from 34 to 47.
- Added regression tests that pin the shipped `examples/` fixtures: both safe
  examples must stay at 0 findings, and the unsafe example must keep the exact
  severity counts quoted in the README, guarding against false-positive drift
  and README/scanner divergence. Test count rose from 47 to 51.

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
