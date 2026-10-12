# CODEX GOAL LOOP — agentic-risk-scan: 0→高 star 采用增长冲刺

You are running in Codex CLI **goal mode**: loop until the goal is met, re-checking
state each iteration. This file is your persistent instruction. Do NOT invent facts;
resolve every claim against the repo files, the live test suite, and `gh` output
before acting.

> 本文件由 Claude 依据 Rigor 的 codex-goal-loop 九段模板生成，基于对项目真实现状的核对。
> 诊断结论：代码成熟（v0.10.0，34 tests 全绿，7 个 CLI 子命令，完整 docs/CI），
> 但**采用增长引擎为零**（0 star / 无 PyPI / 无 release / README 第一眼不抓人）。
> 因此本冲刺重心 = 降低采用门槛 + 提升第一眼说服力，而非再堆功能。

---

## 0. Hard context anchors (do not drift)

- Workspace root: `/home/ec/ec-ws/projects/agentic-risk-scan`
- Runtime/env: `.venv/bin/python`（Python 3.13）；项目标榜 **dependency-free**，测试用标准库 `unittest`，**不得**为主包引入第三方运行时依赖。
- Test command (verified working): `.venv/bin/python -m unittest discover -s tests -v`（当前 34 tests 全绿）
- CLI entry (verified): `PYTHONPATH=src .venv/bin/python -m agentic_risk_scan <scan|rules|inventory|report|doctor|init-config|init-ci>`
- Package: name `agentic-risk-scan`, version `0.10.0`, `pyproject.toml`；`[project.scripts]` 已定义 `agentic-risk-scan` 入口。
- Git identity: repo-local `ecoreal <jh1478036@gmail.com>`。不碰 global config。
- Remote: `origin https://github.com/ecoreal/agentic-risk-scan.git`（公开开源仓库）。
- Baseline (2026-07-06, via gh): ⭐ 0 star · 0 fork · 0 open issue · 无 release · 无 tag · 无 PyPI 发布。
- Current-truth layer (READ FIRST every fresh session, in order):
  1. `.rigor/handoff/LOOP.md`（本文件）
  2. `.rigor/handoff/STATUS.md`（若存在，你上一轮的进度）
  3. `README.md`（项目门面 —— 采用增长的头号杠杆）
  4. `CHANGELOG.md` + `pyproject.toml`（当前版本与发布状态）
  5. `git log --oneline -10` + `git status`

## 1. Framing constraints (NON-NEGOTIABLE)

- **代码不是短板，别再堆功能。** 现状诊断是「产品够好但没人能发现/一键用上/第一眼被抓住」。所有动作服务于**采用增长**，不是特性膨胀。
- **dependency-free 是卖点，不能破。** 主包绝不引入第三方运行时依赖。构建/发布工具（build、twine）只能是 dev/CI 依赖，不进 `[project.dependencies]`。
- **不夸大营销。** README 里的能力描述、示例输出、扫描结果必须来自**真实运行**，不得编造 star、下载量、用户证言或未实现的功能。每个示例输出都要能用仓库里的命令复现。
- **绝不直接推 main。** 所有改动走 feature 分支 + PR，保留用户的合并闸门（见 §7）。

## 2. Goal (definition of done)

Deliver 一组**能被外部用户发现、一键安装、第一眼信服**的采用增长改进，in priority order:

- **P0 · 第一眼说服力**：README 顶部加一段**真实的示例扫描输出**（对一个含风险的小样本仓库跑 `scan`，贴真实 findings + risk score），让访客 5 秒内看懂「它能抓到什么」。示例样本 + 复现命令放进 `examples/`。
- **P0 · 一键安装路径**：准备好 PyPI 发布所需的一切（`pyproject` 元数据补全：urls/classifiers/keywords/readme；`python -m build` 能产出干净的 wheel+sdist；`twine check` 通过）。**实际 upload 留给用户做**（需要 PyPI token，见 §7），你只把包做到「可发布」状态并写好发布说明。
- **P1 · Release 就绪**：起草 `v0.10.0`（或合适版本）的 GitHub release notes（从 CHANGELOG 提炼），写好 tag 方案。tag/release 的实际创建可由你用 gh 在**分支合并后**做，或留给用户——按 §7 规则。
- **P1 · 采用门槛文档**：README「Quick Start」补 `pipx install` / `pip install` 路径与 SARIF→GitHub code scanning 的一步步接入示例（真实可跑）。
- **P2 · 差异化说清**：README 加一小节「Why this vs generic SAST」——用真实的 agentic 威胁场景（PR 注入、MCP download-and-exec、隐藏 Unicode 指令）说清它独有的扫描面。

DONE when: 上述 P0 全部完成且有**真实运行证据**；`unittest` 全绿不回归；`python -m build` + `twine check` 通过；所有改动在 **feature 分支**上并**已开 PR**（`gh pr create`）；`.rigor/handoff/STATUS.md` 记录了最终状态、真实证据、以及「留给用户做的事」（PyPI upload / PR 合并）。

## 3. Priority & resource scheduling

Ranked; do the highest available:

1. **建 examples/ 风险样本 + 跑出真实 scan 输出** → 喂给 README P0（这是第一眼说服力的原料）。
2. **补全 pyproject 元数据 + 本地 build + twine check**（一键安装的地基）。
3. **改 README**（示例输出、安装路径、差异化小节）。
4. **起草 release notes + tag 方案**。
5. **开 PR**（gh）。

Explicitly FORBIDDEN unless 用户另行批准:
- **禁止**直接 `git push origin main` 或向 main 直推 commit。
- **禁止**为主包新增第三方运行时依赖（破坏 dependency-free 卖点）。
- **禁止**编造任何数字/证言/未实现功能；README 每条能力都要可复现。
- **禁止**执行 PyPI upload（`twine upload`）——需要用户的 PyPI token，属用户动作。
- **禁止**读取或提交任何密钥文件（token、`.pypirc`、CI secrets）。

## 4. Per-iteration loop procedure

Each iteration:

1. Re-read §0 current-truth layer + `.rigor/handoff/STATUS.md`。Do not trust memory across loops.
2. Check current state:
   - `git status && git branch --show-current`（确认在 feature 分支，不在 main）
   - `.venv/bin/python -m unittest discover -s tests -v 2>&1 | tail -5`（测试基线）
   - `git log --oneline -5`
3. Pick the highest-priority incomplete action (§3)。
4. Before 任何 README 能力声明或示例输出：**先真跑对应命令拿到真实输出**，再写进文档。preflight 失败就不写那条。
5. 长动作（build）：跑完立即 `twine check dist/*` 验证，产物不齐不算数。
6. On completion of a unit：跑 `unittest` 确认无回归；把真实证据（命令 + 输出摘要）记进 STATUS。
7. Update `.rigor/handoff/STATUS.md`：本轮做了什么、真实证据、完成度、下一步、以及「留给用户的事」。
8. If an approach fails twice, STOP patching —— 诊断根因、换路、记录决策。

## 5. Verified commands

```bash
cd /home/ec/ec-ws/projects/agentic-risk-scan

# —— 测试基线（已验证 34 green）——
.venv/bin/python -m unittest discover -s tests -v

# —— CLI 真实运行（已验证）——
PYTHONPATH=src .venv/bin/python -m agentic_risk_scan scan .
PYTHONPATH=src .venv/bin/python -m agentic_risk_scan rules
PYTHONPATH=src .venv/bin/python -m agentic_risk_scan scan <sample> --format sarif

# —— 分支 + 提交（绝不直推 main）——
git checkout -b feat/adoption-growth
git add -A && git status
git commit -m "..."
git push -u origin feat/adoption-growth
gh pr create --title "..." --body "..."   # 开 PR，不合并

# —— 打包就绪（build/twine 仅 dev 工具，不进主包依赖）——
.venv/bin/python -m pip install --quiet build twine   # dev 环境用
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*

# —— 发布状态查询 ——
gh repo view ecoreal/agentic-risk-scan --json stargazerCount,latestRelease
```

对不确定是否存在的命令/子命令，先 `--help` 或读源码确认，不要猜。

## 6. Reality checkpoint

- **star 是滞后指标，不可能在一次 loop 内涨。** 本冲刺的真实产出是「让项目具备被 star 的条件」——可发现、可一键装、第一眼信服。不要把 DONE 绑在 star 数字上（那不受你控制），要绑在**可交付的采用增长改进**上。
- **诚实边界**：你无法验证「这些改动真的带来 star」。STATUS 里如实写「已完成采用增长改进 X/Y/Z，star 影响需时间与用户验证」，不得声称「已提升 star」。
- Hard checkpoint：若 P0 两项完成且 PR 已开，即可收敛——不要为追求「更多」而无限扩张 README 或加边角功能。

## 7. Integrity red lines (enforced)

- 项目方向、定位、要不要合并 PR、要不要发 PyPI —— 都归用户。你加速开发与打包这些机械环节。
- **绝不直推 main**：所有改动 feature 分支 + PR，合并权归用户。
- **PyPI upload 归用户**（需 token）；你只做到「可发布」。
- 不编造 star/下载/证言/功能；README 每条能力可复现。
- 保留 dirty git 状态与日志；非请求不 reset/clean。
- 不读取/提交任何密钥文件（token / `.pypirc` / CI secrets）。
- dependency-free 卖点不可破。

## 8. First iteration should start with

1. 建 feature 分支 `feat/adoption-growth`（确认不在 main 上工作）。
2. 读 `README.md` 全文 + `CHANGELOG.md` + `pyproject.toml`，摸清门面与发布现状。
3. 在 `examples/` 下造一个**含真实可检测风险**的小样本仓库（如带 write 权限 token 的 workflow、download-and-exec 的 MCP config），对它跑 `scan`，**拿到真实 findings 输出**——这是 README P0 的原料。
4. 把计划与首批真实证据写入 `.rigor/handoff/STATUS.md`。

结束本轮前，把本轮动作、真实运行证据、下一步写入 `.rigor/handoff/STATUS.md`。
