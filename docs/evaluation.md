# Evaluation Corpus

What the scanner finds on real, well-maintained repositories — and what that
means for adoption. This is the answer to "does it cry wolf?" before you run
it on your own repo.

## Method

Five public repositories were scanned at the commits below with a fresh
checkout (`git clone --depth 1`), no exclusions and no baseline:

```bash
agentic-risk-scan scan <repo> --format json --fail-on none
```

The repositories are not chosen to be vulnerable. Four of them are
security-conscious projects (GitHub's own MCP server, Anthropic's
claude-code-action, the official MCP servers monorepo, OpenAI's agents SDK).
That makes their findings the interesting ones: either the rule is wrong, or
the pattern is a real trade-off worth seeing before it is copied.

## Results

| Repository | Scanned files | Findings | By rule |
|---|---|---|---|
| `modelcontextprotocol/servers` | 40 | 50 | GHA008×45, GHA001×1, GHA007×1, GHA002×1, GHA005×1, PKG002×1 |
| `anthropics/claude-code-action` | 30 | 23 | GHA008×14, GHA002×3, GHA007×2, GHA005×2, GHA004×1, MCP008×1 |
| `langchain-ai/langchain-mcp-adapters` | 5 | 9 | GHA008×9 |
| `github/github-mcp-server` | 19 | 7 | GHA002×3, GHA005×3, GHA009×1 |
| `openai/openai-agents-python` | 73 | 3 | GHA005×1, GHA002×1, AGENT005×1 |

67% of all findings are `GHA008` (mutable action refs, severity `low`), which
is also why these repos pass their own CI: the default `--fail-on high`
threshold never blocks on unpinned refs. The remaining findings are
concentrated in exactly the workflows that hand write authority to
untrusted input — issue triggers on repos that use AI labelers and
moderators.

## What the findings actually mean

- `GHA002`/`GHA005` on `github/github-mcp-server` flag issue-triggered
  workflows that give an AI step `issues: write` and the workflow token.
  This is the intended trade-off of an issue-triage bot, but it is also the
  exact composition that makes a repo worth targeting: if the AI step can be
  steered by issue text, the token is the blast radius. The finding is a
  "review this" signal, not a claim of exploitability.
- `GHA004` on `anthropics/claude-code-action` (eval/exec usage in a
  maintenance workflow) and the `GHA009` on `github/github-mcp-server`'s
  license check both reflect deliberate design decisions in those repos
  (a script behind the AI reviewer; a check step whose "failure" means
  "changes needed" and is routed via `steps.changes.outcome`). This is why
  `GHA009` only fires on untrusted triggers and carries `medium`.
- `AGENT005` on `openai/openai-agents-python`'s `AGENTS.md` matched a
  security-guidance line describing OIDC credentials. Instruction rules
  are line-matched with broad patterns; one finding from a 700-line
  contributor guide is the expected precision at this rule's severity.
- `MCP008` on `claude-code-action`'s `npx` usage and `PKG002` on
  `mcp-servers`' package script are single signals about unpinned
  package-runner and script shapes.

## Regressions this corpus caught

Running the corpus is not just marketing: it found a real false-positive
class. Trigger detection matched any bare `key:` line against untrusted
event names, so `issues: write` under `permissions:` fabricated an `issues`
trigger for schedule-only workflows — `sdk-watch.yml`,
`dependency-refresh.yml`, and `dependabot-alerts.yml` in
`modelcontextprotocol/servers` were each reported as untrusted-trigger
workflows that no untrusted event can reach. Triggers are now parsed
structurally from the `on:` block; the corpus re-measures at three spurious
triggers before and zero after, with no missed real triggers across the 25
workflow files examined for that fix.

## Reproducing

The scanner is dependency-free, so reproducing takes one command per repo:

```bash
python -m pip install -e .
git clone --depth 1 https://github.com/github/github-mcp-server /tmp/eval-repo
agentic-risk-scan scan /tmp/eval-repo --format markdown
```

When quoting these numbers, pin the clone date: upstream workflow files
change, and findings follow the files. Results above were measured on
2026-10-12, with scanner version after commit `bd608fb`.
