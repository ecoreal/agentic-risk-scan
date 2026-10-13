from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .common import first_line_matching, make_finding
from ..models import Finding


UNTRUSTED_EVENTS = {
    "pull_request_target",
    "pull_request",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "workflow_run",
}

HIGHER_RISK_EVENTS = {
    "pull_request_target",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "workflow_run",
}

AI_KEYWORDS = (
    "agent",
    "ai",
    "llm",
    "mcp",
    "openai",
    "anthropic",
    "claude",
    "codex",
    "copilot",
    "gemini",
    "aider",
    "cursor",
    "devin",
    "sweep",
    "qodo",
    "goose",
)
AI_KEYWORD_PATTERNS = tuple(
    re.compile(rf"\b{re.escape(keyword)}\b", re.IGNORECASE)
    for keyword in AI_KEYWORDS
)

WRITE_SCOPES = (
    "actions",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
)

UNTRUSTED_EXPRESSIONS = (
    "github.event.comment.body",
    "github.event.issue.body",
    "github.event.issue.title",
    "github.event.pull_request.body",
    "github.event.pull_request.title",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.repo",
    "github.event.discussion.body",
    "github.event.discussion.title",
    "github.event.inputs",
    "github.head_ref",
    # workflow_run chains: the completed run's metadata (branch/tag name and
    # commit message) is attacker-controlled when the trigger run came from a
    # fork, and `workflow_run` workflows usually hold write permissions.
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
)

ACTION_USE_RE = re.compile(
    r"^\s*(?:-\s*)?uses:\s*(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(?P<ref>[^\s#]+)"
)
FULL_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


DANGEROUS_SHELL_PATTERNS = (
    # Shell eval/exec builtins only: "--exec" flags, "pnpm exec <bin>", and
    # hyphenated names are not shell evaluation (same boundary class as the
    # PKG002 fix; found scanning next.js and ai-toolbox CI).
    re.compile(
        r"(?<![\w-])(?<!pnpm )(?<!npm )(?<!yarn )(?<!bun )(?<!npx )(eval|exec)(?![\w-])",
        re.IGNORECASE,
    ),
    re.compile(r"\b(curl|wget)\b.+\|\s*(sh|bash|zsh)\b", re.IGNORECASE),
    re.compile(r"\b(base64|openssl)\b.+\|\s*(sh|bash|zsh|python|node)\b", re.IGNORECASE),
    re.compile(r"\b(bash|sh|zsh)\s+-c\s+\$\{\{", re.IGNORECASE),
)


# Inline interpreter scripts (`node -e ...`) only belong to this rule when the
# script consumes a data source an attacker can influence; a fixed
# `JSON.parse(readFileSync("manifest.json"))`-style validation step is common
# CI and not a dangerous shell pattern (found scanning ai-toolbox).
INLINE_INTERPRETER_RE = re.compile(r"\b(python3?|node|ruby|perl)\s+-e\s+", re.IGNORECASE)
INLINE_INPUT_SINK_RE = re.compile(
    r"(argv|/dev/stdin|stdin|readline|process\.env|os\.environ|child_process"
    r"|subprocess|fetch\(|requests\.|\$\{?)",
    re.IGNORECASE,
)


def has_dangerous_shell_pattern(body: str) -> bool:
    if any(pattern.search(body) for pattern in DANGEROUS_SHELL_PATTERNS):
        return True
    return bool(INLINE_INTERPRETER_RE.search(body)) and bool(INLINE_INPUT_SINK_RE.search(body))



@dataclass(frozen=True)
class RunBlock:
    line: int
    body: str


class GitHubActionsRule:
    rule_group = "github-actions"

    def interested(self, rel_path: Path) -> bool:
        path = rel_path.as_posix().lower()
        return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))

    def scan(self, rel_path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, action, ref in unpinned_action_refs(text):
            findings.append(
                make_finding(
                    rule_id="GHA008",
                    title="GitHub Action is referenced by a mutable ref",
                    severity="low",
                    path=rel_path,
                    line=line_number,
                    message=(
                        f"{action} uses {ref!r} instead of an immutable commit SHA. "
                        "A moving tag or branch can change the code executed by CI."
                    ),
                    evidence=f"uses: {action}@{ref}",
                    remediation=(
                        "Pin third-party Actions to a full 40-character commit SHA and keep the "
                        "release tag in a trailing comment for update review."
                    ),
                    tags=("github-actions", "supply-chain", "pinning"),
                )
            )
        events = detect_events(text)
        has_untrusted_trigger = bool(events & UNTRUSTED_EVENTS)
        has_high_risk_trigger = bool(events & HIGHER_RISK_EVENTS)
        ai_lines = find_ai_lines(text)
        permissions = detect_write_permissions(text)
        run_blocks = list(iter_run_blocks(text))

        interrupted_checks = interrupted_check_steps(text)
        if interrupted_checks and has_untrusted_trigger:
            line_number, line_text = interrupted_checks[0]
            findings.append(
                make_finding(
                    rule_id="GHA009",
                    title="Set-up step can be silently skipped by continuing past failures",
                    severity="medium",
                    path=rel_path,
                    line=line_number,
                    message=(
                        "A verification, lint, scan, or install step uses "
                        "`continue-on-error: true`, so a failing set-up step does not "
                        "stop the workflow. In an untrusted-trigger workflow, skipped "
                        "hardening lets later steps act with an unverified environment."
                    ),
                    evidence=line_text,
                    remediation=(
                        "Remove `continue-on-error` from verification and set-up steps "
                        "so failures stop the job, or split optional steps into a "
                        "separate non-blocking job with read-only permissions."
                    ),
                    tags=("github-actions", "fail-open", "verification"),
                )
            )

        if "pull_request_target" in events and checkout_untrusted_head(text):
            line_match = first_line_matching(
                text,
                re.compile(r"uses:\s*actions/checkout|ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.", re.I),
            )
            findings.append(
                make_finding(
                    rule_id="GHA001",
                    title="pull_request_target checks out untrusted PR code",
                    severity="critical",
                    path=rel_path,
                    line=line_match[0] if line_match else None,
                    message=(
                        "This workflow runs with target-repository privileges and checks out "
                        "code from the pull request head."
                    ),
                    evidence=line_match[1] if line_match else "pull_request_target with PR head checkout",
                    remediation=(
                        "Use pull_request with read-only permissions, or split analysis and write-back "
                        "into separate workflows connected by reviewed artifacts."
                    ),
                    tags=("github-actions", "untrusted-code", "write-token"),
                )
            )

        if has_high_risk_trigger and permissions and ai_lines:
            first_perm = permissions[0]
            findings.append(
                make_finding(
                    rule_id="GHA002",
                    title="AI agent workflow has write-capable token on untrusted trigger",
                    severity="high",
                    path=rel_path,
                    line=first_perm[0],
                    message=(
                        "An AI or agent-like workflow can be triggered by untrusted GitHub content "
                        "while the workflow token has write privileges."
                    ),
                    evidence=first_perm[1],
                    remediation=(
                        "Default permissions to read-all, gate write-back behind labels or maintainers, "
                        "and avoid giving agent jobs repository mutation scopes."
                    ),
                    tags=("github-actions", "agent", "permissions"),
                )
            )

        if has_untrusted_trigger:
            for block in run_blocks:
                if contains_untrusted_expression(block.body):
                    findings.append(
                        make_finding(
                            rule_id="GHA003",
                            title="Untrusted GitHub event data is interpolated into shell",
                            severity="high",
                            path=rel_path,
                            line=block.line,
                            message=(
                                "PR, issue, comment, discussion, or workflow input text is used inside "
                                "a shell command. Attackers can inject shell syntax through GitHub content."
                            ),
                            evidence=block.body,
                            remediation=(
                                "Pass event payload through files or environment variables, quote safely, "
                                "or process it in a language runtime without shell interpolation."
                            ),
                            tags=("github-actions", "shell-injection"),
                        )
                    )
                    break

        if has_untrusted_trigger:
            for block in run_blocks:
                if has_dangerous_shell_pattern(block.body):
                    findings.append(
                        make_finding(
                            rule_id="GHA004",
                            title="Dangerous shell pattern in untrusted workflow",
                            severity="medium",
                            path=rel_path,
                            line=block.line,
                            message=(
                                "This workflow combines an untrusted trigger with shell constructs that "
                                "are commonly abused for command execution or bootstrap downloads."
                            ),
                            evidence=block.body,
                            remediation=(
                                "Pin reviewed actions or scripts, avoid curl-to-shell and eval, and keep "
                                "untrusted payloads out of shell code."
                            ),
                            tags=("github-actions", "shell"),
                        )
                    )
                    break

        if has_high_risk_trigger and uses_secrets(text):
            line_match = first_line_matching(text, re.compile(r"\$\{\{\s*secrets\.", re.I))
            severity = "high" if ai_lines or permissions else "medium"
            findings.append(
                make_finding(
                    rule_id="GHA005",
                    title="Secrets are available in workflow with untrusted trigger",
                    severity=severity,
                    path=rel_path,
                    line=line_match[0] if line_match else None,
                    message=(
                        "The workflow references repository or environment secrets while accepting "
                        "untrusted GitHub events."
                    ),
                    evidence=line_match[1] if line_match else "${{ secrets.* }}",
                    remediation=(
                        "Move secret use to a trusted follow-up workflow or require maintainer approval "
                        "before exposing secrets to agent-controlled steps."
                    ),
                    tags=("github-actions", "secrets"),
                )
            )

        if has_untrusted_trigger and self_hosted_runner(text):
            line_match = first_line_matching(text, re.compile(r"runs-on:.*self-hosted", re.I))
            findings.append(
                make_finding(
                    rule_id="GHA006",
                    title="Untrusted trigger can reach a self-hosted runner",
                    severity="high",
                    path=rel_path,
                    line=line_match[0] if line_match else None,
                    message=(
                        "Self-hosted runners often have network and filesystem access beyond GitHub's "
                        "hosted isolation model."
                    ),
                    evidence=line_match[1] if line_match else "runs-on: self-hosted",
                    remediation=(
                        "Keep untrusted PR, issue, and comment workflows on isolated hosted runners or "
                        "ephemeral locked-down self-hosted runners."
                    ),
                    tags=("github-actions", "runner"),
                )
            )

        if has_high_risk_trigger and id_token_write(permissions):
            line_match = first_line_matching(text, re.compile(r"id-token:\s*write", re.I))
            findings.append(
                make_finding(
                    rule_id="GHA007",
                    title="OIDC token can be minted from untrusted workflow",
                    severity="high",
                    path=rel_path,
                    line=line_match[0] if line_match else None,
                    message=(
                        "id-token: write allows the workflow to request cloud federation tokens. "
                        "With untrusted triggers, this can cross the boundary from repo to cloud."
                    ),
                    evidence=line_match[1] if line_match else "id-token: write",
                    remediation=(
                        "Only grant id-token: write in trusted deployment workflows with strict "
                        "environment protections and claim conditions."
                    ),
                    tags=("github-actions", "oidc", "cloud"),
                )
            )

        return dedupe(findings)


# Word-boundary patterns, not substrings: "latest" contains "test" and
# "checkout" contains "check". "setup" is intentionally absent because the
# ubiquitous actions/setup-* steps are not the hazard this rule targets.
FAIL_OPEN_STEP_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\baudit\b",
        r"\bcheck(?:s|er|er-)?\b",
        r"\bexit[ -]code\b",
        r"\bfail(?:s|ed|ure|ing)?\b",
        r"\bgate\b",
        r"\binstall(?:s|ed|ing|ation)?\b",
        r"\blint(?:s|er|ing)?\b",
        r"\bscan(?:s|ner|ning)?\b",
        r"\btest(?:s|ed|ing)?\b",
        r"\bvalidat(?:e|es|ed|ing|ion|or)\b",
        r"\bverif(?:y|ies|ied|ication)\b",
    )
)


def interrupted_check_steps(text: str) -> list[tuple[int, str]]:
    """Steps that continue on error while looking like checks or set-up.

    The rest of the scanner treats a job's exit code as the success signal;
    a verification, scan, or install step marked ``continue-on-error: true``
    silently removes that signal, letting later steps run against an
    unverified environment. Each step block is examined as a whole so a
    ``name:`` or ``run:`` line near ``continue-on-error`` still matches.
    """
    matches: list[tuple[int, str]] = []
    block: list[tuple[int, str]] = []

    def flush() -> None:
        if not block:
            return
        block_text = "\n".join(line for _, line in block).lower()
        continue_line = next(
            (entry for entry in block if "continue-on-error:" in entry[1].lower()),
            None,
        )
        if continue_line and re.search(r"continue-on-error:\s*(true|'true'|\"true\")", block_text):
            if any(pattern.search(block_text) for pattern in FAIL_OPEN_STEP_PATTERNS):
                matches.append(continue_line)

    for line_number, line in enumerate(text.splitlines(), start=1):
        if re.match(r"^\s*-\s", line) and block and leading_spaces(line) <= leading_spaces(block[0][1]):
            flush()
            block = []
        block.append((line_number, line))
    flush()
    return matches


def unpinned_action_refs(text: str) -> list[tuple[int, str, str]]:
    refs: list[tuple[int, str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = ACTION_USE_RE.match(strip_comment(line))
        if not match:
            continue
        ref = match.group("ref")
        if not FULL_COMMIT_SHA_RE.fullmatch(ref):
            refs.append((line_number, match.group("action"), ref))
    return refs


def detect_events(text: str) -> set[str]:
    """Trigger events, read structurally from the `on:` block only.

    A bare ``name:``/``issues:`` line anywhere in the file is not a trigger:
    ``permissions: {issues: write}`` and job keys like ``jobs:`` are common
    and previously matched the line pattern, fabricating untrusted triggers
    for workflows that run on ``schedule`` alone (verified against
    modelcontextprotocol/servers and anthropics/claude-code-action).
    """
    events: set[str] = set()
    for event in _on_block_events(text):
        if event in UNTRUSTED_EVENTS:
            events.add(event)
    return events


def _on_block_events(text: str) -> list[str]:
    lines = text.splitlines()
    header = next(
        (index for index, line in enumerate(lines) if re.match(r"^(['\"]?on['\"]?)\s*:", line)),
        None,
    )
    if header is None:
        return []
    on_line = lines[header]
    after_colon = on_line.split(":", 1)[1].strip()
    inline = re.fullmatch(r"\[(?P<events>[^\]]*)\]", after_colon)
    if inline:
        return [item.strip("'\" ") for item in inline.group("events").split(",") if item.strip()]
    if after_colon and not after_colon.startswith("#"):
        # `on: push` / `on: pull_request` scalar shorthand.
        return [after_colon.strip("'\" ")]
    base_indent = len(on_line) - len(on_line.lstrip())
    events: list[str] = []
    for line in lines[header + 1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent:
            break
        match = re.match(r"^\s*-?\s*(?P<event>[A-Za-z_][A-Za-z0-9_-]*)\s*:", line)
        if match:
            events.append(match.group("event"))
    return events


def detect_write_permissions(text: str) -> list[tuple[int, str]]:
    matches: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = strip_comment(line)
        if re.search(r"\bpermissions:\s*write-all\b", stripped, re.I):
            matches.append((line_number, line.strip()))
        for scope in WRITE_SCOPES:
            if re.search(rf"\b{re.escape(scope)}:\s*write\b", stripped, re.I):
                matches.append((line_number, line.strip()))
    return matches


def find_ai_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if any(pattern.search(line) for pattern in AI_KEYWORD_PATTERNS):
            lines.append((line_number, line.strip()))
    return lines


def checkout_untrusted_head(text: str) -> bool:
    lowered = text.lower()
    if "uses: actions/checkout" not in lowered:
        return False
    head_patterns = (
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.repo.full_name",
        "github.head_ref",
    )
    return any(pattern in lowered for pattern in head_patterns)


def contains_untrusted_expression(text: str) -> bool:
    lowered = text.lower()
    return any(expression in lowered for expression in UNTRUSTED_EXPRESSIONS)


def uses_secrets(text: str) -> bool:
    return bool(re.search(r"\$\{\{\s*secrets\.", text, re.I))


def self_hosted_runner(text: str) -> bool:
    return bool(re.search(r"runs-on:\s*(?:\[.*)?self-hosted", text, re.I))


def id_token_write(permissions: list[tuple[int, str]]) -> bool:
    return any("id-token" in line.lower() for _, line in permissions)


def iter_run_blocks(text: str) -> list[RunBlock]:
    blocks: list[RunBlock] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(?P<indent>\s*)(?:-\s*)?run:\s*(?P<body>.*)$", line)
        if not match:
            index += 1
            continue

        start_line = index + 1
        indent = len(match.group("indent"))
        body = match.group("body").strip()
        if body in {"|", ">"} or body.startswith("|") or body.startswith(">"):
            collected: list[str] = []
            index += 1
            while index < len(lines):
                next_line = lines[index]
                if next_line.strip() and leading_spaces(next_line) <= indent:
                    break
                collected.append(next_line.strip())
                index += 1
            blocks.append(RunBlock(line=start_line, body="\n".join(collected)))
            continue

        blocks.append(RunBlock(line=start_line, body=body))
        index += 1
    return blocks


def leading_spaces(value: str) -> int:
    return len(value) - len(value.lstrip(" "))


def strip_comment(line: str) -> str:
    if "#" not in line:
        return line
    prefix, _, _ = line.partition("#")
    return prefix


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.location.path, finding.location.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
