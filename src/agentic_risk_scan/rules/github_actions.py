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
)

DANGEROUS_SHELL_PATTERNS = (
    re.compile(r"\b(eval|exec)\b", re.IGNORECASE),
    re.compile(r"\b(curl|wget)\b.+\|\s*(sh|bash|zsh)\b", re.IGNORECASE),
    re.compile(r"\b(base64|openssl)\b.+\|\s*(sh|bash|zsh|python|node)\b", re.IGNORECASE),
    re.compile(r"\b(bash|sh|zsh)\s+-c\s+\$\{\{", re.IGNORECASE),
    re.compile(r"\b(python|node|ruby|perl)\s+-e\s+", re.IGNORECASE),
)


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
        events = detect_events(text)
        has_untrusted_trigger = bool(events & UNTRUSTED_EVENTS)
        has_high_risk_trigger = bool(events & HIGHER_RISK_EVENTS)
        ai_lines = find_ai_lines(text)
        permissions = detect_write_permissions(text)
        run_blocks = list(iter_run_blocks(text))

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
                if any(pattern.search(block.body) for pattern in DANGEROUS_SHELL_PATTERNS):
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


def detect_events(text: str) -> set[str]:
    events: set[str] = set()
    lines = text.splitlines()
    for line in lines:
        stripped = strip_comment(line).strip().strip("'\"")
        inline = re.search(r"\bon:\s*\[(?P<events>[^\]]+)\]", stripped)
        if inline:
            for item in re.split(r"[, ]+", inline.group("events")):
                event = item.strip("'\" ")
                if event in UNTRUSTED_EVENTS:
                    events.add(event)
        match = re.match(r"^(?:-\s*)?(?P<event>[a-z_]+)\s*:", stripped)
        if match and match.group("event") in UNTRUSTED_EVENTS:
            events.add(match.group("event"))
        if stripped.startswith("on:"):
            for event in UNTRUSTED_EVENTS:
                if re.search(rf"\b{re.escape(event)}\b", stripped):
                    events.add(event)
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
        lowered = line.lower()
        if any(keyword in lowered for keyword in AI_KEYWORDS):
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
