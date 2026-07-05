from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .common import find_key_line, make_finding
from ..models import Finding


CLAUDE_SETTINGS = {
    ".claude/settings.json",
    ".claude/settings.local.json",
}

GEMINI_SETTINGS = {
    ".gemini/settings.json",
}

CODEX_CONFIG = {
    ".codex/config.toml",
}

BROAD_TOOL_GRANTS = {
    "*",
    "bash",
    "bash(*)",
    "read(*)",
    "write(*)",
    "edit(*)",
    "multiedit(*)",
    "webfetch(*)",
    "websearch(*)",
}

DANGEROUS_BASH = (
    re.compile(r"\brm\s+-rf\s+(/|\$HOME|~|\*)", re.I),
    re.compile(r"\b(curl|wget)\b.+\|\s*(sh|bash|zsh|python|node)\b", re.I),
    re.compile(r"\bchmod\s+-R\s+777\b", re.I),
    re.compile(r"\b(sudo|su)\b", re.I),
    re.compile(r"\b(gh|git)\s+.*(push|release|auth|token)\b", re.I),
    re.compile(r"\b(npm|pnpm|yarn)\s+publish\b", re.I),
    re.compile(r"\b(docker|kubectl|aws|gcloud|az)\b", re.I),
)

SECRET_EXPOSURE = re.compile(
    r"\b(printenv|env|set|cat)\b.*\b(token|secret|password|credential|api[_-]?key|GITHUB_TOKEN)\b",
    re.I,
)

SECRET_NAME = re.compile(
    r"(token|secret|password|credential|api[_-]?key|github_token|auth[_-]?token|authorization)",
    re.I,
)


class AgentConfigRule:
    rule_group = "agent-config"

    def interested(self, rel_path: Path) -> bool:
        path = rel_path.as_posix().lower()
        return path in CLAUDE_SETTINGS or path in GEMINI_SETTINGS or path in CODEX_CONFIG

    def scan(self, rel_path: Path, text: str) -> list[Finding]:
        path = rel_path.as_posix().lower()
        if path in CODEX_CONFIG:
            return scan_codex_config(rel_path, text)
        if path in CLAUDE_SETTINGS:
            return scan_json_agent_settings(rel_path, text, ecosystem="Claude Code")
        if path in GEMINI_SETTINGS:
            return scan_json_agent_settings(rel_path, text, ecosystem="Gemini CLI")
        return []


def scan_json_agent_settings(rel_path: Path, text: str, *, ecosystem: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [
            make_finding(
                rule_id="CFG000",
                title="Agent settings file is invalid JSON",
                severity="low",
                path=rel_path,
                line=exc.lineno,
                message=f"{ecosystem} settings could not be parsed as JSON.",
                evidence=exc.msg,
                remediation="Fix JSON syntax so agent clients and scanners read the same configuration.",
                tags=("agent-config", "json"),
            )
        ]

    findings: list[Finding] = []
    findings.extend(scan_literal_secrets(rel_path, text, ecosystem, data))

    permissions = data.get("permissions") if isinstance(data, dict) else None
    if isinstance(permissions, dict):
        allow = permissions.get("allow", [])
        if isinstance(allow, str):
            allow = [allow]
        if isinstance(allow, list):
            findings.extend(scan_allowed_tools(rel_path, text, ecosystem, [str(item) for item in allow]))

    findings.extend(scan_hook_commands(rel_path, text, ecosystem, data))

    if ecosystem == "Gemini CLI":
        findings.extend(scan_gemini_settings(rel_path, text, data))

    return dedupe(findings)


def scan_allowed_tools(
    rel_path: Path,
    text: str,
    ecosystem: str,
    allowed_tools: list[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for tool in allowed_tools:
        normalized = normalize_tool(tool)
        line = find_line_containing(text, tool) or find_key_line(text, "allow")

        if normalized in BROAD_TOOL_GRANTS or normalized.endswith("(*)"):
            severity = "high" if normalized in {"*", "bash(*)", "write(*)", "edit(*)", "multiedit(*)"} else "medium"
            findings.append(
                make_finding(
                    rule_id="CFG001",
                    title="Agent configuration grants broad tool permission",
                    severity=severity,
                    path=rel_path,
                    line=line,
                    message=f"{ecosystem} settings allow a broad tool pattern that can expand agent authority.",
                    evidence=tool,
                    remediation="Replace broad allow rules with exact command or path-scoped permissions.",
                    tags=("agent-config", "permissions"),
                )
            )

        if normalized.startswith("bash("):
            command = extract_tool_argument(tool)
            if any(pattern.search(command) for pattern in DANGEROUS_BASH):
                findings.append(
                    make_finding(
                        rule_id="CFG002",
                        title="Agent configuration allows dangerous shell command",
                        severity="high",
                        path=rel_path,
                        line=line,
                        message=f"{ecosystem} settings allow shell behavior that can mutate repos, publish artifacts, or reach infrastructure.",
                        evidence=tool,
                        remediation="Require explicit approval for dangerous shell commands and remove them from committed allow lists.",
                        tags=("agent-config", "shell"),
                    )
                )

        if normalized.startswith(("read(", "write(", "edit(", "multiedit(")):
            argument = extract_tool_argument(tool)
            if argument in {"*", "/", "~", "$home", "/home", "/users"} or argument.startswith(("/", "~")):
                findings.append(
                    make_finding(
                        rule_id="CFG003",
                        title="Agent configuration grants broad filesystem access",
                        severity="medium",
                        path=rel_path,
                        line=line,
                        message=f"{ecosystem} settings grant filesystem access outside a narrow project path.",
                        evidence=tool,
                        remediation="Scope file permissions to the specific repository paths the agent needs.",
                        tags=("agent-config", "filesystem"),
                    )
                )

    return findings


def scan_hook_commands(rel_path: Path, text: str, ecosystem: str, data: Any) -> list[Finding]:
    findings: list[Finding] = []
    for key_path, value in walk_json(data):
        if key_path[-1:] != ("command",) or not isinstance(value, str):
            continue
        line = find_line_containing(text, value) or find_key_line(text, "command")
        if any(pattern.search(value) for pattern in DANGEROUS_BASH):
            findings.append(
                make_finding(
                    rule_id="CFG004",
                    title="Agent hook runs dangerous shell command",
                    severity="high",
                    path=rel_path,
                    line=line,
                    message=f"{ecosystem} hook configuration runs shell behavior that deserves code review.",
                    evidence=value,
                    remediation="Move hook behavior into reviewed scripts and avoid destructive or publish-capable commands.",
                    tags=("agent-config", "hooks", "shell"),
                )
            )
        if SECRET_EXPOSURE.search(value):
            findings.append(
                make_finding(
                    rule_id="CFG005",
                    title="Agent hook may expose secret environment values",
                    severity="medium",
                    path=rel_path,
                    line=line,
                    message=f"{ecosystem} hook configuration appears to print or transmit secret-like environment values.",
                    evidence=value,
                    remediation="Avoid printing secret-bearing environments from hooks.",
                    tags=("agent-config", "hooks", "secrets"),
                )
            )
    return findings


def scan_gemini_settings(rel_path: Path, text: str, data: Any) -> list[Finding]:
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    security = data.get("security") if isinstance(data.get("security"), dict) else {}
    general = data.get("general") if isinstance(data.get("general"), dict) else {}

    sandbox = get_nested(data, ("security", "toolSandboxing"))
    if sandbox is None:
        sandbox = data.get("toolSandboxing", data.get("sandbox"))
    if sandbox is False or (isinstance(sandbox, dict) and sandbox.get("enabled") is False):
        findings.append(
            make_finding(
                rule_id="CFG006",
                title="Agent tool sandboxing is disabled",
                severity="medium",
                path=rel_path,
                line=find_key_line(text, "toolSandboxing") or find_key_line(text, "sandbox"),
                message="Gemini CLI settings appear to disable tool sandboxing.",
                evidence="toolSandboxing=false",
                remediation="Keep tool sandboxing enabled unless there is a documented compensating control.",
                tags=("agent-config", "sandbox"),
            )
        )

    redaction = security.get("environmentVariableRedaction") if isinstance(security, dict) else None
    if isinstance(redaction, dict):
        if redaction.get("enabled") is False:
            findings.append(
                make_finding(
                    rule_id="CFG013",
                    title="Agent configuration weakens secret redaction",
                    severity="medium",
                    path=rel_path,
                    line=find_key_line(text, "environmentVariableRedaction") or find_key_line(text, "enabled"),
                    message="Gemini CLI settings disable environment variable redaction.",
                    evidence="environmentVariableRedaction.enabled=false",
                    remediation="Keep environment variable redaction enabled for committed agent defaults.",
                    tags=("agent-config", "secrets", "redaction"),
                )
            )
        allowed = redaction.get("allowed")
        if isinstance(allowed, list):
            secret_names = [str(item) for item in allowed if SECRET_NAME.search(str(item))]
            if secret_names:
                findings.append(
                    make_finding(
                        rule_id="CFG013",
                        title="Agent configuration weakens secret redaction",
                        severity="medium",
                        path=rel_path,
                        line=find_key_line(text, "allowed"),
                        message="Gemini CLI settings allow secret-like environment variable names to bypass redaction.",
                        evidence=", ".join(secret_names[:4]),
                        remediation="Do not allow token, secret, password, credential, or API key variables through redaction filters.",
                        tags=("agent-config", "secrets", "redaction"),
                    )
                )

    if security.get("enablePermanentToolApproval") is True or security.get("autoAddToPolicyByDefault") is True:
        findings.append(
            make_finding(
                rule_id="CFG014",
                title="Gemini automatic or persistent tool approval is enabled",
                severity="medium",
                path=rel_path,
                line=find_key_line(text, "enablePermanentToolApproval")
                or find_key_line(text, "autoAddToPolicyByDefault"),
                message="Gemini CLI settings can persist tool approvals without a fresh review prompt.",
                evidence="persistent tool approval enabled",
                remediation="Keep permanent approval disabled in committed settings and require review for tool use.",
                tags=("agent-config", "gemini", "approval"),
            )
        )

    approval_mode = general.get("defaultApprovalMode", data.get("defaultApprovalMode"))
    if isinstance(approval_mode, str) and approval_mode.lower() in {"auto_edit", "yolo"}:
        findings.append(
            make_finding(
                rule_id="CFG014",
                title="Gemini automatic or persistent tool approval is enabled",
                severity="medium",
                path=rel_path,
                line=find_key_line(text, "defaultApprovalMode"),
                message="Gemini CLI settings use an approval mode that can reduce review before tool execution.",
                evidence=approval_mode,
                remediation="Use the default approval mode for committed project settings.",
                tags=("agent-config", "gemini", "approval"),
            )
        )
    return findings


def scan_codex_config(rel_path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []

    findings.extend(scan_toml_literal_secrets(rel_path, text))

    if re.search(r"^\s*default_permissions\s*=\s*[\"']:danger-full-access[\"']", text, re.I | re.M):
        line = find_key_line(text, "default_permissions")
        findings.append(
            make_finding(
                rule_id="CFG011",
                title="Codex permission profile grants full access",
                severity="high",
                path=rel_path,
                line=line,
                message="Codex config sets the default permission profile to danger-full-access.",
                evidence=line_text(text, line),
                remediation="Use a workspace-scoped permission profile as the project default.",
                tags=("agent-config", "codex", "permissions"),
            )
        )

    if re.search(r"^\s*sandbox_mode\s*=\s*[\"']danger-full-access[\"']", text, re.I | re.M):
        line = find_key_line(text, "sandbox_mode")
        findings.append(
            make_finding(
                rule_id="CFG007",
                title="Codex sandbox is disabled",
                severity="high",
                path=rel_path,
                line=line,
                message="Codex config sets sandbox_mode to danger-full-access.",
                evidence=line_text(text, line),
                remediation="Use workspace-write or read-only sandboxing for committed project defaults.",
                tags=("agent-config", "codex", "sandbox"),
            )
        )

    if re.search(r"^\s*approval_policy\s*=\s*[\"']never[\"']", text, re.I | re.M):
        line = find_key_line(text, "approval_policy")
        findings.append(
            make_finding(
                rule_id="CFG008",
                title="Codex approvals are disabled",
                severity="high",
                path=rel_path,
                line=line,
                message="Codex config disables approval prompts.",
                evidence=line_text(text, line),
                remediation="Use on-request or a stricter approval policy for repository defaults.",
                tags=("agent-config", "codex", "approval"),
            )
        )

    if re.search(r"^\s*network_access\s*=\s*true\b", text, re.I | re.M):
        line = find_key_line(text, "network_access")
        findings.append(
            make_finding(
                rule_id="CFG009",
                title="Codex workspace sandbox allows network access",
                severity="medium",
                path=rel_path,
                line=line,
                message="Codex config enables network access for sandboxed commands.",
                evidence=line_text(text, line),
                remediation="Keep network access disabled by default and allow it only for reviewed commands.",
                tags=("agent-config", "codex", "network"),
            )
        )

    for line_number, line in enumerate(text.splitlines(), start=1):
        if re.search(r"writable_roots\s*=.*([\"']/(?:[\"']|,)|[\"']~[\"']|[\"']\$HOME[\"'])", line, re.I):
            findings.append(
                make_finding(
                    rule_id="CFG010",
                    title="Codex writable roots include broad filesystem path",
                    severity="medium",
                    path=rel_path,
                    line=line_number,
                    message="Codex config grants write access outside a narrow workspace path.",
                    evidence=line,
                    remediation="Limit writable_roots to specific project directories.",
                    tags=("agent-config", "codex", "filesystem"),
                )
            )

    if re.search(r"^\s*ignore_default_excludes\s*=\s*true\b", text, re.I | re.M):
        line = find_key_line(text, "ignore_default_excludes")
        findings.append(
            make_finding(
                rule_id="CFG013",
                title="Agent configuration weakens secret redaction",
                severity="medium",
                path=rel_path,
                line=line,
                message="Codex config keeps environment variables that are normally excluded because their names look secret-bearing.",
                evidence=line_text(text, line),
                remediation="Keep default environment exclusions enabled for token, secret, password, and key variables.",
                tags=("agent-config", "codex", "secrets"),
            )
        )

    return dedupe(findings)


def scan_literal_secrets(rel_path: Path, text: str, ecosystem: str, data: Any) -> list[Finding]:
    findings: list[Finding] = []
    for key_path, value in walk_json(data):
        if not key_path or not isinstance(value, str):
            continue
        key = key_path[-1]
        if not SECRET_NAME.search(key) or not looks_like_literal_secret(value):
            continue
        line = find_line_containing(text, f'"{key}"') or find_key_line(text, key)
        findings.append(
            make_finding(
                rule_id="CFG012",
                title="Agent configuration stores literal secret-like value",
                severity="high",
                path=rel_path,
                line=line,
                message=f"{ecosystem} settings contain a literal value under a secret-like key.",
                evidence=key,
                remediation="Reference secrets through the runtime environment or a secret manager instead of committing them.",
                tags=("agent-config", "secrets"),
            )
        )
    return findings


def scan_toml_literal_secrets(rel_path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*([\"'])(.*?)\2", re.I)
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if not match:
            continue
        key = match.group(1)
        value = match.group(3)
        if not SECRET_NAME.search(key) or not looks_like_literal_secret(value):
            continue
        findings.append(
            make_finding(
                rule_id="CFG012",
                title="Agent configuration stores literal secret-like value",
                severity="high",
                path=rel_path,
                line=line_number,
                message="Codex config contains a literal value under a secret-like key.",
                evidence=key,
                remediation="Reference secrets through the runtime environment or a secret manager instead of committing them.",
                tags=("agent-config", "codex", "secrets"),
            )
        )
    return findings


def looks_like_literal_secret(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8:
        return False
    lowered = stripped.lower()
    if stripped.startswith(("$", "${")) or "{{" in stripped:
        return False
    if lowered in {"redacted", "changeme", "change-me", "placeholder"}:
        return False
    return True


def get_nested(value: Any, path: tuple[str, ...]) -> Any:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def normalize_tool(tool: str) -> str:
    return "".join(tool.lower().split())


def extract_tool_argument(tool: str) -> str:
    match = re.search(r"\((.*)\)", tool)
    if not match:
        return ""
    return match.group(1).strip().lower()


def find_line_containing(text: str, needle: str) -> int | None:
    if not needle:
        return None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return line_number
    return None


def line_text(text: str, line_number: int | None) -> str:
    if line_number is None:
        return ""
    lines = text.splitlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""


def walk_json(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    items: list[tuple[tuple[str, ...], Any]] = [(path, value)]
    if isinstance(value, dict):
        for key, child in value.items():
            items.extend(walk_json(child, (*path, str(key))))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            items.extend(walk_json(child, (*path, str(index))))
    return items


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.location.path, finding.location.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
