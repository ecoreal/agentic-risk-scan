from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .common import find_key_line, make_finding
from ..models import Finding


MCP_FILENAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "claude-desktop-config.json",
}

SHELL_COMMANDS = {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
REMOTE_FETCH = re.compile(r"\b(curl|wget|irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\b", re.I)
INLINE_EXECUTION = re.compile(r"\b(node|python|python3|ruby|perl|php)\s+-e\b", re.I)
SECRET_KEY = re.compile(r"(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential)", re.I)
RISKY_FLAGS = (
    "--allow-all",
    "--allow-write",
    "--allow-run",
    "--dangerously-skip-permissions",
    "--no-sandbox",
    "--privileged",
    "full-access",
)
TEMP_PATH_PREFIXES = ("/tmp/", "/var/tmp/", "~/downloads/", "/users/shared/")


class MCPConfigRule:
    rule_group = "mcp"

    def interested(self, rel_path: Path) -> bool:
        path = rel_path.as_posix().lower()
        name = rel_path.name.lower()
        return (
            name in MCP_FILENAMES
            or path.endswith("/mcp.json")
            or path.endswith("/mcp.servers.json")
            or path.endswith("/.cursor/mcp.json")
            or path.endswith("/.vscode/mcp.json")
            or path.endswith("/.roo/mcp.json")
        )

    def scan(self, rel_path: Path, text: str) -> list[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return [
                make_finding(
                    rule_id="MCP000",
                    title="MCP config is invalid JSON",
                    severity="low",
                    path=rel_path,
                    line=exc.lineno,
                    message="The file looks like an MCP config but cannot be parsed as JSON.",
                    evidence=exc.msg,
                    remediation="Fix the JSON syntax so scanners and clients read the same configuration.",
                    tags=("mcp", "json"),
                )
            ]

        findings: list[Finding] = []
        servers = extract_servers(data)
        for server_name, server_config in servers.items():
            if not isinstance(server_config, dict):
                continue
            line = find_key_line(text, server_name)
            findings.extend(scan_server(rel_path, text, server_name, server_config, line))
        return dedupe(findings)


def extract_servers(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    for key in ("mcpServers", "servers", "serverConfigs"):
        value = data.get(key)
        if isinstance(value, dict):
            return value
    if "command" in data:
        return {"default": data}
    return {}


def scan_server(
    rel_path: Path,
    text: str,
    server_name: str,
    server_config: dict[str, Any],
    line: int | None,
) -> list[Finding]:
    findings: list[Finding] = []
    command = str(server_config.get("command", ""))
    args = normalize_args(server_config.get("args", []))
    joined = " ".join([command, *args]).strip()
    command_name = Path(command).name.lower()

    if command_name in SHELL_COMMANDS and any(arg.lower() in {"-c", "/c"} for arg in args):
        findings.append(
            make_finding(
                rule_id="MCP001",
                title="MCP server starts through a shell wrapper",
                severity="high",
                path=rel_path,
                line=line,
                message=(
                    f"MCP server '{server_name}' launches through a shell. Shell wrappers hide the "
                    "actual executable boundary and make argument injection easier."
                ),
                evidence=joined,
                remediation="Point command directly at the reviewed executable and pass arguments as an array.",
                tags=("mcp", "shell"),
            )
        )

    if REMOTE_FETCH.search(joined) and re.search(r"\|\s*(sh|bash|zsh|python|node|pwsh)", joined, re.I):
        findings.append(
            make_finding(
                rule_id="MCP002",
                title="MCP server uses download-and-execute bootstrap",
                severity="high",
                path=rel_path,
                line=line,
                message=f"MCP server '{server_name}' downloads code and pipes it into an interpreter.",
                evidence=joined,
                remediation="Install MCP servers from pinned packages or checked-in scripts instead of runtime fetches.",
                tags=("mcp", "supply-chain"),
            )
        )

    if INLINE_EXECUTION.search(joined):
        findings.append(
            make_finding(
                rule_id="MCP003",
                title="MCP server uses inline interpreter execution",
                severity="medium",
                path=rel_path,
                line=line,
                message=f"MCP server '{server_name}' uses inline code execution.",
                evidence=joined,
                remediation="Move inline code into a reviewed file and invoke that file directly.",
                tags=("mcp", "inline-code"),
            )
        )

    for flag in RISKY_FLAGS:
        if flag in joined:
            findings.append(
                make_finding(
                    rule_id="MCP004",
                    title="MCP server requests broad runtime access",
                    severity="medium",
                    path=rel_path,
                    line=line,
                    message=f"MCP server '{server_name}' includes a broad or sandbox-disabling flag.",
                    evidence=joined,
                    remediation="Replace broad runtime flags with the narrow paths and operations required.",
                    tags=("mcp", "permissions"),
                )
            )
            break

    if command.lower().startswith(TEMP_PATH_PREFIXES):
        findings.append(
            make_finding(
                rule_id="MCP005",
                title="MCP server executable is loaded from a temporary path",
                severity="high",
                path=rel_path,
                line=line,
                message=f"MCP server '{server_name}' runs from a path that is often writable by other processes.",
                evidence=command,
                remediation="Install reviewed MCP server binaries into a controlled project or user-local path.",
                tags=("mcp", "path"),
            )
        )

    cwd = server_config.get("cwd")
    if isinstance(cwd, str) and cwd.strip() in {"/", "~", "$HOME"}:
        findings.append(
            make_finding(
                rule_id="MCP006",
                title="MCP server has overly broad working directory",
                severity="low",
                path=rel_path,
                line=line,
                message=f"MCP server '{server_name}' starts at a broad filesystem root.",
                evidence=f"cwd={cwd}",
                remediation="Set cwd to the specific project directory needed by this server.",
                tags=("mcp", "filesystem"),
            )
        )

    env = server_config.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            if SECRET_KEY.search(str(key)) and looks_inline_secret(value):
                findings.append(
                    make_finding(
                        rule_id="MCP007",
                        title="MCP config contains inline secret-like environment value",
                        severity="high",
                        path=rel_path,
                        line=find_key_line(text, str(key)) or line,
                        message=f"MCP server '{server_name}' appears to contain an inline secret value.",
                        evidence=str(key),
                        remediation=(
                            "Load secrets from the user's secret manager or environment at runtime, "
                            "and avoid committing secret values."
                        ),
                        tags=("mcp", "secrets"),
                    )
                )

    if is_unpinned_npx(command_name, args):
        findings.append(
            make_finding(
                rule_id="MCP008",
                title="MCP server uses unpinned npx package",
                severity="medium",
                path=rel_path,
                line=line,
                message=(
                    f"MCP server '{server_name}' runs a package without an explicit version pin."
                ),
                evidence=joined,
                remediation="Pin npx-launched MCP servers to a reviewed version, for example package@1.2.3.",
                tags=("mcp", "supply-chain"),
            )
        )

    return findings


def normalize_args(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


def looks_inline_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped or stripped.startswith(("${", "$", "%", "{{")):
        return False
    return len(stripped) >= 8


def is_unpinned_npx(command_name: str, args: list[str]) -> bool:
    if command_name not in {"npx", "npx.cmd", "pnpm", "pnpm.cmd", "bun", "bunx"}:
        return False
    package_args = [
        arg
        for arg in args
        if not arg.startswith("-") and arg not in {"dlx", "exec", "x", "bunx"}
    ]
    if not package_args:
        return False
    package = package_args[0]
    if package.startswith("@"):
        return package.count("@") < 2
    return "@" not in package


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

