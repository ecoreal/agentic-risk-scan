from __future__ import annotations

import json
import re
import urllib.parse
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
# Environment variables that let a process inject code or load attacker-controlled
# libraries before the MCP server itself runs. Committing them into an MCP config
# is a code-execution primitive independent of the server binary, because the
# runtime (Node, CPython, the dynamic linker, the shell) honors them at startup.
CODE_EXECUTION_ENV_KEYS = {
    "node_options": "Node.js evaluates code and loads modules from NODE_OPTIONS.",
    "ld_preload": "The dynamic linker preloads LD_PRELOAD libraries into the process.",
    "ld_audit": "The dynamic linker loads LD_AUDIT libraries into the process.",
    "dyld_insert_libraries": "macOS injects DYLD_INSERT_LIBRARIES into the process.",
    "pythonstartup": "CPython runs the PYTHONSTARTUP file when the interpreter starts.",
    "perl5opt": "Perl applies PERL5OPT command-line switches, including -M.",
    "rubyopt": "Ruby applies RUBYOPT switches, including -r.",
    "bash_env": "Bash sources BASH_ENV before running non-interactive scripts.",
    "shellopts": "SHELLOPTS enables shell options such as xtrace for spawned shells.",
    "prompt_command": "PROMPT_COMMAND runs arbitrary shell code before each prompt.",
    "git_ssh_command": "GIT_SSH_COMMAND runs an arbitrary program for Git SSH operations.",
    "git_external_diff": "GIT_EXTERNAL_DIFF runs an arbitrary program during Git diffs.",
    "npm_config_node_options": "npm forwards NODE_OPTIONS to child Node.js processes.",
}
# Weaker, but still hijackable: these variables change where a runtime resolves
# modules or libraries, so an attacker-controlled path can shadow real code.
LIBRARY_PATH_ENV_KEYS = {
    "node_path": "Node.js resolves modules from NODE_PATH, which can shadow real packages.",
    "ld_library_path": "The dynamic linker resolves libraries from LD_LIBRARY_PATH.",
    "dyld_library_path": "macOS resolves libraries from DYLD_LIBRARY_PATH.",
    "dyld_framework_path": "macOS resolves frameworks from DYLD_FRAMEWORK_PATH.",
    "pythonpath": "CPython resolves imports from PYTHONPATH, which can shadow real modules.",
    "pythonhome": "CPython resolves its standard library from PYTHONHOME.",
    "perl5lib": "Perl resolves modules from PERL5LIB.",
    "rubylib": "Ruby resolves libraries from RUBYLIB.",
    "zdotdir": "ZDOTDIR changes where zsh loads its startup files from.",
}

# Remote (streamable HTTP / SSE) MCP servers are configured with a URL instead of
# a command. Plaintext transport leaks the JSON-RPC traffic and any auth headers,
# and link-local or cloud-metadata targets let a config turn the client into an
# SSRF pivot against the host's metadata service.
CLOUD_METADATA_HOSTS = {
    "169.254.169.254",  # AWS/GCP/Azure/OpenStack IMDS
    "100.100.100.200",  # Alibaba Cloud metadata
    "fd00:ec2::254",  # AWS IPv6 IMDS
    "metadata.google.internal",
    "metadata.goog",
}
LINK_LOCAL_PREFIXES = ("169.254.", "fe80:", "::ffff:169.254.")
AUTH_HEADER_KEYS = {"authorization", "proxy-authorization", "x-auth-token", "x-api-key"}
EXACT_SEMVER_RE = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


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
    if "command" in data or "url" in data:
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

    env = server_config.get("env")
    if isinstance(env, dict):
        findings.extend(scan_environment(rel_path, text, server_name, env, line))
    findings.extend(scan_remote_server(rel_path, text, server_name, server_config, line))

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


def scan_environment(
    rel_path: Path,
    text: str,
    server_name: str,
    env: dict[str, Any],
    fallback_line: int | None,
) -> list[Finding]:
    findings: list[Finding] = []
    for key, value in env.items():
        name = str(key)
        lowered = name.lower()
        if lowered in CODE_EXECUTION_ENV_KEYS:
            severity = "high"
            reason = CODE_EXECUTION_ENV_KEYS[lowered]
        elif lowered in LIBRARY_PATH_ENV_KEYS:
            severity = "medium"
            reason = LIBRARY_PATH_ENV_KEYS[lowered]
        else:
            continue
        findings.append(
            make_finding(
                rule_id="MCP009",
                title="MCP server sets a code-injecting environment variable",
                severity=severity,
                path=rel_path,
                line=find_key_line(text, name) or fallback_line,
                message=(
                    f"MCP server '{server_name}' sets {name} in its environment. {reason}"
                ),
                evidence=f"{name}={value}",
                remediation=(
                    "Remove runtime-hijacking environment variables from the MCP config. "
                    "Pass only the specific configuration the server needs, and set secrets "
                    "or loader paths through a trusted launcher instead of the committed config."
                ),
                tags=("mcp", "code-execution", "environment"),
            )
        )
    return findings


def scan_remote_server(
    rel_path: Path,
    text: str,
    server_name: str,
    server_config: dict[str, Any],
    fallback_line: int | None,
) -> list[Finding]:
    findings: list[Finding] = []
    raw_url = server_config.get("url")
    url_line = find_key_line(text, "url") or fallback_line
    if isinstance(raw_url, str) and raw_url.strip():
        url = raw_url.strip()
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").strip().lower()
        if parsed.scheme.lower() == "http":
            findings.append(
                make_finding(
                    rule_id="MCP010",
                    title="Remote MCP server uses plaintext HTTP",
                    severity="high",
                    path=rel_path,
                    line=url_line,
                    message=(
                        f"Remote MCP server '{server_name}' connects over plaintext HTTP, "
                        "exposing its traffic and auth headers to anyone on the path."
                    ),
                    evidence=url,
                    remediation="Use an https:// URL for remote MCP servers so traffic and headers stay encrypted.",
                    tags=("mcp", "transport", "network"),
                )
            )
        if is_metadata_or_link_local(host):
            findings.append(
                make_finding(
                    rule_id="MCP011",
                    title="Remote MCP server targets a link-local or cloud metadata address",
                    severity="high",
                    path=rel_path,
                    line=url_line,
                    message=(
                        f"Remote MCP server '{server_name}' points at {host}, a link-local or "
                        "cloud metadata endpoint. This can turn the client into an SSRF pivot "
                        "against the host's instance credentials."
                    ),
                    evidence=url,
                    remediation="Point remote MCP servers at reviewed public or private service hosts, never at link-local or metadata addresses.",
                    tags=("mcp", "network", "ssrf"),
                )
            )

    headers = server_config.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if looks_inline_header_secret(str(key), value):
                findings.append(
                    make_finding(
                        rule_id="MCP012",
                        title="MCP config embeds an inline secret header",
                        severity="high",
                        path=rel_path,
                        line=find_key_line(text, str(key)) or url_line,
                        message=f"Remote MCP server '{server_name}' appears to embed an inline secret in its headers.",
                        evidence=str(key),
                        remediation=(
                            "Reference the secret through the client's environment or secret store "
                            "instead of committing the value in the MCP config."
                        ),
                        tags=("mcp", "secrets"),
                    )
                )
    return findings


def is_metadata_or_link_local(host: str) -> bool:
    if not host:
        return False
    if host in CLOUD_METADATA_HOSTS:
        return True
    return host.startswith(LINK_LOCAL_PREFIXES)


def looks_inline_header_secret(key: str, value: Any) -> bool:
    """True when a remote MCP header carries a committed credential."""

    if not isinstance(value, str) or not looks_inline_secret(value):
        return False
    lowered = key.strip().lower()
    if lowered in AUTH_HEADER_KEYS or SECRET_KEY.search(key):
        return True
    # A literal bearer/basic token is a credential regardless of the header name.
    return re.match(r"^(bearer|basic|token)\s+\S", value.strip(), re.I) is not None


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
    if "@" not in package:
        return True
    package_name, version = package.rsplit("@", 1)
    return not package_name or EXACT_SEMVER_RE.fullmatch(version) is None


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

