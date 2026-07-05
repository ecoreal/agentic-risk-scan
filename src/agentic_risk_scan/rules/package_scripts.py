from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .common import find_key_line, make_finding
from ..models import Finding


LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepublishOnly",
    "prepare",
}

DANGEROUS_SCRIPT_PATTERNS = (
    re.compile(r"\b(curl|wget)\b.+\|\s*(sh|bash|zsh|node|python)\b", re.I),
    re.compile(r"\b(eval|exec)\b", re.I),
    re.compile(r"\bbase64\s+(-d|--decode)\b.+\|\s*(sh|bash|node|python)\b", re.I),
    re.compile(r"\b(node|python|python3|ruby|perl)\s+-e\s+", re.I),
    re.compile(r"\brm\s+-rf\s+(/|\$HOME|~|\*)", re.I),
    re.compile(r"\b(nc|netcat)\b.+\s-e\s+", re.I),
)

SECRET_LEAK_PATTERNS = (
    re.compile(
        r"\b(printenv|env|set)\b.*(token|secret|password|credential|api[_-]?key|GITHUB_TOKEN|NPM_TOKEN)",
        re.I,
    ),
    re.compile(r"\b(curl|wget)\b.+\b(GITHUB_TOKEN|NPM_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)\b", re.I),
)

REMOTE_DEPENDENCY_PATTERNS = (
    re.compile(r"git\+https?://", re.I),
    re.compile(r"https?://.+\.(tgz|tar\.gz|zip)", re.I),
)


class PackageScriptsRule:
    rule_group = "package-scripts"

    def interested(self, rel_path: Path) -> bool:
        return rel_path.name == "package.json"

    def scan(self, rel_path: Path, text: str) -> list[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            findings.extend(scan_scripts(rel_path, text, scripts))

        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            dependencies = data.get(section, {})
            if isinstance(dependencies, dict):
                findings.extend(scan_dependencies(rel_path, text, section, dependencies))

        return dedupe(findings)


def scan_scripts(rel_path: Path, text: str, scripts: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for script_name, command_value in scripts.items():
        if not isinstance(command_value, str):
            continue
        command = command_value.strip()
        line = find_key_line(text, script_name)
        dangerous = any(pattern.search(command) for pattern in DANGEROUS_SCRIPT_PATTERNS)
        leaks_secret = any(pattern.search(command) for pattern in SECRET_LEAK_PATTERNS)

        if script_name in LIFECYCLE_SCRIPTS and dangerous:
            findings.append(
                make_finding(
                    rule_id="PKG001",
                    title="Install lifecycle script runs dangerous shell behavior",
                    severity="high",
                    path=rel_path,
                    line=line,
                    message=(
                        f"npm lifecycle script '{script_name}' can execute during install or publish "
                        "and contains risky shell behavior."
                    ),
                    evidence=command,
                    remediation=(
                        "Remove install-time network execution and move setup steps to explicit, reviewed commands."
                    ),
                    tags=("package", "supply-chain"),
                )
            )
        elif dangerous:
            findings.append(
                make_finding(
                    rule_id="PKG002",
                    title="npm script contains dangerous shell behavior",
                    severity="medium",
                    path=rel_path,
                    line=line,
                    message=f"Script '{script_name}' contains command patterns often used for execution abuse.",
                    evidence=command,
                    remediation="Replace eval, inline interpreters, and download-and-execute chains with reviewed scripts.",
                    tags=("package", "shell"),
                )
            )

        if leaks_secret:
            findings.append(
                make_finding(
                    rule_id="PKG003",
                    title="npm script may expose secret environment values",
                    severity="medium",
                    path=rel_path,
                    line=line,
                    message=f"Script '{script_name}' appears to print or send secret-like environment values.",
                    evidence=command,
                    remediation="Avoid printing secret-bearing environments and send tokens only to trusted endpoints.",
                    tags=("package", "secrets"),
                )
            )
    return findings


def scan_dependencies(
    rel_path: Path,
    text: str,
    section: str,
    dependencies: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []
    for name, spec_value in dependencies.items():
        spec = str(spec_value)
        if any(pattern.search(spec) for pattern in REMOTE_DEPENDENCY_PATTERNS):
            findings.append(
                make_finding(
                    rule_id="PKG004",
                    title="Dependency is installed from a remote URL",
                    severity="low",
                    path=rel_path,
                    line=find_key_line(text, name),
                    message=(
                        f"Dependency '{name}' in {section} is installed from a URL instead of a registry version."
                    ),
                    evidence=spec,
                    remediation="Prefer registry packages pinned by version and lockfile integrity.",
                    tags=("package", "supply-chain"),
                )
            )
    return findings


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
