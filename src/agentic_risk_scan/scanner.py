from __future__ import annotations

import os
from fnmatch import fnmatch
from pathlib import Path
from typing import Protocol

from .models import Finding, ScanConfig, ScanResult
from .rules.agent_instructions import AgentInstructionRule
from .rules.github_actions import GitHubActionsRule
from .rules.mcp import MCPConfigRule
from .rules.package_scripts import PackageScriptsRule


IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "bower_components",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    "coverage",
}


class FileRule(Protocol):
    rule_group: str

    def interested(self, rel_path: Path) -> bool:
        ...

    def scan(self, rel_path: Path, text: str) -> list[Finding]:
        ...


RULES: tuple[FileRule, ...] = (
    GitHubActionsRule(),
    AgentInstructionRule(),
    MCPConfigRule(),
    PackageScriptsRule(),
)


def scan_path(path: str | Path, *, config: ScanConfig | None = None) -> ScanResult:
    root = Path(path).resolve()
    if config is None:
        config = ScanConfig(root=root)
    result = ScanResult(root=root)

    for file_path in iter_files(root, include_ignored=config.include_ignored):
        rel_path = Path(file_path.name) if root.is_file() else file_path.relative_to(root)
        if path_excluded(rel_path, config.exclude):
            continue
        interested_rules = [rule for rule in RULES if rule.interested(rel_path)]
        if not interested_rules:
            continue

        try:
            if file_path.stat().st_size > config.max_file_size:
                result.skipped_files += 1
                continue
            text = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            result.skipped_files += 1
            continue

        result.scanned_files += 1
        for rule in interested_rules:
            for finding in rule.scan(rel_path, text):
                if finding.rule_id not in config.disabled_rules:
                    result.findings.append(finding)

    return result


def iter_files(root: Path, *, include_ignored: bool = False) -> list[Path]:
    files: list[Path] = []
    if root.is_file():
        return [root]

    for current, dirs, filenames in os.walk(root):
        if not include_ignored:
            dirs[:] = [
                dirname
                for dirname in dirs
                if dirname not in IGNORED_DIRS and not dirname.endswith(".egg-info")
            ]
        current_path = Path(current)
        for filename in filenames:
            files.append(current_path / filename)
    return files


def path_excluded(rel_path: Path, patterns: tuple[str, ...]) -> bool:
    if not patterns:
        return False
    path = rel_path.as_posix()
    return any(fnmatch(path, pattern) or fnmatch(rel_path.name, pattern) for pattern in patterns)
