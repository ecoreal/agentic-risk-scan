from __future__ import annotations

import os
import re
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

    files = (
        iter_changed_files(root, config.changed_paths, include_ignored=config.include_ignored)
        if config.changed_paths
        else iter_files(root, include_ignored=config.include_ignored)
    )
    for file_path in files:
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
        inline_ignores = parse_inline_ignores(text) if config.inline_ignores else {}
        for rule in interested_rules:
            for finding in rule.scan(rel_path, text):
                if finding.rule_id not in config.disabled_rules:
                    if inline_ignored(finding, inline_ignores):
                        continue
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


def iter_changed_files(
    root: Path,
    changed_paths: tuple[str, ...],
    *,
    include_ignored: bool = False,
) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    scan_root = root.parent if root.is_file() else root

    for raw_path in changed_paths:
        if not raw_path:
            continue
        candidate = resolve_changed_path(scan_root, raw_path)
        if candidate is None:
            continue

        if root.is_file():
            if candidate == root and candidate not in seen:
                files.append(candidate)
                seen.add(candidate)
            continue

        if candidate.is_dir():
            nested_files = iter_files(candidate, include_ignored=include_ignored)
        elif candidate.is_file():
            nested_files = [candidate]
        else:
            continue

        for nested_file in nested_files:
            try:
                nested_file.relative_to(scan_root)
            except ValueError:
                continue
            if nested_file not in seen:
                files.append(nested_file)
                seen.add(nested_file)

    return files


def resolve_changed_path(root: Path, raw_path: str) -> Path | None:
    path = Path(raw_path)
    candidate = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def path_excluded(rel_path: Path, patterns: tuple[str, ...]) -> bool:
    if not patterns:
        return False
    path = rel_path.as_posix()
    return any(fnmatch(path, pattern) or fnmatch(rel_path.name, pattern) for pattern in patterns)


IGNORE_PATTERN = re.compile(
    r"agentic-risk-scan:\s*(?:ignore|disable-next-line)\s+(?P<rules>[A-Z0-9*,_\-\s]+)",
    re.IGNORECASE,
)


def parse_inline_ignores(text: str) -> dict[int, set[str]]:
    ignores: dict[int, set[str]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = IGNORE_PATTERN.search(line)
        if not match:
            continue
        rules = {
            rule.strip().upper()
            for rule in re.split(r"[, ]+", match.group("rules"))
            if rule.strip()
        }
        target_line = line_number + 1 if "disable-next-line" in line.lower() else line_number
        ignores.setdefault(target_line, set()).update(rules)
    return ignores


def inline_ignored(finding: Finding, ignores: dict[int, set[str]]) -> bool:
    if finding.location.line is None:
        return False
    direct = ignores.get(finding.location.line, set())
    previous = ignores.get(finding.location.line - 1, set())
    rules = direct | previous
    return "*" in rules or finding.rule_id in rules
