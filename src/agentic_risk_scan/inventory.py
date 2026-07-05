from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .models import ScanConfig
from .rules.agent_config import AgentConfigRule, path_matches
from .rules.agent_instructions import AgentInstructionRule
from .rules.github_actions import (
    detect_events,
    detect_write_permissions,
    find_ai_lines,
)
from .rules.mcp import MCPConfigRule, extract_servers
from .rules.package_scripts import PackageScriptsRule, LIFECYCLE_SCRIPTS
from .scanner import iter_changed_files, iter_files, path_excluded


@dataclass(frozen=True)
class InventoryItem:
    category: str
    path: str
    detail: str
    signals: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "path": self.path,
            "detail": self.detail,
            "signals": list(self.signals),
        }


@dataclass
class InventoryResult:
    root: Path
    items: list[InventoryItem] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0

    def summary(self) -> dict[str, int]:
        summary: dict[str, int] = {"total": len(self.items)}
        for item in self.items:
            summary[item.category] = summary.get(item.category, 0) + 1
        return summary

    def sorted_items(self) -> list[InventoryItem]:
        return sorted(self.items, key=lambda item: (item.category, item.path, item.detail))


AGENT_CONFIG_DETAILS = {
    ".claude/settings.json": "Claude Code settings",
    ".claude/settings.local.json": "Claude Code local settings",
    ".codex/config.toml": "Codex config",
    ".gemini/settings.json": "Gemini CLI settings",
}

Classifier = Callable[[Path, str], InventoryItem | None]


def collect_inventory(path: str | Path, *, config: ScanConfig | None = None) -> InventoryResult:
    root = Path(path).resolve()
    if config is None:
        config = ScanConfig(root=root)
    result = InventoryResult(root=root)

    files = (
        iter_changed_files(root, config.changed_paths, include_ignored=config.include_ignored)
        if config.changed_paths
        else iter_files(root, include_ignored=config.include_ignored)
    )
    for file_path in files:
        rel_path = Path(file_path.name) if root.is_file() else file_path.relative_to(root)
        if path_excluded(rel_path, config.exclude):
            continue

        classifiers = interested_classifiers(rel_path)
        if not classifiers:
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
        for classifier in classifiers:
            item = classifier(rel_path, text)
            if item is not None:
                result.items.append(item)

    return result


def interested_classifiers(rel_path: Path) -> list[Classifier]:
    classifiers: list[Classifier] = []
    if AgentConfigRule().interested(rel_path):
        classifiers.append(agent_config_item)
    if AgentInstructionRule().interested(rel_path):
        classifiers.append(agent_instruction_item)
    if MCPConfigRule().interested(rel_path):
        classifiers.append(mcp_item)
    if PackageScriptsRule().interested(rel_path):
        classifiers.append(package_scripts_item)
    path = rel_path.as_posix().lower()
    if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
        classifiers.append(github_actions_item)
    return classifiers


def agent_config_item(rel_path: Path, text: str) -> InventoryItem:
    path = rel_path.as_posix()
    detail = agent_config_detail(path.lower())
    signals = agent_config_signals(path.lower(), text)
    return InventoryItem("agent-config", path, detail, tuple(signals))


def agent_config_detail(path: str) -> str:
    for candidate, detail in AGENT_CONFIG_DETAILS.items():
        if path_matches(path, {candidate}):
            return detail
    return "Agent client settings"


def agent_config_signals(path: str, text: str) -> list[str]:
    lowered = text.lower()
    signals: list[str] = []
    if "permissions" in lowered:
        signals.append("permissions")
    if "hooks" in lowered:
        signals.append("hooks")
    if "sandbox_mode" in lowered or "sandbox" in lowered:
        signals.append("sandbox")
    if "approval_policy" in lowered or "approvalmode" in lowered:
        signals.append("approval-policy")
    if "environmentvariableredaction" in lowered or "shell_environment_policy" in lowered:
        signals.append("environment-policy")
    if path.endswith("config.toml") and "default_permissions" in lowered:
        signals.append("permission-profile")
    return signals


def agent_instruction_item(rel_path: Path, text: str) -> InventoryItem:
    path = rel_path.as_posix()
    signals = []
    lowered = text.lower()
    if "allowed-tools" in lowered or "permissions" in lowered:
        signals.append("tool-policy")
    if "ignore previous" in lowered or "system prompt" in lowered:
        signals.append("prompt-sensitive")
    return InventoryItem("agent-instructions", path, "Agent instruction file", tuple(signals))


def mcp_item(rel_path: Path, text: str) -> InventoryItem:
    path = rel_path.as_posix()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return InventoryItem("mcp", path, "MCP config", ("invalid-json",))
    servers = extract_servers(data)
    signals = []
    if servers:
        signals.append(f"servers:{len(servers)}")
        signals.extend(f"server:{name}" for name in sorted(servers)[:5])
    return InventoryItem("mcp", path, "MCP config", tuple(signals))


def package_scripts_item(rel_path: Path, text: str) -> InventoryItem | None:
    path = rel_path.as_posix()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    scripts = data.get("scripts")
    if not isinstance(scripts, dict) or not scripts:
        return None
    script_names = [str(name) for name in scripts]
    lifecycle = [name for name in script_names if name in LIFECYCLE_SCRIPTS]
    signals = [f"scripts:{len(script_names)}"]
    if lifecycle:
        signals.append("lifecycle:" + ",".join(sorted(lifecycle)[:5]))
    return InventoryItem("package-scripts", path, "npm package scripts", tuple(signals))


def github_actions_item(rel_path: Path, text: str) -> InventoryItem:
    path = rel_path.as_posix()
    events = sorted(detect_events(text))
    permissions = detect_write_permissions(text)
    ai_lines = find_ai_lines(text)
    signals = []
    if events:
        signals.append("events:" + ",".join(events))
    if permissions:
        signals.append("write-permissions")
    if ai_lines:
        signals.append("agent-like")
    return InventoryItem("github-actions", path, "GitHub Actions workflow", tuple(signals))


def render_inventory(result: InventoryResult, *, fmt: str) -> str:
    if fmt == "text":
        return render_inventory_text(result)
    if fmt == "json":
        return render_inventory_json(result)
    if fmt == "markdown":
        return render_inventory_markdown(result)
    raise ValueError(f"unknown inventory output format: {fmt}")


def render_inventory_text(result: InventoryResult) -> str:
    summary = result.summary()
    lines = [
        "Agentic Risk Inventory",
        f"root: {result.root}",
        "surfaces: "
        + (
            ", ".join(f"{key}={value}" for key, value in sorted(summary.items()) if key != "total")
            if summary["total"]
            else "none"
        ),
        f"total surfaces: {summary['total']}",
        f"scanned files: {result.scanned_files}, skipped files: {result.skipped_files}",
    ]
    for item in result.sorted_items():
        lines.extend(["", f"[{item.category}] {item.path}", f"  detail: {item.detail}"])
        if item.signals:
            lines.append(f"  signals: {', '.join(item.signals)}")
    return "\n".join(lines) + "\n"


def render_inventory_json(result: InventoryResult) -> str:
    payload = {
        "schema": "agentic-risk-inventory-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(result.root),
        "summary": result.summary(),
        "scanned_files": result.scanned_files,
        "skipped_files": result.skipped_files,
        "items": [item.to_dict() for item in result.sorted_items()],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_inventory_markdown(result: InventoryResult) -> str:
    summary = result.summary()
    lines = [
        "# Agentic Risk Inventory",
        "",
        f"- Root: `{result.root}`",
        f"- Total surfaces: `{summary['total']}`",
        f"- Scanned files: `{result.scanned_files}`",
        f"- Skipped files: `{result.skipped_files}`",
        "",
        "| Category | Path | Detail | Signals |",
        "| --- | --- | --- | --- |",
    ]
    for item in result.sorted_items():
        signals = ", ".join(item.signals) if item.signals else ""
        lines.append(f"| `{item.category}` | `{item.path}` | {item.detail} | {signals} |")
    return "\n".join(lines) + "\n"
