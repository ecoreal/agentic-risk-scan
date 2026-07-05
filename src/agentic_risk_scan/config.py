from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .models import Finding, SEVERITY_ORDER


DEFAULT_CONFIG_NAMES = (".agentic-risk-scan.json", "agentic-risk-scan.json")


DEFAULT_CONFIG = """{
  "$schema": "https://raw.githubusercontent.com/ecoreal/agentic-risk-scan/main/docs/config.schema.json",
  "fail_on": "high",
  "exclude": [
    "node_modules/**",
    "dist/**"
  ],
  "disabled_rules": [],
  "severity_overrides": {},
  "suppressions": []
}
"""


@dataclass(frozen=True)
class Suppression:
    rule_id: str = "*"
    path: str = "*"
    fingerprint: str | None = None
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.fingerprint and self.fingerprint != finding.fingerprint():
            return False
        rule_ok = self.rule_id in {"*", finding.rule_id}
        path_ok = fnmatch(finding.location.path, self.path) or fnmatch(Path(finding.location.path).name, self.path)
        return rule_ok and path_ok


@dataclass(frozen=True)
class ProjectConfig:
    path: Path | None = None
    fail_on: str | None = None
    baseline: Path | None = None
    exclude: tuple[str, ...] = ()
    disabled_rules: tuple[str, ...] = ()
    severity_overrides: dict[str, str] = field(default_factory=dict)
    suppressions: tuple[Suppression, ...] = field(default_factory=tuple)

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        if self.severity_overrides:
            findings = [
                replace(finding, severity=self.severity_overrides.get(finding.rule_id, finding.severity))
                for finding in findings
            ]
        if not self.suppressions:
            return findings
        return [
            finding
            for finding in findings
            if not any(suppression.matches(finding) for suppression in self.suppressions)
        ]


def discover_config(root: Path) -> Path | None:
    start = root if root.is_dir() else root.parent
    for current in (start, *start.parents):
        for name in DEFAULT_CONFIG_NAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
    return None


def load_project_config(root: Path, path: Path | None = None, *, no_config: bool = False) -> ProjectConfig:
    if no_config:
        return ProjectConfig()

    config_path = path or discover_config(root.resolve())
    if config_path is None:
        return ProjectConfig()

    data = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{config_path} must contain a JSON object")

    fail_on = data.get("fail_on")
    if fail_on is not None and fail_on not in {*SEVERITY_ORDER, "none"}:
        raise ValueError(f"{config_path}: fail_on must be one of critical, high, medium, low, info, none")

    baseline = data.get("baseline")
    baseline_path = resolve_optional_path(config_path.parent, baseline)

    suppressions = tuple(parse_suppression(config_path, item) for item in as_list(data.get("suppressions")))
    severity_overrides = parse_severity_overrides(config_path, data.get("severity_overrides", {}))
    return ProjectConfig(
        path=config_path,
        fail_on=fail_on,
        baseline=baseline_path,
        exclude=tuple(str(item) for item in as_list(data.get("exclude"))),
        disabled_rules=tuple(str(item) for item in as_list(data.get("disabled_rules"))),
        severity_overrides=severity_overrides,
        suppressions=suppressions,
    )


def parse_suppression(config_path: Path, item: Any) -> Suppression:
    if not isinstance(item, dict):
        raise ValueError(f"{config_path}: each suppression must be an object")
    rule_id = str(item.get("rule_id", "*"))
    path = str(item.get("path", "*"))
    fingerprint = item.get("fingerprint")
    if fingerprint is not None:
        fingerprint = str(fingerprint)
    reason = str(item.get("reason", ""))
    return Suppression(rule_id=rule_id, path=path, fingerprint=fingerprint, reason=reason)


def parse_severity_overrides(config_path: Path, value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{config_path}: severity_overrides must be an object")
    overrides: dict[str, str] = {}
    for rule_id, severity in value.items():
        severity_value = str(severity)
        if severity_value not in SEVERITY_ORDER:
            raise ValueError(f"{config_path}: invalid severity override for {rule_id}: {severity_value}")
        overrides[str(rule_id).upper()] = severity_value
    return overrides


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def resolve_optional_path(base: Path, value: Any) -> Path | None:
    if not value:
        return None
    path = Path(str(value))
    if path.is_absolute():
        return path
    return base / path


def write_default_config(path: Path) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.write_text(DEFAULT_CONFIG, encoding="utf-8")
