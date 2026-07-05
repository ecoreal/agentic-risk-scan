from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_LABELS = tuple(SEVERITY_ORDER.keys())


@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None
    column: int | None = None

    def display(self) -> str:
        if self.line is None:
            return self.path
        if self.column is None:
            return f"{self.path}:{self.line}"
        return f"{self.path}:{self.line}:{self.column}"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"path": self.path}
        if self.line is not None:
            data["line"] = self.line
        if self.column is not None:
            data["column"] = self.column
        return data


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    message: str
    location: Location
    evidence: str = ""
    remediation: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity}")

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def fingerprint(self) -> str:
        stable = "\n".join(
            [
                self.rule_id,
                self.location.path,
                self.title,
                normalize_evidence(self.evidence),
            ]
        )
        return sha256(stable.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "location": self.location.to_dict(),
            "evidence": self.evidence,
            "remediation": self.remediation,
            "tags": list(self.tags),
            "fingerprint": self.fingerprint(),
        }


@dataclass(frozen=True)
class ScanConfig:
    root: Path
    include_ignored: bool = False
    max_file_size: int = 1_000_000
    exclude: tuple[str, ...] = ()
    disabled_rules: tuple[str, ...] = ()
    inline_ignores: bool = True


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0

    def summary(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        counts["total"] = len(self.findings)
        return counts

    def risk_score(self) -> int:
        if not self.findings:
            return 0
        weights = {
            "critical": 35,
            "high": 18,
            "medium": 8,
            "low": 3,
            "info": 1,
        }
        score = sum(weights[finding.severity] for finding in self.findings)
        return min(100, score)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda finding: (
                -finding.rank,
                finding.location.path,
                finding.location.line or 0,
                finding.rule_id,
            ),
        )


def normalize_evidence(evidence: str) -> str:
    return " ".join(evidence.strip().split())
