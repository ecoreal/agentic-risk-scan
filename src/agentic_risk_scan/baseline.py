from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {str(item) for item in data}
    if isinstance(data, dict):
        values = data.get("findings", data.get("fingerprints", []))
        if isinstance(values, list):
            fingerprints: set[str] = set()
            for item in values:
                if isinstance(item, str):
                    fingerprints.add(item)
                elif isinstance(item, dict) and "fingerprint" in item:
                    fingerprints.add(str(item["fingerprint"]))
            return fingerprints
    return set()


def filter_baseline(findings: list[Finding], fingerprints: set[str]) -> list[Finding]:
    if not fingerprints:
        return findings
    return [finding for finding in findings if finding.fingerprint() not in fingerprints]


def write_baseline(path: Path, findings: list[Finding]) -> None:
    payload = {
        "schema": "agentic-risk-scan-baseline-v1",
        "findings": [
            {
                "fingerprint": finding.fingerprint(),
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "path": finding.location.path,
                "title": finding.title,
            }
            for finding in sorted(findings, key=lambda item: item.fingerprint())
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

