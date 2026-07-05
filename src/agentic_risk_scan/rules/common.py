from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Location


def make_finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    path: Path,
    line: int | None,
    message: str,
    evidence: str = "",
    remediation: str = "",
    tags: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        message=message,
        location=Location(path=path.as_posix(), line=line),
        evidence=clean_evidence(evidence),
        remediation=remediation,
        tags=tags,
    )


def clean_evidence(value: str, *, max_len: int = 220) -> str:
    value = " ".join(value.strip().split())
    if len(value) <= max_len:
        return value
    return value[: max_len - 3].rstrip() + "..."


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def first_line_matching(text: str, pattern: str | re.Pattern[str]) -> tuple[int, str] | None:
    compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
    for number, line in enumerate(text.splitlines(), start=1):
        if compiled.search(line):
            return number, line
    return None


def find_key_line(text: str, key: str) -> int | None:
    escaped = re.escape(key)
    pattern = re.compile(rf'["\']?{escaped}["\']?\s*[:=]')
    for number, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return number
    return None


def has_word(text: str, words: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in words)
