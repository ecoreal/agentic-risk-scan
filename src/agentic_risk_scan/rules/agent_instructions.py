from __future__ import annotations

import re
from pathlib import Path

from .agent_config import is_agent_config_path
from .common import make_finding
from ..models import Finding


INSTRUCTION_BASENAMES = {
    "agents.md",
    "agent.md",
    "claude.md",
    "gemini.md",
    "copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".roomodes",
}

INSTRUCTION_PATH_MARKERS = (
    ".github/instructions/",
    ".github/agents/",
    ".github/prompts/",
    ".cursor/rules/",
    ".windsurf/rules/",
    ".roo/rules/",
    ".claude/",
    ".codex/skills/",
    ".codex/prompts/",
    # Agent Skills packaging: instructions distributed as a skill directory.
    ".claude/skills/",
    "skills/",
)

BIDI_CHARS = {
    "\u202a": "left-to-right embedding",
    "\u202b": "right-to-left embedding",
    "\u202c": "pop directional formatting",
    "\u202d": "left-to-right override",
    "\u202e": "right-to-left override",
    "\u2066": "left-to-right isolate",
    "\u2067": "right-to-left isolate",
    "\u2068": "first strong isolate",
    "\u2069": "pop directional isolate",
}

ZERO_WIDTH_CHARS = {
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u200e": "left-to-right mark",
    "\u200f": "right-to-left mark",
}

PROMPT_INJECTION_PATTERNS = (
    # "ignore previous instructions" is the canonical payload; real-world
    # variants insert an article ("ignore the previous instructions", "ignore
    # all the above instructions") and must match too.
    re.compile(
        r"\bignore\s+(?:(?:all|any)\s+)?(?:(?:the|these|those)\s+)?"
        r"(?:previous|above|earlier|prior|preceding)\s+instructions\b",
        re.I,
    ),
    re.compile(
        r"\bdisregard\s+(?:(?:all|any)\s+)?(?:(?:the|these|those)\s+)?"
        r"(?:previous|above|earlier|prior|preceding)\s+instructions\b",
        re.I,
    ),
    re.compile(r"\boverride\s+(the\s+)?(system|developer)\s+(prompt|message|instructions)\b", re.I),
    re.compile(r"\breveal\s+(the\s+)?(system\s+prompt|developer\s+message|hidden\s+instructions)\b", re.I),
    re.compile(r"\b(exfiltrate|steal|leak)\b.*\b(secret|token|credential|api key|prompt)\b", re.I),
    re.compile(r"\bsend\b.*\b(secret|token|credential|api key)\b.*\b(http|https|webhook|server)\b", re.I),
)

# A line that *documents* an injection pattern (security guidance, detector
# reference tables) quotes the phrase inside a string/backtick and explains it
# with defensive vocabulary. That is a mention, not a payload: keep the finding
# but at info severity so security teams can still see (and inline-ignore) it.
DEFENSIVE_CONTEXT_RE = re.compile(
    r"\b(detect|detected|detection|scan|scanner|scans|redact|redaction|sanitiz[a-z]*"
    r"|block|blocked|pattern|patterns|resembl[a-z]*|e\.g\.|example|malicious|suspicious"
    r"|injection|untrusted|do not follow|never follow|not\s+follow)\b",
    re.IGNORECASE,
)


def quoted_phrase(line: str, pattern: re.Pattern[str]) -> bool:
    match = pattern.search(line)
    if not match:
        return False
    start, end = match.span()
    before = line[:start].rstrip()
    after = line[end:].lstrip()
    if not before or not after:
        return False
    return before[-1] in "\"'`" and after[0] in "\"'`"


def is_defensive_mention(line: str) -> bool:
    """True when the line cites an injection phrase rather than carrying one.

    Quoting is the load-bearing signal: a payload is written as an
    instruction, while reference material and defensive guidance put the
    phrase inside quotes or backticks ("ignore previous instructions"). Also
    require at least a few words of surrounding prose so a one-word line that
    is itself only a quoted phrase still counts as a payload.
    """
    if not any(quoted_phrase(line, pattern) for pattern in PROMPT_INJECTION_PATTERNS):
        return False
    return len(line.split()) >= 6


DANGEROUS_COMMAND_PATTERNS = (
    re.compile(r"\b(curl|wget)\b.+\|\s*(sh|bash|zsh)\b", re.I),
    re.compile(r"\brm\s+-rf\s+(/|\$HOME|~|\*)", re.I),
    re.compile(r"\bchmod\s+-R\s+777\b", re.I),
    re.compile(r"\b(nc|netcat)\b.+\s-e\s+", re.I),
    re.compile(r"\bbash\s+-i\s+.*>&", re.I),
    re.compile(r"\bbase64\s+(-d|--decode)\b.+\|\s*(sh|bash|python|node)", re.I),
)

BROAD_TOOL_PATTERNS = (
    re.compile(r"\ballowed[-_ ]tools\s*:\s*(\*|all|bash\(\*\)|shell|terminal)\b", re.I),
    re.compile(r"\btools\s*:\s*(\*|all|\[\s*['\"]?\*['\"]?\s*\])", re.I),
    re.compile(r"\bpermissions\s*:\s*(\*|all|full[-_ ]access|dangerously)", re.I),
)


class AgentInstructionRule:
    rule_group = "agent-instructions"

    def interested(self, rel_path: Path) -> bool:
        path = rel_path.as_posix().lower()
        name = rel_path.name.lower()
        if is_agent_config_path(rel_path):
            return False
        return (
            name in INSTRUCTION_BASENAMES
            or any(marker in path for marker in INSTRUCTION_PATH_MARKERS)
            or path.endswith(".mdc")
        )

    def scan(self, rel_path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()

        for line_number, line in enumerate(lines, start=1):
            for char, label in BIDI_CHARS.items():
                if char in line:
                    findings.append(
                        make_finding(
                            rule_id="AGENT001",
                            title="Bidirectional control character in agent instructions",
                            severity="high",
                            path=rel_path,
                            line=line_number,
                            message=(
                                "Bidirectional control characters can hide or reorder instructions "
                                "as rendered by editors and review tools."
                            ),
                            evidence=f"{label} detected",
                            remediation="Remove invisible Unicode control characters from instruction files.",
                            tags=("agent-instructions", "unicode"),
                        )
                    )
                    break

            for char, label in ZERO_WIDTH_CHARS.items():
                if char in line:
                    findings.append(
                        make_finding(
                            rule_id="AGENT002",
                            title="Zero-width character in agent instructions",
                            severity="medium",
                            path=rel_path,
                            line=line_number,
                            message=(
                                "Zero-width characters can be used to hide prompt text from casual review."
                            ),
                            evidence=f"{label} detected",
                            remediation="Remove zero-width characters unless the file has a documented need for them.",
                            tags=("agent-instructions", "unicode"),
                        )
                    )
                    break

            if any(pattern.search(line) for pattern in PROMPT_INJECTION_PATTERNS):
                mention = is_defensive_mention(line)
                findings.append(
                    make_finding(
                        rule_id="AGENT003",
                        title="Prompt-injection phrase in agent instructions",
                        severity="info" if mention else "high",
                        path=rel_path,
                        line=line_number,
                        message=(
                            "This line quotes a known override phrase while describing detection or "
                            "redaction; it is likely documentation. Confirm and inline-ignore if so."
                            if mention
                            else "This line resembles an instruction designed to override "
                            "higher-priority agent policy or extract secrets."
                        ),
                        evidence=line,
                        remediation=(
                            "Keep untrusted instructions out of committed agent config, and review "
                            "instruction changes like code."
                        ),
                        tags=("agent-instructions", "prompt-injection"),
                    )
                )

            if any(pattern.search(line) for pattern in DANGEROUS_COMMAND_PATTERNS):
                findings.append(
                    make_finding(
                        rule_id="AGENT004",
                        title="Dangerous command embedded in agent instructions",
                        severity="high",
                        path=rel_path,
                        line=line_number,
                        message=(
                            "Agent instructions contain shell behavior commonly associated with "
                            "download-and-execute, destructive actions, or reverse shells."
                        ),
                        evidence=line,
                        remediation=(
                            "Move reviewed commands into scripts, require explicit user approval, and "
                            "avoid network bootstrap commands in instruction files."
                        ),
                        tags=("agent-instructions", "shell"),
                    )
                )

            if any(pattern.search(line) for pattern in BROAD_TOOL_PATTERNS):
                findings.append(
                    make_finding(
                        rule_id="AGENT005",
                        title="Agent instructions request broad tool access",
                        severity="medium",
                        path=rel_path,
                        line=line_number,
                        message=(
                            "Broad tool grants make it harder to reason about what a repository-scoped "
                            "agent may execute."
                        ),
                        evidence=line,
                        remediation=(
                            "List only the specific tools and command prefixes needed by the workflow."
                        ),
                        tags=("agent-instructions", "permissions"),
                    )
                )

        return dedupe(findings)


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.location.path, finding.location.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
