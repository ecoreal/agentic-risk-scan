# Security Policy

Agentic Risk Scan is a security tool, but scanner findings are heuristic and do
not prove exploitability.

## Reporting Vulnerabilities

Please report vulnerabilities through GitHub Security Advisories when available.
If advisories are not available for your fork, open a minimal issue that avoids
publishing live secrets or exploit-only details.

## Scope

Security reports are in scope when they affect:

- Scanner correctness for a documented rule.
- SARIF, JSON, or baseline output integrity.
- CLI behavior that could unexpectedly execute repository content.

The scanner should never execute files from the repository being scanned.

