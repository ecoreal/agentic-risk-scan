from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .baseline import filter_baseline, load_baseline, write_baseline
from .config import load_project_config, write_default_config
from .models import SEVERITY_ORDER, ScanConfig
from .reporters import render
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentic-risk-scan",
        description="Scan repositories for AI agent workflow, MCP, and instruction-file risks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="scan a repository or file")
    add_scan_args(scan)
    scan.set_defaults(func=run_scan)

    list_rules = subparsers.add_parser("rules", help="list built-in rule identifiers")
    list_rules.set_defaults(func=run_rules)

    init_config = subparsers.add_parser("init-config", help="write a starter .agentic-risk-scan.json")
    init_config.add_argument(
        "path",
        nargs="?",
        default=".agentic-risk-scan.json",
        help="config file path to create",
    )
    init_config.set_defaults(func=run_init_config)

    return parser


def add_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="repository path to scan",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "sarif"),
        default="text",
        help="report output format",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="write the report to a file instead of stdout",
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "info", "none"),
        default=None,
        help="exit with code 1 when a finding at or above this severity exists",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="load JSON config from this path",
    )
    parser.add_argument(
        "--no-config",
        action="store_true",
        help="do not auto-load .agentic-risk-scan.json",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="exclude files matching this glob; can be repeated",
    )
    parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        help="disable a rule ID for this run; can be repeated",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="ignore findings whose fingerprints are present in a baseline file",
    )
    parser.add_argument(
        "--update-baseline",
        type=Path,
        help="write the current finding fingerprints to this baseline file",
    )
    parser.add_argument(
        "--include-ignored",
        action="store_true",
        help="scan ignored/generated directories such as node_modules and .git",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=1_000_000,
        help="maximum file size in bytes to read",
    )


def run_scan(args: argparse.Namespace) -> int:
    path = Path(args.path or ".")
    project_config = load_project_config(path, args.config, no_config=args.no_config)
    baseline_path = args.baseline or project_config.baseline
    config = ScanConfig(
        root=path.resolve(),
        include_ignored=args.include_ignored,
        max_file_size=args.max_file_size,
        exclude=tuple(project_config.exclude) + tuple(args.exclude),
        disabled_rules=tuple(project_config.disabled_rules) + tuple(args.disable_rule),
    )
    result = scan_path(path, config=config)
    result.findings = project_config.filter_findings(result.findings)

    if args.update_baseline:
        write_baseline(args.update_baseline, result.findings)

    if baseline_path:
        result.findings = filter_baseline(result.findings, load_baseline(baseline_path))

    output = render(result, fmt=args.format)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)

    fail_on = args.fail_on or project_config.fail_on or "high"
    if fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[fail_on]
    return 1 if any(finding.rank >= threshold for finding in result.findings) else 0


def run_init_config(args: argparse.Namespace) -> int:
    try:
        write_default_config(Path(args.path))
    except FileExistsError:
        sys.stderr.write(f"{args.path} already exists\n")
        return 2
    sys.stdout.write(f"wrote {args.path}\n")
    return 0


def run_rules(args: argparse.Namespace) -> int:
    del args
    rules = [
        ("GHA001", "critical", "pull_request_target checks out untrusted PR code"),
        ("GHA002", "high", "AI agent workflow has write-capable token on untrusted trigger"),
        ("GHA003", "high", "Untrusted GitHub event data is interpolated into shell"),
        ("GHA004", "medium", "Dangerous shell pattern in untrusted workflow"),
        ("GHA005", "medium/high", "Secrets are available in workflow with untrusted trigger"),
        ("GHA006", "high", "Untrusted trigger can reach a self-hosted runner"),
        ("GHA007", "high", "OIDC token can be minted from untrusted workflow"),
        ("AGENT001", "high", "Bidirectional control character in agent instructions"),
        ("AGENT002", "medium", "Zero-width character in agent instructions"),
        ("AGENT003", "high", "Prompt-injection phrase in agent instructions"),
        ("AGENT004", "high", "Dangerous command embedded in agent instructions"),
        ("AGENT005", "medium", "Agent instructions request broad tool access"),
        ("MCP000", "low", "MCP config is invalid JSON"),
        ("MCP001", "high", "MCP server starts through a shell wrapper"),
        ("MCP002", "high", "MCP server uses download-and-execute bootstrap"),
        ("MCP003", "medium", "MCP server uses inline interpreter execution"),
        ("MCP004", "medium", "MCP server requests broad runtime access"),
        ("MCP005", "high", "MCP server executable is loaded from a temporary path"),
        ("MCP006", "low", "MCP server has overly broad working directory"),
        ("MCP007", "high", "MCP config contains inline secret-like environment value"),
        ("MCP008", "medium", "MCP server uses unpinned npx package"),
        ("PKG001", "high", "Install lifecycle script runs dangerous shell behavior"),
        ("PKG002", "medium", "npm script contains dangerous shell behavior"),
        ("PKG003", "medium", "npm script may expose secret environment values"),
        ("PKG004", "low", "Dependency is installed from a remote URL"),
    ]
    for rule_id, severity, title in rules:
        sys.stdout.write(f"{rule_id:<8} {severity:<11} {title}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    commands = {"scan", "rules", "init-config"}
    if not argv or (argv[0] not in commands and not argv[0].startswith("-")):
        argv = ["scan", *argv]
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
