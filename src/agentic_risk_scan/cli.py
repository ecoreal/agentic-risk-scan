from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .audit_report import render_audit_report
from .baseline import filter_baseline, load_baseline, write_baseline
from .config import load_project_config, write_default_config
from .gitdiff import DEFAULT_DIFF_FILTER, GitDiffError, changed_paths_from_git
from .inventory import collect_inventory, render_inventory
from .models import SEVERITY_ORDER, ScanConfig
from .registry import RULES
from .reporters import render
from .scanner import scan_path
from .workflow import DEFAULT_WORKFLOW_PATH, write_workflow


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
    list_rules.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="rule list output format",
    )
    list_rules.set_defaults(func=run_rules)

    inventory = subparsers.add_parser("inventory", help="list repository agentic attack surfaces")
    add_inventory_args(inventory)
    inventory.set_defaults(func=run_inventory)

    report = subparsers.add_parser("report", help="write a combined scan and inventory report")
    add_report_args(report)
    report.set_defaults(func=run_report)

    init_config = subparsers.add_parser("init-config", help="write a starter .agentic-risk-scan.json")
    init_config.add_argument(
        "path",
        nargs="?",
        default=".agentic-risk-scan.json",
        help="config file path to create",
    )
    init_config.set_defaults(func=run_init_config)

    init_ci = subparsers.add_parser("init-ci", help="write a GitHub Actions workflow for this scanner")
    init_ci.add_argument(
        "--output",
        "-o",
        type=Path,
        default=DEFAULT_WORKFLOW_PATH,
        help="workflow path to create",
    )
    init_ci.add_argument(
        "--mode",
        choices=("pr", "full", "both"),
        default="both",
        help="workflow type to generate",
    )
    init_ci.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "info", "none"),
        default="high",
        help="severity threshold used by generated workflow",
    )
    init_ci.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing workflow file",
    )
    init_ci.set_defaults(func=run_init_ci)

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
        choices=("text", "json", "markdown", "sarif", "github"),
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
        "--changed",
        action="append",
        default=[],
        metavar="PATH",
        help="only scan this changed file or directory; can be repeated",
    )
    parser.add_argument(
        "--changed-from",
        metavar="REF",
        help="only scan files changed from this git ref to --changed-to",
    )
    parser.add_argument(
        "--changed-to",
        metavar="REF",
        default="HEAD",
        help="git ref used with --changed-from; defaults to HEAD",
    )
    parser.add_argument(
        "--diff-filter",
        default=DEFAULT_DIFF_FILTER,
        help="git diff-filter used with --changed-from; defaults to ACMR",
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
        "--no-inline-ignores",
        action="store_true",
        help="do not honor agentic-risk-scan inline ignore comments",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=1_000_000,
        help="maximum file size in bytes to read",
    )


def add_inventory_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="repository path to inventory",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="inventory output format",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="write the inventory to a file instead of stdout",
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
        "--include-ignored",
        action="store_true",
        help="inventory ignored/generated directories such as node_modules and .git",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=1_000_000,
        help="maximum file size in bytes to read",
    )


def add_report_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="repository path to report on",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="write the report to a file instead of stdout",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "html"),
        default="markdown",
        help="report output format",
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
        "--changed",
        action="append",
        default=[],
        metavar="PATH",
        help="only report on this changed file or directory; can be repeated",
    )
    parser.add_argument(
        "--changed-from",
        metavar="REF",
        help="only report on files changed from this git ref to --changed-to",
    )
    parser.add_argument(
        "--changed-to",
        metavar="REF",
        default="HEAD",
        help="git ref used with --changed-from; defaults to HEAD",
    )
    parser.add_argument(
        "--diff-filter",
        default=DEFAULT_DIFF_FILTER,
        help="git diff-filter used with --changed-from; defaults to ACMR",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="ignore findings whose fingerprints are present in a baseline file",
    )
    parser.add_argument(
        "--include-ignored",
        action="store_true",
        help="report on ignored/generated directories such as node_modules and .git",
    )
    parser.add_argument(
        "--no-inline-ignores",
        action="store_true",
        help="do not honor agentic-risk-scan inline ignore comments",
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
    changed_paths = list(args.changed)
    if args.changed_from:
        try:
            changed_paths.extend(
                changed_paths_from_git(
                    path.resolve(),
                    args.changed_from,
                    head=args.changed_to,
                    diff_filter=args.diff_filter,
                )
            )
        except GitDiffError as exc:
            sys.stderr.write(f"failed to compute changed files: {exc}\n")
            return 2
    config = ScanConfig(
        root=path.resolve(),
        include_ignored=args.include_ignored,
        max_file_size=args.max_file_size,
        exclude=tuple(project_config.exclude) + tuple(args.exclude),
        disabled_rules=tuple(project_config.disabled_rules) + tuple(args.disable_rule),
        inline_ignores=not args.no_inline_ignores,
        changed_paths=tuple(changed_paths),
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


def run_init_ci(args: argparse.Namespace) -> int:
    try:
        write_workflow(args.output, mode=args.mode, fail_on=args.fail_on, force=args.force)
    except FileExistsError:
        sys.stderr.write(f"{args.output} already exists\n")
        return 2
    sys.stdout.write(f"wrote {args.output}\n")
    return 0


def run_inventory(args: argparse.Namespace) -> int:
    path = Path(args.path or ".")
    project_config = load_project_config(path, args.config, no_config=args.no_config)
    config = ScanConfig(
        root=path.resolve(),
        include_ignored=args.include_ignored,
        max_file_size=args.max_file_size,
        exclude=tuple(project_config.exclude) + tuple(args.exclude),
    )
    result = collect_inventory(path, config=config)
    output = render_inventory(result, fmt=args.format)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


def run_report(args: argparse.Namespace) -> int:
    path = Path(args.path or ".")
    project_config = load_project_config(path, args.config, no_config=args.no_config)
    baseline_path = args.baseline or project_config.baseline
    changed_paths = list(args.changed)
    if args.changed_from:
        try:
            changed_paths.extend(
                changed_paths_from_git(
                    path.resolve(),
                    args.changed_from,
                    head=args.changed_to,
                    diff_filter=args.diff_filter,
                )
            )
        except GitDiffError as exc:
            sys.stderr.write(f"failed to compute changed files: {exc}\n")
            return 2
    config = ScanConfig(
        root=path.resolve(),
        include_ignored=args.include_ignored,
        max_file_size=args.max_file_size,
        exclude=tuple(project_config.exclude) + tuple(args.exclude),
        disabled_rules=tuple(project_config.disabled_rules) + tuple(args.disable_rule),
        inline_ignores=not args.no_inline_ignores,
        changed_paths=tuple(changed_paths),
    )
    scan_result = scan_path(path, config=config)
    scan_result.findings = project_config.filter_findings(scan_result.findings)
    if baseline_path:
        scan_result.findings = filter_baseline(scan_result.findings, load_baseline(baseline_path))

    inventory_result = collect_inventory(path, config=config)
    output = render_audit_report(scan_result, inventory_result, fmt=args.format)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)

    fail_on = args.fail_on or project_config.fail_on or "high"
    if fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[fail_on]
    return 1 if any(finding.rank >= threshold for finding in scan_result.findings) else 0


def run_rules(args: argparse.Namespace) -> int:
    if args.format == "json":
        import json

        sys.stdout.write(json.dumps([rule.__dict__ for rule in RULES], indent=2, sort_keys=True) + "\n")
        return 0
    if args.format == "markdown":
        current_category = None
        for rule in RULES:
            if rule.category != current_category:
                if current_category is not None:
                    sys.stdout.write("\n")
                sys.stdout.write(f"## {rule.category}\n\n")
                sys.stdout.write("| Rule | Severity | Description |\n| --- | --- | --- |\n")
                current_category = rule.category
            sys.stdout.write(f"| `{rule.rule_id}` | {rule.severity} | {rule.title} |\n")
        return 0
    for rule in RULES:
        sys.stdout.write(f"{rule.rule_id:<8} {rule.severity:<11} {rule.title}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    commands = {"scan", "rules", "inventory", "report", "init-config", "init-ci"}
    if not argv or (argv[0] not in commands and not argv[0].startswith("-")):
        argv = ["scan", *argv]
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
