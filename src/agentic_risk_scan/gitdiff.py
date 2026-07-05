from __future__ import annotations

import subprocess
from pathlib import Path


DEFAULT_DIFF_FILTER = "ACMR"


class GitDiffError(RuntimeError):
    pass


def changed_paths_from_git(
    root: Path,
    base: str,
    *,
    head: str = "HEAD",
    diff_filter: str = DEFAULT_DIFF_FILTER,
) -> tuple[str, ...]:
    scan_root = root if root.is_dir() else root.parent
    top_level = git_top_level(scan_root)
    args = [
        "git",
        "-C",
        str(top_level),
        "diff",
        "--name-only",
        f"--diff-filter={diff_filter}",
        f"{base}...{head}",
    ]
    completed = subprocess.run(args, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        fallback = [
            "git",
            "-C",
            str(top_level),
            "diff",
            "--name-only",
            f"--diff-filter={diff_filter}",
            base,
            head,
        ]
        completed = subprocess.run(fallback, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "git diff failed"
        raise GitDiffError(message)
    return tuple(
        rel_path
        for raw_path in completed.stdout.splitlines()
        if (rel_path := repo_path_to_scan_path(top_level, scan_root, raw_path.strip())) is not None
    )


def git_top_level(path: Path) -> Path:
    completed = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "not a git repository"
        raise GitDiffError(message)
    return Path(completed.stdout.strip()).resolve()


def repo_path_to_scan_path(top_level: Path, scan_root: Path, raw_path: str) -> str | None:
    if not raw_path:
        return None
    absolute = (top_level / raw_path).resolve()
    try:
        return absolute.relative_to(scan_root).as_posix()
    except ValueError:
        return None
