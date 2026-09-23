"""Git helpers: parse staged changes via ``git diff --cached``."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path


class GitError(Exception):
    """Raised when a git command fails or the directory is not a repository."""


@dataclass
class AddedLine:
    path: str
    line_no: int  # line number in the new (staged) file
    text: str  # content without the leading '+'


@dataclass
class StagedDiff:
    files: list[str] = field(default_factory=list)
    added_lines: list[AddedLine] = field(default_factory=list)
    binary_files: list[str] = field(default_factory=list)


def _run_git(args: list[str], cwd: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found on PATH") from exc
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise GitError(err or f"git {' '.join(args)} failed with code {proc.returncode}")
    return proc.stdout


def ensure_repo(cwd: Path | None = None) -> Path:
    """Return the repository work-tree root; raise GitError if not in a repo."""
    base = Path(cwd) if cwd else Path.cwd()
    try:
        out = _run_git(["rev-parse", "--show-toplevel"], base)
    except GitError as exc:
        raise GitError("not a git repository (or any of the parent directories)") from exc
    top = out.strip()
    if not top:
        raise GitError("could not determine git toplevel")
    return Path(top)


def git_dir(cwd: Path | None = None) -> Path:
    base = Path(cwd) if cwd else Path.cwd()
    out = _run_git(["rev-parse", "--absolute-git-dir"], base)
    return Path(out.strip())


def hooks_path(cwd: Path | None = None) -> Path:
    """Resolve hooks directory, honouring ``core.hooksPath`` when set."""
    base = Path(cwd) if cwd else Path.cwd()
    gd = git_dir(base)
    try:
        out = _run_git(["config", "--get", "core.hooksPath"], base)
    except GitError:
        return gd / "hooks"
    configured = out.strip()
    if not configured:
        return gd / "hooks"
    p = Path(configured)
    if p.is_absolute():
        return p
    # Relative to work tree root (git convention)
    return ensure_repo(base) / p


def parse_staged_diff(raw: str) -> StagedDiff:
    """Parse unified diff output (``-U0``) into staged added lines."""
    result = StagedDiff()
    current_path: str | None = None
    new_line_no = 0
    in_hunk = False
    binary_current: str | None = None

    lines = raw.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        if line.startswith("diff --git "):
            current_path = None
            in_hunk = False
            binary_current = None
            i += 1
            continue

        if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            # Path often appears as: Binary files a/x and b/x differ
            path = _path_from_binary_header(line)
            if path and path not in result.binary_files:
                result.binary_files.append(path)
                if path not in result.files:
                    result.files.append(path)
            binary_current = path
            i += 1
            continue

        if line.startswith("+++ "):
            current_path = _path_from_plus_plus(line)
            if current_path and current_path not in result.files:
                result.files.append(current_path)
            in_hunk = False
            i += 1
            continue

        if line.startswith("--- "):
            # Deletion-only or rename: path may only appear on ---
            # For pure deletions new file is /dev/null; skip content scan.
            i += 1
            continue

        if line.startswith("@@"):
            if current_path is None:
                # Fallback: try to extract from @@ header context (rare)
                i += 1
                continue
            new_line_no = _parse_hunk_new_start(line)
            in_hunk = True
            i += 1
            continue

        if in_hunk and current_path is not None and binary_current is None:
            if line.startswith("+") and not line.startswith("+++"):
                text = line[1:]
                # git may append \ No newline at end of file as separate line
                result.added_lines.append(
                    AddedLine(path=current_path, line_no=new_line_no, text=text)
                )
                new_line_no += 1
            elif line.startswith("-") and not line.startswith("---"):
                # removed line: only old side advances
                pass
            elif line.startswith(" ") or line == "":
                new_line_no += 1
            elif line.startswith("\\"):
                pass  # \ No newline marker
            else:
                # New file header inside hunk region shouldn't happen with -U0
                in_hunk = False

        i += 1

    return result


def _path_from_plus_plus(line: str) -> str | None:
    # +++ b/path/to/file  or  +++ /dev/null
    rest = line[4:].strip()
    if rest == "/dev/null":
        return None
    if rest.startswith('"'):
        # quoted path with escapes — strip quotes conservatively
        rest = rest.strip('"')
    if rest.startswith("b/"):
        rest = rest[2:]
    return rest or None


def _path_from_binary_header(line: str) -> str | None:
    # Binary files a/foo and b/foo differ
    if " b/" in line:
        part = line.split(" b/", 1)[1]
        part = part.replace(" differ", "").strip()
        return part or None
    if " and b/" in line:
        part = line.split(" and b/", 1)[1]
        part = part.replace(" differ", "").strip()
        return part or None
    return None


def _parse_hunk_new_start(header: str) -> int:
    # @@ -old,count +new,count @@
    try:
        plus = header.split("+", 1)[1]
        num = plus.split(",", 1)[0].split(" ", 1)[0]
        return int(num)
    except (IndexError, ValueError):
        return 1


def get_staged_diff(cwd: Path | None = None) -> StagedDiff:
    """Return staged added lines for the current repository."""
    base = Path(cwd) if cwd else Path.cwd()
    ensure_repo(base)
    raw = _run_git(
        [
            "diff",
            "--cached",
            "--no-color",
            "--unified=0",
            "--diff-filter=ACMR",
            "--no-textconv",
        ],
        base,
    )
    return parse_staged_diff(raw)


def staged_file_count(diff: StagedDiff) -> int:
    return len(diff.files)
