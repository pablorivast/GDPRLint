"""Git-free directory walking for ``gdprlint scan --all``.

Honors ``.gitignore`` files (root and nested) with git precedence rules:
deeper files override shallower ones, later patterns override earlier
ones, and nothing under an excluded directory can be re-included.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path

from pathspec import GitIgnoreSpec

from gdprlint.git_ops import AddedLine, StagedDiff

# Oversized files are counted but not scanned (line scanners are line-oriented).
MAX_SCAN_FILE_BYTES = 1_048_576
_BINARY_SNIFF_BYTES = 8192

_SpecChain = list[tuple[Path, GitIgnoreSpec]]


def scan_root(cwd: Path | None = None) -> Path:
    """Return the directory :func:`walk_worktree` scans.

    The nearest ancestor carrying a ``.git`` marker (directory or file, so
    worktrees and submodules count) wins; without one, ``cwd`` itself.
    """
    base = Path(cwd) if cwd else Path.cwd()
    start = base.absolute()
    current = start
    while True:
        if (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            return start
        current = parent


def _is_ignored(
    path: Path,
    chain: Sequence[tuple[Path, GitIgnoreSpec]],
    *,
    is_dir: bool,
) -> bool:
    """Resolve ignore decisions across the spec chain (shallowest first)."""
    ignored = False
    for base, spec in chain:
        try:
            rel = path.relative_to(base).as_posix()
        except ValueError:
            continue
        if is_dir:
            rel += "/"
        match = spec.check_file(rel)
        if match.include is not None:
            ignored = bool(match.include)
    return ignored


def _read_file(path: Path, rel: str, result: StagedDiff) -> None:
    try:
        data = path.read_bytes()
    except OSError:
        return
    if rel not in result.files:
        result.files.append(rel)
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        if rel not in result.binary_files:
            result.binary_files.append(rel)
        return
    if len(data) > MAX_SCAN_FILE_BYTES:
        return
    text = data.decode("utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), start=1):
        result.added_lines.append(AddedLine(path=rel, line_no=line_no, text=line))


def walk_worktree(
    cwd: Path | None = None,
    *,
    is_excluded: Callable[[str], bool] | None = None,
) -> StagedDiff:
    """Return every line of every non-ignored file under the scan root.

    Files ignored by any applicable ``.gitignore`` never reach the result;
    binary files (NUL byte in the first 8 KiB) and files larger than
    :data:`MAX_SCAN_FILE_BYTES` are counted but not scanned. ``is_excluded``
    applies the GDPRLint config exclude patterns to root-relative paths.
    Output is deterministically sorted by path (and line number).
    """
    root = scan_root(cwd)
    result = StagedDiff()
    chains: dict[Path, _SpecChain] = {root: []}

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dpath = Path(dirpath)
        chain = chains.get(dpath, [])
        ignore_file = dpath / ".gitignore"
        if ignore_file.is_file():
            try:
                lines = ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines = []
            if lines:
                chain = [*chain, (dpath, GitIgnoreSpec.from_lines(lines))]

        keep: list[str] = []
        for name in dirnames:
            if name == ".git":
                continue
            child = dpath / name
            if _is_ignored(child, chain, is_dir=True):
                continue
            chains[child] = chain
            keep.append(name)
        dirnames[:] = keep

        for name in filenames:
            if name == ".git":
                continue
            fpath = dpath / name
            if _is_ignored(fpath, chain, is_dir=False):
                continue
            rel = fpath.relative_to(root).as_posix()
            if is_excluded is not None and is_excluded(rel):
                continue
            _read_file(fpath, rel, result)

    result.files.sort()
    result.binary_files.sort()
    result.added_lines.sort(key=lambda ln: (ln.path, ln.line_no))
    return result
