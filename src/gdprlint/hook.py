"""Install / manage the Git pre-commit hook."""

from __future__ import annotations

import sys
from pathlib import Path

from gdprlint.git_ops import GitError, ensure_repo, hooks_path

BEGIN_MARK = "# >>> gdprlint begin (managed) >>>"
END_MARK = "# <<< gdprlint end <<<"

# Prefer console script on PATH; fall back to the installing interpreter.
_PY = sys.executable or "python3"
HOOK_BODY = f"""{BEGIN_MARK}
# GDPRLint pre-commit hook — technical privacy/security guardrail.
# Does not certify legal or GDPR compliance.
# Mute Hugging Face / tqdm / transformers download noise during scan.
export HF_HUB_DISABLE_PROGRESS_BARS=1
export TQDM_DISABLE=1
export TRANSFORMERS_VERBOSITY=error
GDPR_LINT_BIN="$(command -v gdprlint 2>/dev/null || true)"
if [ -n "$GDPR_LINT_BIN" ]; then
    "$GDPR_LINT_BIN" scan
    status=$?
else
    "{_PY}" -m gdprlint scan
    status=$?
fi
if [ "$status" -ne 0 ]; then
    exit "$status"
fi
{END_MARK}
"""


class HookError(Exception):
    """Raised when the hook cannot be installed."""


def _has_markers(content: str) -> bool:
    return BEGIN_MARK in content and END_MARK in content


def install_hook(cwd: Path | None = None) -> Path:
    """Install pre-commit hook in the current repository (idempotent)."""
    try:
        ensure_repo(cwd)
        hook_dir = hooks_path(cwd)
    except GitError as exc:
        raise HookError(str(exc)) from exc

    try:
        hook_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise HookError(f"cannot create hooks directory {hook_dir}: {exc}") from exc

    hook_path = hook_dir / "pre-commit"

    if hook_path.exists():
        content = hook_path.read_text(encoding="utf-8", errors="replace")
        if _has_markers(content):
            # Already installed — leave as-is (idempotent)
            _ensure_executable(hook_path)
            return hook_path
        # Append managed block without destroying existing hook
        new_content = content.rstrip() + "\n\n" + HOOK_BODY
        if not new_content.endswith("\n"):
            new_content += "\n"
        hook_path.write_text(new_content, encoding="utf-8")
    else:
        hook_path.write_text("#!/bin/sh\n\n" + HOOK_BODY, encoding="utf-8")

    _ensure_executable(hook_path)
    return hook_path


def uninstall_hook(cwd: Path | None = None) -> bool:
    """Remove the managed block from pre-commit if present. Returns True if removed."""
    try:
        ensure_repo(cwd)
        hook_dir = hooks_path(cwd)
    except GitError as exc:
        raise HookError(str(exc)) from exc

    hook_path = hook_dir / "pre-commit"
    if not hook_path.is_file():
        return False
    content = hook_path.read_text(encoding="utf-8", errors="replace")
    if not _has_markers(content):
        return False

    begin = content.index(BEGIN_MARK)
    end = content.index(END_MARK) + len(END_MARK)
    # Also strip a trailing newline after END_MARK
    after = content[end:]
    if after.startswith("\n"):
        after = after[1:]
    new_content = content[:begin].rstrip() + ("\n" + after if after.strip() else "\n")
    if new_content.strip() in {"", "#!/bin/sh"}:
        # Would leave an empty hook — remove file if it only had our block
        only_ours = content.replace(HOOK_BODY, "").replace("#!/bin/sh", "").strip()
        if not only_ours:
            hook_path.unlink()
            return True
    hook_path.write_text(new_content, encoding="utf-8")
    return True


def is_installed(cwd: Path | None = None) -> bool:
    try:
        ensure_repo(cwd)
        hook_dir = hooks_path(cwd)
    except GitError:
        return False
    hook_path = hook_dir / "pre-commit"
    if not hook_path.is_file():
        return False
    return _has_markers(hook_path.read_text(encoding="utf-8", errors="replace"))


def _ensure_executable(path: Path) -> None:
    try:
        mode = path.stat().st_mode
        path.chmod(mode | 0o111)
    except OSError:
        pass
