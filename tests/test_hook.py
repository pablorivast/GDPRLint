"""Hook install/uninstall behaviour."""

from pathlib import Path

from laya_guard.hook import (
    BEGIN_MARK,
    END_MARK,
    HOOK_BODY,
    install_hook,
    is_installed,
    uninstall_hook,
)


def test_install_creates_executable_hook(git_repo: Path):
    path = install_hook(git_repo)
    assert path.name == "pre-commit"
    assert path.is_file()
    content = path.read_text(encoding="utf-8")
    assert BEGIN_MARK in content
    assert END_MARK in content
    assert path.stat().st_mode & 0o111


def test_install_idempotent(git_repo: Path):
    p1 = install_hook(git_repo)
    c1 = p1.read_text(encoding="utf-8")
    p2 = install_hook(git_repo)
    c2 = p2.read_text(encoding="utf-8")
    assert c1 == c2
    assert c2.count(BEGIN_MARK) == 1


def test_install_appends_to_existing_hook(git_repo: Path):
    hooks = git_repo / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    existing = hooks / "pre-commit"
    existing.write_text("#!/bin/sh\necho custom-hook\n", encoding="utf-8")
    path = install_hook(git_repo)
    content = path.read_text(encoding="utf-8")
    assert "echo custom-hook" in content
    assert BEGIN_MARK in content
    # custom content comes first
    assert content.index("echo custom-hook") < content.index(BEGIN_MARK)


def test_uninstall_removes_managed_block(git_repo: Path):
    install_hook(git_repo)
    assert is_installed(git_repo)
    assert uninstall_hook(git_repo) is True
    # Either file removed or markers gone
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    if hook.exists():
        assert BEGIN_MARK not in hook.read_text(encoding="utf-8")
    assert not is_installed(git_repo)


def test_uninstall_keeps_foreign_hook(git_repo: Path):
    hooks = git_repo / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    existing = hooks / "pre-commit"
    existing.write_text("#!/bin/sh\necho keep-me\n", encoding="utf-8")
    install_hook(git_repo)
    assert uninstall_hook(git_repo) is True
    content = existing.read_text(encoding="utf-8")
    assert "keep-me" in content
    assert BEGIN_MARK not in content


def test_hook_exports_quiet_env_vars():
    assert "HF_HUB_DISABLE_PROGRESS_BARS=1" in HOOK_BODY
    assert "TQDM_DISABLE=1" in HOOK_BODY
    assert "TRANSFORMERS_VERBOSITY=error" in HOOK_BODY
