"""CLI scan modes: --all (whole worktree) and --history (revision range)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import _git, run_cli, stage_file, stage_modified

# 36-char body after ghp_ → high-confidence SECRET.GITHUB_TOKEN
SECRET = "ghp_1234567890abcdefghij1234567890abcdef"


def test_scan_all_detects_untracked_secret(git_repo: Path):
    (git_repo / "leak.js").write_text(f'token = "{SECRET}";\n', encoding="utf-8")

    # Default (staged) mode sees nothing: no staged changes
    code, _out, _err = run_cli(["scan", "--no-laya"], git_repo)
    assert code == 0

    code, out, _err = run_cli(["scan", "--all", "--no-laya"], git_repo)
    assert code == 1
    assert "Commit blocked." in out
    assert SECRET not in out


def test_scan_all_respects_default_excludes(git_repo: Path):
    # Control: same secret in a normal file is blocked
    (git_repo / "bundle.js").write_text(f'var k = "{SECRET}";\n', encoding="utf-8")
    code, _out, _err = run_cli(["scan", "--all", "--no-laya"], git_repo)
    assert code == 1

    (git_repo / "bundle.js").unlink()
    # Default exclude pattern **/*.min.js skips the minified bundle
    (git_repo / "bundle.min.js").write_text(f'var k = "{SECRET}";\n', encoding="utf-8")
    code, _out, _err = run_cli(["scan", "--all", "--no-laya"], git_repo)
    assert code == 0


def test_scan_all_skips_binary_files(git_repo: Path):
    (git_repo / "blob.bin").write_bytes(
        b"\x00\x01\x02" + f'token = "{SECRET}";'.encode()
    )
    code, out, _err = run_cli(["scan", "--all", "--no-laya"], git_repo)
    assert code == 0
    assert "Commit allowed." in out


def test_scan_all_skips_oversized_files(git_repo: Path):
    padding = "a" * (1_048_576 + 64)
    (git_repo / "big.txt").write_text(
        f"{padding}\ntoken = \"{SECRET}\";\n", encoding="utf-8"
    )
    code, _out, _err = run_cli(["scan", "--all", "--no-laya"], git_repo)
    assert code == 0


def test_scan_all_json_reports_mode(git_repo: Path):
    (git_repo / "leak.js").write_text(f'token = "{SECRET}";\n', encoding="utf-8")
    code, out, _err = run_cli(["scan", "--all", "--no-laya", "--format", "json"], git_repo)
    data = json.loads(out)
    assert data["mode"] == "all"
    assert code == 1
    assert data["blocked"] is True


def _commit_pair_with_secret(git_repo: Path) -> None:
    stage_file(git_repo, "app.py", "def ok():\n    return 1\n")
    _git(git_repo, "commit", "-q", "-m", "feat: clean")
    stage_modified(git_repo, "app.py", f'token = "{SECRET}"\n')
    _git(git_repo, "commit", "-q", "-m", "feat: leak")


def test_scan_history_detects_secret_in_range(git_repo: Path):
    _commit_pair_with_secret(git_repo)

    code, out, _err = run_cli(
        ["scan", "--history", "HEAD~1..HEAD", "--no-laya"], git_repo
    )
    assert code == 1
    assert "Commit blocked." in out
    assert SECRET not in out

    # Nothing staged right now → default mode stays quiet
    code, _out, _err = run_cli(["scan", "--no-laya"], git_repo)
    assert code == 0


def test_scan_history_json_reports_mode(git_repo: Path):
    _commit_pair_with_secret(git_repo)
    code, out, _err = run_cli(
        ["scan", "--history", "HEAD~1..HEAD", "--no-laya", "--format", "json"],
        git_repo,
    )
    data = json.loads(out)
    assert data["mode"] == "history"
    assert code == 1


def test_scan_history_clean_range_allowed(git_repo: Path):
    stage_file(git_repo, "app.py", "def ok():\n    return 1\n")
    _git(git_repo, "commit", "-q", "-m", "feat: one")
    stage_modified(git_repo, "app.py", "def ok():\n    return 2\n")
    _git(git_repo, "commit", "-q", "-m", "feat: two")

    code, out, _err = run_cli(
        ["scan", "--history", "HEAD~1..HEAD", "--no-laya"], git_repo
    )
    assert code == 0
    assert "Commit allowed." in out


def test_scan_history_invalid_range_errors(git_repo: Path):
    code, _out, err = run_cli(
        ["scan", "--history", "HEAD~999..HEAD", "--no-laya"], git_repo
    )
    assert code == 2
    assert "git error" in err.lower()


def test_scan_history_rejects_option_like_range(git_repo: Path):
    code, _out, err = run_cli(["scan", "--history=-p", "--no-laya"], git_repo)
    assert code == 2
    assert "invalid revision range" in err


def test_scan_all_and_history_are_mutually_exclusive(git_repo: Path):
    with pytest.raises(SystemExit) as exc:
        run_cli(["scan", "--all", "--history", "HEAD"], git_repo)
    assert exc.value.code == 2


def test_scan_all_works_outside_git_repository(tmp_path: Path):
    (tmp_path / "leak.js").write_text(f'token = "{SECRET}";\n', encoding="utf-8")

    # Plain staged mode still requires a repository
    code, _out, err = run_cli(["scan", "--no-laya"], tmp_path)
    assert code == 2
    assert "git error" in err.lower() or "not a git" in err.lower()

    code, out, _err = run_cli(["scan", "--all", "--no-laya"], tmp_path)
    assert code == 1
    assert "Commit blocked." in out
    assert SECRET not in out


def test_scan_all_honors_gitignore_outside_git(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("leak.js\n", encoding="utf-8")
    (tmp_path / "leak.js").write_text(f'token = "{SECRET}";\n', encoding="utf-8")

    code, out, _err = run_cli(["scan", "--all", "--no-laya"], tmp_path)
    assert code == 0
    assert "Commit allowed." in out


def test_scan_all_json_reports_mode_outside_git(tmp_path: Path):
    (tmp_path / "leak.js").write_text(f'token = "{SECRET}";\n', encoding="utf-8")
    code, out, _err = run_cli(
        ["scan", "--all", "--no-laya", "--format", "json"], tmp_path
    )
    data = json.loads(out)
    assert data["mode"] == "all"
    assert code == 1
    assert data["blocked"] is True
