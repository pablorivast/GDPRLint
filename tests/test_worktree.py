"""Git-free worktree walking (.gitignore support for ``scan --all``)."""

from __future__ import annotations

from pathlib import Path

from gdprlint.worktree import MAX_SCAN_FILE_BYTES, scan_root, walk_worktree


def test_scan_root_uses_git_directory_marker(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    sub = repo / "src" / "pkg"
    sub.mkdir(parents=True)
    assert scan_root(sub) == repo


def test_scan_root_accepts_git_file_marker(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")
    sub = repo / "a" / "b"
    sub.mkdir(parents=True)
    assert scan_root(sub) == repo


def test_scan_root_without_git_returns_cwd(tmp_path: Path):
    plain = tmp_path / "plain"
    nested = plain / "nested"
    nested.mkdir(parents=True)
    assert scan_root(nested) == nested
    assert scan_root(plain) == plain


def test_scan_root_normalizes_relative_input(tmp_path: Path, monkeypatch):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)
    root = scan_root(Path("."))
    assert root.is_absolute()
    assert root == Path.cwd()


def test_walk_lists_files_relative_to_root(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "app.py").write_text("line one\nline two\n", encoding="utf-8")
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "mod.py").write_text("nested\n", encoding="utf-8")

    result = walk_worktree(tmp_path)
    assert result.files == ["app.py", "src/mod.py"]
    lines = {(ln.path, ln.line_no): ln.text for ln in result.added_lines}
    assert lines[("app.py", 2)] == "line two"
    assert lines[("src/mod.py", 1)] == "nested"


def test_walk_from_subdir_scans_from_repo_root(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("a\n", encoding="utf-8")
    (repo / "docs").mkdir()
    (repo / "docs" / "b.md").write_text("b\n", encoding="utf-8")

    result = walk_worktree(repo / "src")
    assert result.files == ["docs/b.md", "src/a.py"]


def test_root_gitignore_excludes_files_and_directories(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("*.log\nbuild/\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("ok\n", encoding="utf-8")
    (tmp_path / "debug.log").write_text("noise\n", encoding="utf-8")
    build = tmp_path / "build"
    build.mkdir()
    (build / "out.js").write_text('var k = "sk-x";\n', encoding="utf-8")

    result = walk_worktree(tmp_path)
    assert "app.py" in result.files
    assert "debug.log" not in result.files
    assert "build/out.js" not in result.files


def test_gitignore_negation_reincludes_a_file(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("*.log\n!keep.log\n", encoding="utf-8")
    (tmp_path / "keep.log").write_text("keep me\n", encoding="utf-8")
    (tmp_path / "drop.log").write_text("drop me\n", encoding="utf-8")

    result = walk_worktree(tmp_path)
    assert "keep.log" in result.files
    assert "drop.log" not in result.files


def test_nested_gitignore_overrides_root(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("*.log\n", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / ".gitignore").write_text("!special.log\n", encoding="utf-8")
    (sub / "special.log").write_text("nested exception\n", encoding="utf-8")
    (sub / "other.log").write_text("still ignored\n", encoding="utf-8")
    (tmp_path / "top.log").write_text("root level\n", encoding="utf-8")

    result = walk_worktree(tmp_path)
    assert "sub/special.log" in result.files
    assert "sub/other.log" not in result.files
    assert "top.log" not in result.files


def test_git_directory_never_scanned(tmp_path: Path):
    gitdir = tmp_path / ".git"
    gitdir.mkdir()
    (gitdir / "secret.txt").write_text("ghp_never_see_me\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("ok\n", encoding="utf-8")

    result = walk_worktree(tmp_path)
    assert result.files == ["app.py"]


def test_git_file_marker_never_scanned(tmp_path: Path):
    (tmp_path / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("ok\n", encoding="utf-8")

    result = walk_worktree(tmp_path)
    assert result.files == ["app.py"]


def test_walk_applies_config_excludes(tmp_path: Path):
    (tmp_path / "bundle.min.js").write_text("minified\n", encoding="utf-8")
    (tmp_path / "bundle.js").write_text("source\n", encoding="utf-8")

    result = walk_worktree(tmp_path, is_excluded=lambda p: p.endswith(".min.js"))
    assert "bundle.min.js" not in result.files
    assert "bundle.js" in result.files


def test_walk_skips_binary_and_oversized_files(tmp_path: Path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01payload\n")
    (tmp_path / "big.txt").write_text("a" * (MAX_SCAN_FILE_BYTES + 1), encoding="utf-8")
    (tmp_path / "ok.txt").write_text("hello\n", encoding="utf-8")

    result = walk_worktree(tmp_path)
    assert "blob.bin" in result.files
    assert "blob.bin" in result.binary_files
    assert "big.txt" in result.files
    assert {ln.path for ln in result.added_lines} == {"ok.txt"}


def test_walk_output_is_deterministically_sorted(tmp_path: Path):
    (tmp_path / "z.txt").write_text("z\n", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    mid = tmp_path / "m"
    mid.mkdir()
    (mid / "n.txt").write_text("n\n", encoding="utf-8")

    first = walk_worktree(tmp_path)
    second = walk_worktree(tmp_path)
    assert first.files == second.files
    assert first.files == ["a.txt", "m/n.txt", "z.txt"]
    assert [(ln.path, ln.line_no) for ln in first.added_lines] == [
        ("a.txt", 1),
        ("m/n.txt", 1),
        ("z.txt", 1),
    ]
