"""Git staged-diff parsing tests against a real temporary repository."""

from pathlib import Path

from gdprlint.git_ops import (
    ensure_repo,
    get_staged_diff,
    parse_staged_diff,
    staged_file_count,
)
from tests.conftest import _git


def test_ensure_repo_on_real_repo(git_repo: Path):
    assert ensure_repo(git_repo) == git_repo.resolve()


def test_only_added_lines_are_scanned(git_repo: Path, stage):
    stage("code.txt", "line1\nline2\nline3\n")
    diff = get_staged_diff(git_repo)
    assert "code.txt" in diff.files
    texts = [ln.text for ln in diff.added_lines if ln.path == "code.txt"]
    assert texts == ["line1", "line2", "line3"]
    assert [ln.line_no for ln in diff.added_lines if ln.path == "code.txt"] == [1, 2, 3]


def test_modified_file_only_new_lines(git_repo: Path, stage):
    stage("app.py", "alpha\nbeta\ngamma\n")
    _git(git_repo, "commit", "-q", "-m", "base app")
    stage("app.py", "alpha\nbeta2\ngamma\n")
    diff = get_staged_diff(git_repo)
    added = [(ln.line_no, ln.text) for ln in diff.added_lines if ln.path == "app.py"]
    # Only line 2 changed relative to HEAD
    assert added == [(2, "beta2")]


def test_new_file_full_content_staged(git_repo: Path, stage):
    stage("src/new.js", "const a = 1;\nconst b = 2;\n")
    diff = get_staged_diff(git_repo)
    assert "src/new.js" in diff.files
    assert len([x for x in diff.added_lines if x.path == "src/new.js"]) == 2


def test_deleted_file_not_in_diff_filter(git_repo: Path):
    (git_repo / "gone.txt").write_text("x\n", encoding="utf-8")
    _git(git_repo, "add", "gone.txt")
    _git(git_repo, "commit", "-q", "-m", "add gone")
    _git(git_repo, "rm", "-q", "gone.txt")
    diff = get_staged_diff(git_repo)
    assert not any(ln.path == "gone.txt" for ln in diff.added_lines)
    assert "gone.txt" not in diff.files  # --diff-filter=ACMR excludes D


def test_unstaged_changes_are_ignored(git_repo: Path, stage):
    stage("tracked.txt", "hello\n")
    (git_repo / "unstaged.txt").write_text("secret_should_not_appear\n", encoding="utf-8")
    diff = get_staged_diff(git_repo)
    assert not any("unstaged" in ln.path for ln in diff.added_lines)
    assert not any("secret_should_not_appear" in ln.text for ln in diff.added_lines)


def test_parse_hunk_line_numbers():
    raw = """diff --git a/f.txt b/f.txt
index 111..222 100644
--- a/f.txt
+++ b/f.txt
@@ -10,0 +11,2 @@
+added-one
+added-two
"""
    diff = parse_staged_diff(raw)
    assert diff.files == ["f.txt"]
    assert [(x.line_no, x.text) for x in diff.added_lines] == [
        (11, "added-one"),
        (12, "added-two"),
    ]


def test_staged_file_count(git_repo: Path, stage):
    stage("a.txt", "1\n")
    stage("b/c.txt", "2\n")
    diff = get_staged_diff(git_repo)
    assert staged_file_count(diff) == 2
