"""Packaging sanity checks: hook manifest, typed package, version source."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_pre_commit_hook_manifest():
    path = REPO_ROOT / ".pre-commit-hooks.yaml"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    # The hook must run a full scan of the staged diff, never per-file:
    # pre-commit passes staged filenames otherwise.
    assert "- id: gdprlint" in text
    assert "entry: gdprlint scan" in text
    assert "language: python" in text
    assert "pass_filenames: false" in text
    assert "stages: [pre-commit]" in text
