"""Packaging sanity checks: hook manifest, typed package, version source."""

from __future__ import annotations

import re
from pathlib import Path

import gdprlint

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


def test_version_is_single_sourced():
    """pyproject must read the version from gdprlint.__version__."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text
    assert 'version = { attr = "gdprlint.__version__" }' in text
    assert re.fullmatch(r"\d+\.\d+\.\d+", gdprlint.__version__), gdprlint.__version__


def test_readme_version_badge_matches():
    """The README version badge must carry the current package version."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert f"version-{gdprlint.__version__}-" in readme


def test_pre_commit_snippet_rev_matches_version():
    """Documented pre-commit pins must match the current version tag."""
    pattern = rf"rev: v{re.escape(gdprlint.__version__)}\b"
    for name in ("README.md", ".pre-commit-hooks.yaml"):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert re.search(pattern, text), name


def test_py_typed_ships_with_the_package():
    assert (Path(gdprlint.__file__).with_name("py.typed")).is_file()
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'gdprlint = ["py.typed"]' in text


def test_project_metadata_is_release_ready():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    # PEP 639 SPDX expression instead of the deprecated table form
    assert 'license = "Apache-2.0"' in text
    assert "license = { text" not in text
    assert "[project.urls]" in text
    assert "Repository =" in text
    assert "Changelog =" in text
