"""Shared fixtures: temporary git repos and staged content."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
        env={
            **dict(**{k: v for k, v in __import__("os").environ.items()}),
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        },
    )
    return proc.stdout


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Initialized git repository with an initial commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "README.md").write_text("# fixture repo\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "chore: init")
    return repo


def stage_file(repo: Path, relative: str, content: str) -> Path:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", relative)
    return path


def stage_modified(repo: Path, relative: str, content: str) -> Path:
    path = repo / relative
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", relative)
    return path


@pytest.fixture
def stage(git_repo: Path):
    def _stage(relative: str, content: str) -> Path:
        if (git_repo / relative).exists():
            return stage_modified(git_repo, relative, content)
        return stage_file(git_repo, relative, content)

    return _stage


class FakeRouter:
    """Deterministic stand-in for Laya Router in unit tests."""

    def __init__(self, answers: dict | None = None, *, fail: bool = False) -> None:
        self.answers = answers or {}
        self.fail = fail
        self.calls: list[tuple] = []

    def predict_batch(self, states, questions, **kwargs):
        self.calls.append((states, questions))
        if self.fail:
            raise RuntimeError("boom")
        return [self._result(s) for s in states]

    def predict(self, state, questions, **kwargs):
        self.calls.append(([state], questions))
        if self.fail:
            raise RuntimeError("boom")
        return self._result(state)

    def _result(self, state) -> dict:
        # Default: genuine high-risk secret unless overridden by rule
        rule = state.get("rule", "")
        defaults = {
            "true_positive": ("A", 0.95),
            "risk_level": ("high", 0.9),
            "data_nature": ("B", 0.85),
            "breach_amplifier": ("A", 0.88),
            "remediation_family": ("remove", 0.9),
            "dpia_signal": ("B", 0.8),
        }
        # Allow per-rule overrides via self.answers {rule: {q: (label, conf)}}
        overrides = self.answers.get(rule, {})
        answers = {}
        for q, (label, conf) in defaults.items():
            lab, c = overrides.get(q, (label, conf))
            answers[q] = {"choice": lab, "confidence": c}
        return {"answers": answers}
