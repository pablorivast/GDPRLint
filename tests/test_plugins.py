"""Third-party scanners contributed via the ``gdprlint.scanners`` entry-point group."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import gdprlint.scanners as scanners_pkg
from gdprlint.config import ConfigError, default_config, load_config_file
from gdprlint.engine import run_scanners
from gdprlint.finding import Finding
from gdprlint.git_ops import AddedLine, StagedDiff
from gdprlint.scanners import Scanner, load_plugin_scanners


class MarkerScanner(Scanner):
    category = "security"

    def scan_line(self, file: str, line_no: int, text: str) -> list[Finding]:
        if "PLUGIN_MARKER" in text:
            return [
                Finding(
                    rule="PLUGIN.MARKER",
                    category="security",
                    severity="high",
                    confidence="high",
                    file=file,
                    line=line_no,
                    message="plugin marker hit",
                    remediation="remove the marker",
                )
            ]
        return []


class ExplodingScanner:
    def __init__(self) -> None:
        raise RuntimeError("boom")


def _ep(name: str, loader) -> SimpleNamespace:
    return SimpleNamespace(name=name, load=loader)


def _patch_eps(monkeypatch, eps: list) -> None:
    monkeypatch.setattr(scanners_pkg, "entry_points", lambda *, group: eps)


def _diff() -> StagedDiff:
    return StagedDiff(
        files=["app.py"],
        added_lines=[AddedLine(path="app.py", line_no=1, text="PLUGIN_MARKER = 1")],
    )


def test_plugins_must_be_boolean(tmp_path):
    path = tmp_path / ".gdprlint.json"
    path.write_text(json.dumps({"plugins": "yes"}), encoding="utf-8")
    with pytest.raises(ConfigError, match="plugins"):
        load_config_file(path)


def test_loads_entry_point_scanner(monkeypatch):
    _patch_eps(monkeypatch, [_ep("marker", lambda: MarkerScanner)])
    loaded = load_plugin_scanners()
    assert len(loaded) == 1
    assert isinstance(loaded[0], MarkerScanner)


def test_loads_already_instantiated_scanner(monkeypatch):
    _patch_eps(monkeypatch, [_ep("marker", MarkerScanner)])
    loaded = load_plugin_scanners()
    assert len(loaded) == 1
    assert isinstance(loaded[0], MarkerScanner)


def test_broken_plugin_warns_and_is_skipped(monkeypatch, capsys):
    _patch_eps(
        monkeypatch,
        [
            _ep("bad", lambda: ExplodingScanner),
            _ep("marker", lambda: MarkerScanner),
        ],
    )
    loaded = load_plugin_scanners()
    assert len(loaded) == 1
    err = capsys.readouterr().err
    assert "bad" in err
    assert "boom" in err


def test_plugin_returning_non_scanner_warns(monkeypatch, capsys):
    _patch_eps(monkeypatch, [_ep("junk", lambda: 42)])
    assert load_plugin_scanners() == []
    assert "junk" in capsys.readouterr().err


def test_broken_entry_point_metadata_is_isolated(monkeypatch):
    def boom(*, group: str):
        raise RuntimeError("corrupt metadata")

    monkeypatch.setattr(scanners_pkg, "entry_points", boom)
    assert load_plugin_scanners() == []


def test_scan_includes_plugin_findings(monkeypatch):
    _patch_eps(monkeypatch, [_ep("marker", lambda: MarkerScanner)])
    cfg = default_config()
    findings, files_scanned = run_scanners(_diff(), cfg)
    assert files_scanned == 1
    assert "PLUGIN.MARKER" in [f.rule for f in findings]


def test_scan_skips_plugins_when_disabled(monkeypatch):
    calls: list[str] = []

    def tracking_eps(*, group: str):
        calls.append(group)
        return [_ep("marker", lambda: MarkerScanner)]

    monkeypatch.setattr(scanners_pkg, "entry_points", tracking_eps)
    cfg = default_config()
    cfg.plugins = False
    findings, _ = run_scanners(_diff(), cfg)
    assert calls == []
    assert "PLUGIN.MARKER" not in [f.rule for f in findings]
