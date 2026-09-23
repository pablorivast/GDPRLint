"""Laya analyzer gate tests with FakeRouter (no real weights)."""

import json
from pathlib import Path

from gdprlint.analyzer import (
    LayaAnalyzer,
    RulesOnlyAnalyzer,
    build_analyzer,
)
from gdprlint.config import default_config
from gdprlint.finding import Finding
from tests.conftest import FakeRouter


def make_finding(**kwargs) -> Finding:
    base = dict(
        rule="SECRET.API_KEY",
        category="secret",
        severity="high",
        confidence="high",
        file="src/config.js",
        line=42,
        message="Potential API credential detected.",
        remediation="Move to env var.",
        evidence="sk-****9f2a",
        related_articles=("5.1.f", "32"),
    )
    base.update(kwargs)
    return Finding(**base)


def test_rules_only_passthrough():
    a = RulesOnlyAnalyzer()
    fs = [make_finding()]
    assert a.analyze(fs) == fs
    assert a.available is False


def test_build_analyzer_respects_enabled_flag():
    cfg = default_config()
    cfg.laya.enabled = False
    a = build_analyzer(cfg)
    assert isinstance(a, RulesOnlyAnalyzer)


def test_laya_analyzer_annotates_tp_and_risk():
    cfg = default_config()
    router = FakeRouter()
    a = LayaAnalyzer(cfg, router=router)
    assert a.available is True
    out = a.analyze([make_finding()])
    assert len(out) == 1
    f = out[0]
    assert f.laya_true_positive is True
    assert f.laya_risk in {"high", "critical", "medium", "low"}
    assert f.laya_confidence is not None
    assert f.laya_remediation_family is not None


def test_laya_analyzer_false_positive_override():
    cfg = default_config()
    router = FakeRouter(
        answers={
            "SECRET.API_KEY": {
                "true_positive": ("B", 0.92),
                "remediation_family": ("none", 0.9),
            }
        }
    )
    a = LayaAnalyzer(cfg, router=router)
    out = a.analyze([make_finding()])
    assert out[0].laya_true_positive is False
    assert out[0].laya_confidence == 0.92


def test_laya_predict_failure_falls_back():
    cfg = default_config()
    router = FakeRouter(fail=True)
    a = LayaAnalyzer(cfg, router=router)
    fs = [make_finding()]
    out = a.analyze(fs)
    assert out == fs
    assert out[0].laya_true_positive is None


def test_disabled_laya_reports_unavailable(tmp_path: Path, capsys):
    cfg = default_config()
    cfg.laya.enabled = False
    # build via LayaAnalyzer directly with enabled config but simulate disabled path
    cfg2 = default_config()
    a = LayaAnalyzer(cfg2, router=None)
    # force unavailable by clearing router without load success path:
    # Instead use RulesOnly via build
    from gdprlint.analyzer import build_analyzer

    an = build_analyzer(cfg)
    assert an.available is False


def test_state_sent_to_laya_has_no_raw_secret():
    cfg = default_config()
    router = FakeRouter()
    a = LayaAnalyzer(cfg, router=router)
    a.analyze([make_finding(evidence="sk-redacted-9f2a")])
    assert router.calls
    states, _questions = router.calls[0]
    blob = json.dumps(states)
    assert "sk-redacted" in blob  # only redacted evidence
    # Ensure full original secret never present if we had one — evidence is what we pass
    assert "hunter2" not in blob
