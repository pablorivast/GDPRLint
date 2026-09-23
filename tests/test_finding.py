"""Finding model unit tests."""

from laya_guard.finding import (
    Category,
    Confidence,
    Decision,
    Finding,
    Severity,
    confidence_rank,
)


def make(**kwargs) -> Finding:
    base = dict(
        rule="SECRET.API_KEY",
        category=Category.SECRET.value,
        severity=Severity.HIGH.value,
        confidence=Confidence.HIGH.value,
        file="src/config.js",
        line=42,
        message="Potential API credential detected.",
        remediation="Move to env var.",
        evidence="sk-test-****abcd",
        related_articles=("5.1.f", "32"),
    )
    base.update(kwargs)
    return Finding(**base)


def test_to_dict_serializes_articles_as_list():
    d = make().to_dict()
    assert d["related_articles"] == ["5.1.f", "32"]
    assert d["rule"] == "SECRET.API_KEY"


def test_with_laya_preserves_identity_fields():
    f = make().with_laya(true_positive=True, risk="high", confidence=0.9)
    assert f.laya_true_positive is True
    assert f.laya_risk == "high"
    assert f.laya_confidence == 0.9
    assert f.rule == "SECRET.API_KEY"
    assert f.related_articles == ("5.1.f", "32")


def test_confidence_rank_ordering():
    assert confidence_rank(Confidence.POSSIBLE) < confidence_rank(Confidence.LIKELY)
    assert confidence_rank(Confidence.LIKELY) < confidence_rank(Confidence.HIGH)
    assert confidence_rank("high") == 2


def test_decision_values_are_stable():
    assert Decision.BLOCK.value == "block"
    assert Decision.SUPPRESS_FP.value == "suppress_fp"
