"""Redaction guarantees — full secrets must never appear in evidence."""

import io

from gdprlint.finding import CommitDecision, Finding
from gdprlint.redact import mask_digits, redact_email, redact_secret
from gdprlint.reporting import render


def test_redact_secret_hides_middle():
    secret = "sk-proj-123456789abcdefghijklmnop9f2a"
    out = redact_secret(secret)
    assert out != secret
    assert "123456789abcdefghijklmnop" not in out
    assert out.startswith("sk-proj-") or out.startswith("sk-")
    assert out.endswith("9f2a") or "****" in out


def test_redact_secret_short_values():
    assert redact_secret("abc") == "****" or "*" in redact_secret("abc")
    assert redact_secret("") == ""


def test_redact_email_masks():
    out = redact_email("maria.garcia@example.com")
    assert "maria.garcia" not in out
    assert "@" in out


def test_mask_digits_hides_most():
    out = mask_digits("ES9121000418450200051332")
    assert "0418450200051332" not in out
    assert "*" in out


def test_mask_digits_keeps_structure_length_sane():
    out = mask_digits("12345678Z")
    assert len(out) >= 4
    assert out != "12345678Z" or "*" in out


def _f(rule: str, category: str, conf: str, line: int = 1) -> Finding:
    return Finding(
        rule=rule,
        category=category,
        severity="low",
        confidence=conf,
        file="a.py",
        line=line,
        message=f"{rule} hit",
        remediation="fix it.",
        evidence="****",
        related_articles=(),
    )


def test_render_additional_warnings_count():
    findings = [
        _f("PII.EMAIL", "pii", "high", 1),
        _f("PII.LOG_PII", "pii", "likely", 2),
        _f("PII.PHONE", "pii", "likely", 3),
        _f("SECURITY.EVAL", "security", "likely", 4),
    ]
    findings = [f.with_laya(decision="warn") for f in findings]
    d = CommitDecision(
        action="allow_warn",
        exit_code=0,
        reasons=[],
        privacy_notes=[],
        findings=findings,
        files_scanned=3,
        laya_available=True,
    )
    buf = io.StringIO()
    render(d, buf)
    out = buf.getvalue()
    assert "✓ 1 high-confidence PII findings" in out
    assert "✓ 2 additional warnings" in out
    assert "✓ 1 security findings" in out
    assert "Commit allowed." in out
