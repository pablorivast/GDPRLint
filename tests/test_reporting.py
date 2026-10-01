"""Redaction guarantees and machine-readable report formats."""

import io
import json

from gdprlint.finding import CommitDecision, Finding
from gdprlint.redact import mask_digits, redact_email, redact_secret
from gdprlint.reporting import render


def test_redact_secret_hides_middle():
    secret = "sk-proj-123456789abcdefghijklmnop9f2a"
    out = redact_secret(secret)
    assert out != secret
    assert "123456789abcdefghijklmnop" not in out
    assert out.startswith(("sk-proj-", "sk-"))
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


def _decision(findings: list[Finding], *, action: str = "allow_warn") -> CommitDecision:
    return CommitDecision(
        action=action,
        exit_code=1 if action == "block" else 0,
        reasons=[],
        privacy_notes=[],
        findings=findings,
        files_scanned=3,
        laya_available=True,
    )


def test_render_json_report_structure():
    findings = [
        _f("SECRET.API_KEY", "secret", "high", 1).with_laya(decision="block"),
        _f("PII.EMAIL", "pii", "likely", 2).with_laya(decision="warn"),
    ]
    buf = io.StringIO()
    render(_decision(findings, action="block"), buf, fmt="json")
    data = json.loads(buf.getvalue())

    assert data["schema"] == "gdprlint/report/v1"
    assert data["tool"]["name"] == "gdprlint"
    assert data["action"] == "block"
    assert data["blocked"] is True
    assert data["exit_code"] == 1
    assert data["counts"]["total"] == 2
    assert data["counts"]["blocking"] == 1
    assert data["counts"]["secret"] == 1
    assert data["counts"]["pii"] == 1
    rules = {item["rule"] for item in data["findings"]}
    assert rules == {"SECRET.API_KEY", "PII.EMAIL"}
    assert "does not certify legal or GDPR compliance" in data["disclaimer"]


def test_render_json_never_prints_human_report():
    findings = [_f("SECURITY.EVAL", "security", "likely", 1).with_laya(decision="warn")]
    buf = io.StringIO()
    render(_decision(findings), buf, fmt="json")
    out = buf.getvalue()
    assert "Commit allowed." not in out
    assert json.loads(out)["action"] == "allow_warn"


def test_render_sarif_structure_and_levels():
    findings = [
        _f("SECRET.API_KEY", "secret", "high", 10).with_laya(decision="block"),
        _f("SECURITY.EVAL", "security", "likely", 20).with_laya(decision="warn"),
        _f("PII.PHONE", "pii", "possible", 30).with_laya(decision="suppress_fp"),
    ]
    buf = io.StringIO()
    render(_decision(findings, action="block"), buf, fmt="sarif")
    data = json.loads(buf.getvalue())

    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "GDPRLint"
    rule_ids = [r["id"] for r in driver["rules"]]
    # Suppressed findings do not define rules or results
    assert sorted(rule_ids) == ["SECRET.API_KEY", "SECURITY.EVAL"]

    results = {r["ruleId"]: r for r in run["results"]}
    assert results["SECRET.API_KEY"]["level"] == "error"
    assert results["SECURITY.EVAL"]["level"] == "warning"
    assert "PII.PHONE" not in results
    loc = results["SECRET.API_KEY"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "a.py"
    assert loc["region"]["startLine"] == 10


def test_render_sarif_rules_deduplicated():
    findings = [
        _f("PII.EMAIL", "pii", "high", 1).with_laya(decision="warn"),
        _f("PII.EMAIL", "pii", "likely", 2).with_laya(decision="warn"),
    ]
    buf = io.StringIO()
    render(_decision(findings), buf, fmt="sarif")
    data = json.loads(buf.getvalue())
    driver = data["runs"][0]["tool"]["driver"]
    assert len(driver["rules"]) == 1
    assert len(data["runs"][0]["results"]) == 2


def test_render_default_format_is_text():
    findings = [_f("SECURITY.EVAL", "security", "likely", 1).with_laya(decision="warn")]
    buf = io.StringIO()
    render(_decision(findings), buf)
    assert "GDPRLint" in buf.getvalue()
