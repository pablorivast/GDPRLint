"""Redaction guarantees — full secrets must never appear in evidence."""

from laya_guard.redact import mask_digits, redact_email, redact_secret


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
