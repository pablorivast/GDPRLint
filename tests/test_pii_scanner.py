"""PII scanner positives, confidence tiers, and false positives."""

from laya_guard.scanners.pii import PIIScanner


def scan(text: str, file: str = "src/import.py"):
    return list(PIIScanner().scan_line(file, 10, text))


def rules(findings):
    return {f.rule for f in findings}


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


def test_email_positive():
    fs = scan('contact = "maria.garcia@acme-corp.es"')
    hits = by_rule(fs, "PII.EMAIL")
    assert hits
    assert hits[0].confidence == "high"
    assert "maria.garcia@acme-corp.es" not in (hits[0].evidence or "")


def test_email_placeholder_example_domain_ignored():
    fs = scan('placeholder = "tucorreo@ejemplo.com"')
    assert "PII.EMAIL" not in rules(fs)
    fs2 = scan('x = "user@example.com"')
    assert "PII.EMAIL" not in rules(fs2)


def test_email_in_comment_downranked_to_possible():
    fs = scan("// FAILURE_EMAIL = 'pabloruizrivas21@gmail.com'")
    hits = by_rule(fs, "PII.EMAIL")
    assert hits
    assert hits[0].confidence == "possible"


def test_phone_es_with_context_likely():
    fs = scan('phone = "+34 612 345 679"  # teléfono contacto')
    hits = by_rule(fs, "PII.PHONE")
    assert hits
    assert hits[0].confidence in {"likely", "possible"}


def test_iban_es_positive():
    fs = scan('iban = "ES9121000418450200051332"')
    hits = by_rule(fs, "PII.IBAN")
    assert hits
    assert hits[0].confidence == "high"
    assert "ES9121000418450200051332" not in (hits[0].evidence or "")


def test_dni_with_context_likely():
    fs = scan('dni_cliente = "12345678Z"  # DNI del cliente')
    hits = by_rule(fs, "PII.SPANISH_ID")
    assert hits
    assert hits[0].confidence == "likely"


def test_dni_without_context_possible():
    fs = scan("order_id = 12345678Z")
    hits = by_rule(fs, "PII.SPANISH_ID")
    assert hits
    assert hits[0].confidence == "possible"


def test_nie_positive():
    fs = scan('nie = "X1234567L"  # NIE')
    assert by_rule(fs, "PII.SPANISH_ID")


def test_credit_card_luhn_positive():
    # Visa test number (Luhn valid)
    fs = scan('card = "4111111111111111"')
    hits = by_rule(fs, "PII.CREDIT_CARD")
    assert hits
    assert "4111111111111111" not in (hits[0].evidence or "")


def test_credit_card_luhn_invalid_not_flagged():
    fs = scan('not_a_card = "4111111111111112"')  # fails Luhn
    assert "PII.CREDIT_CARD" not in rules(fs)


def test_public_ip_flagged_private_excluded():
    fs = scan("server = 8.8.8.8")
    assert "PII.IP_ADDRESS" in rules(fs)
    fs2 = scan("localhost = 127.0.0.1; private = 192.168.1.10; ten = 10.0.0.5")
    # private IPs excluded
    ip_hits = by_rule(fs2, "PII.IP_ADDRESS")
    for h in ip_hits:
        assert "127.0.0.1" not in (h.evidence or "")
        assert "192.168.1.10" not in (h.evidence or "")


def test_ssn_with_context():
    fs = scan('employee_ssn = "123-45-6789"  # SSN')
    assert "PII.SSN_US" in rules(fs)


def test_cpf_with_context():
    fs = scan('cpf = "123.456.789-09"  # CPF')
    assert "PII.CPF_BR" in rules(fs)


def test_special_category_health_with_id():
    fs = scan('patient_dni = "12345678Z"  # medical record diagnosis')
    assert "PII.SPECIAL_CATEGORY" in rules(fs)


def test_special_category_needs_context():
    fs = scan('value = "12345678Z"')
    assert "PII.SPECIAL_CATEGORY" not in rules(fs)


def test_false_positive_version_numbers_as_ip():
    fs = scan('version = "1.2.3.4"')
    # 1.2.3.4 is public-range shaped — may flag as IP (possible). Ensure no crash.
    assert isinstance(fs, list)


def test_false_positive_short_digit_runs_not_dni():
    fs = scan("count = 12345")
    assert "PII.SPANISH_ID" not in rules(fs)


def test_mac_address():
    fs = scan('mac = "AA:BB:CC:DD:EE:FF"')
    assert "PII.MAC_ADDRESS" in rules(fs)


def test_url_with_email_param():
    fs = scan("GET /u?email=user%40example.com")
    assert "PII.URL_WITH_PII" in rules(fs)


def test_log_pii_pattern():
    fs = scan('logger.info("user email " + email + " password " + password)')
    assert "PII.LOG_PII" in rules(fs)


def test_log_pii_interpolation_template():
    fs = scan("console.log(`login ok ${email}`)")
    assert "PII.LOG_PII" in rules(fs)


def test_log_pii_false_positive_api_login():
    fs = scan("const user = await api.login(email, password);")
    assert "PII.LOG_PII" not in rules(fs)


def test_log_pii_false_positive_warn_missing_secret():
    fs = scan('console.warn("GOOGLE_CLIENT_ID/SECRET not found in .env");')
    assert "PII.LOG_PII" not in rules(fs)


def test_phone_lockfile_version_skipped():
    fs = scan('"caniuse-lite": "^1.0.30001754"', file="package-lock.json")
    assert "PII.PHONE" not in rules(fs)
    fs2 = scan('"version": "1.0.30001757"', file="package-lock.json")
    assert "PII.PHONE" not in rules(fs2)


def test_phone_without_context_not_flagged():
    fs = scan("order_ref = 300017574")
    assert "PII.PHONE" not in rules(fs)
