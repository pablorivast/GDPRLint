"""Secret scanner positive and false-positive cases."""

from gdprlint.scanners.secrets import SecretScanner


def scan_line(text: str, file: str = "src/config.js"):
    return list(SecretScanner().scan_line(file, 42, text))


def rules(findings):
    return {f.rule for f in findings}


def test_aws_access_key_positive():
    fs = scan_line('const k = "AKIAIOSFODNN7EXAMPLE";')
    # AKIA + 16 chars total after AKIA means 16 alnum — EXAMPLE ones may be rejected as placeholder
    # Use a more realistic key without placeholder words
    fs = scan_line('const k = "AKIA" + "ABCDEFGHIJKLMNOP";')
    # concatenation won't match full key; use literal
    fs = scan_line("aws_key = 'AKIA1234567890ABCDEF'")
    assert "SECRET.AWS_ACCESS_KEY" in rules(fs)


def test_github_token_positive():
    # ghp_ + 36+ alphanumeric
    body = "1234567890abcdefghij1234567890abcd"  # 34 → pad to 36
    fs = scan_line(f"GITHUB_TOKEN=ghp_{body}ef")
    assert "SECRET.GITHUB_TOKEN" in rules(fs)


def test_openai_key_positive():
    fs = scan_line('openai_api_key = "sk-proj-abcDEF1234567890xyzXYZ9f2a"')
    assert "SECRET.OPENAI_KEY" in rules(fs)
    f = next(x for x in fs if x.rule == "SECRET.OPENAI_KEY")
    assert f.evidence is not None
    assert "abcDEF1234567890xyzXYZ9f2a" not in f.evidence
    assert "*" in f.evidence


def test_private_key_positive():
    fs = scan_line("-----BEGIN RSA PRIVATE KEY-----")
    assert "SECRET.PRIVATE_KEY" in rules(fs)


def test_jwt_positive():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    fs = scan_line(f'const t = "{jwt}";')
    assert "SECRET.JWT" in rules(fs)


def test_connection_string_positive():
    fs = scan_line(
        'DATABASE_URL="postgres://user:supersecret@db.example.com:5432/app"'
    )
    assert "SECRET.CONNECTION_STRING" in rules(fs)


def test_password_assignment_positive():
    fs = scan_line('password = "hunter2secret"')
    assert "SECRET.PASSWORD" in rules(fs)


def test_compose_weak_password_flagged():
    fs = scan_line(
        "MYSQL_ROOT_PASSWORD: rootpassword",
        file="docker-compose.yml",
    )
    assert "SECRET.HARDCODED_WEAK_PW" in rules(fs)
    f = next(x for x in fs if x.rule == "SECRET.HARDCODED_WEAK_PW")
    assert "rootpassword" not in (f.evidence or "")
    assert f.confidence == "likely"


def test_compose_db_password_weak_flagged():
    fs = scan_line("DB_PASSWORD: rootpassword", file="docker-compose.yml")
    assert "SECRET.HARDCODED_WEAK_PW" in rules(fs)


def test_env_ref_password_not_flagged_as_weak():
    fs = scan_line("DB_PASSWORD=process.env.DB_PASSWORD")
    assert "SECRET.HARDCODED_WEAK_PW" not in rules(fs)
    assert "SECRET.PASSWORD" not in rules(fs)


def test_strong_password_not_weak_rule():
    fs = scan_line('password = "hunter2secret"')
    # Strong hardcoded still hits SECRET.PASSWORD; weak rule may or may not —
    # rootpassword case is the weak path. hunter2secret is not in weak list.
    assert "SECRET.HARDCODED_WEAK_PW" not in rules(fs)


def test_credentials_in_url_query_flagged():
    fs = scan_line(
        "const u = `http://api.example.com/login?username=${id}&password=${password}`;",
        file="api.ts",
    )
    assert "SECRET.CREDENTIALS_IN_URL" in rules(fs)
    f = next(x for x in fs if x.rule == "SECRET.CREDENTIALS_IN_URL")
    assert f.confidence == "high"
    # evidence redacted
    assert "${password}" not in (f.evidence or "") or "****" in (f.evidence or "")


def test_credentials_in_url_token():
    fs = scan_line(
        'fetch("https://x.test/a?token=abc123def456ghi789")',
        file="client.js",
    )
    assert "SECRET.CREDENTIALS_IN_URL" in rules(fs)


def test_url_without_credentials_not_flagged():
    fs = scan_line('fetch(`${BASE_URL}/rooms?userId=${userId}`)', file="api.ts")
    assert "SECRET.CREDENTIALS_IN_URL" not in rules(fs)


def test_api_key_assignment_positive():
    fs = scan_line('api_key = "abcd1234efgh5678ijkl"')
    assert "SECRET.API_KEY" in rules(fs)


def test_false_positive_placeholder_env_var():
    fs = scan_line("api_key = process.env.API_KEY")
    assert "SECRET.API_KEY" not in rules(fs)


def test_false_positive_example_placeholder():
    fs = scan_line('api_key = "your_api_key_here_please_change"')
    assert "SECRET.API_KEY" not in rules(fs)


def test_false_positive_changelog_sk_prefix():
    fs = scan_line("- docs: mention sk- prefix in changelog", file="CHANGELOG.md")
    assert "SECRET.OPENAI_KEY" not in rules(fs)


def test_false_positive_dummy_repeated_chars():
    fs = scan_line('password = "aaaaaaaaaaaaaaaa"')
    assert "SECRET.PASSWORD" not in rules(fs)


def test_false_positive_empty_and_comment_noise():
    fs = scan_line("")
    assert fs == []
    fs = scan_line("   ")
    assert fs == []


def test_evidence_never_contains_full_secret_long_key():
    key = "ghp_1234567890abcdefghij1234567890abcd"
    fs = scan_line(f'token="{key}"')
    for f in fs:
        if f.evidence:
            assert key not in f.evidence
            assert key[-4:] in f.evidence or "****" in f.evidence
