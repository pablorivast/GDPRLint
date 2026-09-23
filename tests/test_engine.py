"""End-to-end engine tests: warn vs block, exceptions, exit codes."""

from pathlib import Path

from gdprlint.analyzer import RulesOnlyAnalyzer
from gdprlint.config import default_config, load_config
from gdprlint.engine import scan
from gdprlint.finding import Decision
from tests.conftest import FakeRouter
from gdprlint.analyzer import LayaAnalyzer


def _cfg_secret_block():
    cfg = default_config()
    cfg.rules = {"SECRET.*": "block", "PII.*": "warn", "SECURITY.*": "warn"}
    cfg.laya.enabled = True
    return cfg


def test_block_on_high_confidence_secret(git_repo: Path, stage):
    stage(
        "src/config.js",
        'const key = "sk-proj-abcDEF1234567890xyzXYZ9f2a";\n',
    )
    cfg = _cfg_secret_block()
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    assert decision.action == "block"
    assert decision.exit_code == 1
    rules = {f.rule for f in decision.findings if f.laya_decision == Decision.BLOCK.value}
    assert any(r.startswith("SECRET.") for r in rules)


def test_clean_scan_allows(git_repo: Path, stage):
    stage("src/safe.py", "def add(a, b):\n    return a + b\n")
    cfg = _cfg_secret_block()
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    assert decision.action == "allow"
    assert decision.exit_code == 0
    assert decision.files_scanned >= 1


def test_pii_only_warns_and_exits_zero(git_repo: Path, stage):
    stage("docs/users.md", "Contact: maria.garcia@acme-corp.es\n")
    cfg = _cfg_secret_block()
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    assert decision.exit_code == 0
    assert decision.action in {"allow", "allow_warn"}
    pii = [f for f in decision.findings if f.category == "pii"]
    assert pii
    assert all(f.laya_decision != Decision.BLOCK.value for f in pii)


def test_rule_off_suppresses_block(git_repo: Path, stage):
    stage("src/config.js", 'token = "ghp_1234567890abcdefghij1234567890abcd";\n')
    cfg = _cfg_secret_block()
    cfg.rules["SECRET.*"] = "off"
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    assert decision.exit_code == 0


def test_mode_off_never_blocks(git_repo: Path, stage):
    stage("src/config.js", 'token = "ghp_1234567890abcdefghij1234567890abcd";\n')
    cfg = _cfg_secret_block()
    cfg.mode = "off"
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    assert decision.exit_code == 0
    assert decision.action == "allow"


def test_exception_suppresses_specific_finding(git_repo: Path, stage):
    stage("fixtures/email.md", "Email: maria.garcia@acme-corp.es\n")
    cfg = _cfg_secret_block()
    cfg.rules["PII.EMAIL"] = "block"
    cfg.min_block_confidence = "high"
    cfg.exceptions = []
    from gdprlint.config import ExceptionRule

    cfg.exceptions = [ExceptionRule(rule="PII.EMAIL", file="fixtures/email.md")]
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    # exception filters at scanner stage — finding should be gone
    assert not any(f.rule == "PII.EMAIL" and f.file == "fixtures/email.md" for f in decision.findings)
    assert decision.exit_code == 0


def test_exclude_glob_skips_file(git_repo: Path, stage):
    stage("fixtures/sanitized/seed.sql", 'password = "hunter2secret";\n')
    cfg = _cfg_secret_block()
    cfg.exclude = ["fixtures/sanitized/**"]
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    assert not any(f.file.startswith("fixtures/sanitized/") for f in decision.findings)


def test_laya_suppress_false_positive_blocks_nothing(git_repo: Path, stage):
    stage("README.md", 'Example api_key = "abcd1234efgh5678ijkl";\n')
    cfg = _cfg_secret_block()
    # Make API key block and force FP suppression via laya
    router = FakeRouter(
        answers={
            "SECRET.API_KEY": {"true_positive": ("B", 0.97)},
        }
    )
    an = LayaAnalyzer(cfg, router=router)
    decision = scan(git_repo, config=cfg, analyzer=an)
    # If a finding was produced, it should be suppressed
    for f in decision.findings:
        if f.rule == "SECRET.API_KEY":
            assert f.laya_decision == Decision.SUPPRESS_FP.value
    if all(
        f.laya_decision != Decision.BLOCK.value for f in decision.findings
    ):
        assert decision.exit_code == 0


def test_rules_only_fallback_blocks_secrets(git_repo: Path, stage):
    stage("src/config.js", 'key = "sk-proj-abcDEF1234567890xyzXYZ9f2a";\n')
    cfg = _cfg_secret_block()
    decision = scan(git_repo, config=cfg, analyzer=RulesOnlyAnalyzer())
    assert decision.laya_available is False
    assert decision.exit_code == 1
    assert "LAYA_FALLBACK_RULES_ONLY" in decision.reasons


def test_gdpr_notes_present_when_special_category(git_repo: Path, stage):
    stage("src/health.py", 'patient_dni = "12345678Z"  # medical record diagnosis\n')
    cfg = _cfg_secret_block()
    cfg.rules["PII.SPECIAL_CATEGORY"] = "block"
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    assert any(f.rule == "PII.SPECIAL_CATEGORY" for f in decision.findings)
    # Should flag privacy review
    assert "FLAG_PRIVACY_REVIEW" in decision.reasons or decision.action == "block"


def test_gdpr_context_off_strips_notes(git_repo: Path, stage):
    stage("src/health.py", 'patient_dni = "12345678Z"  # medical record diagnosis\n')
    cfg = _cfg_secret_block()
    cfg.gdpr_context = "off"
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    assert decision.privacy_notes == []


def test_art9_only_on_special_category_rule(git_repo: Path, stage):
    """Laya data_nature=C alone must not emit Art. 9 note."""
    from gdprlint.finding import Finding, Category

    cfg = _cfg_secret_block()
    # Standalone decide() call — bypass scanners
    from gdprlint.engine import decide

    f = Finding(
        rule="PII.EMAIL",
        category=Category.PII.value,
        severity="medium",
        confidence="high",
        file="a.py",
        line=1,
        message="email",
        remediation="x",
        evidence="a@b.co",
        related_articles=("5.1.c",),
    ).with_laya(data_nature="C", dpia_signal="B")
    decision = decide([f], cfg, files_scanned=1, laya_available=True)
    assert "FLAG_PRIVACY_REVIEW" not in decision.reasons
    assert not any("Art. 9" in n for n in decision.privacy_notes)


def test_art9_on_special_category_rule(git_repo: Path, stage):
    from gdprlint.finding import Finding, Category
    from gdprlint.engine import decide

    cfg = _cfg_secret_block()
    f = Finding(
        rule="PII.SPECIAL_CATEGORY",
        category=Category.PII.value,
        severity="high",
        confidence="likely",
        file="a.py",
        line=1,
        message="health",
        remediation="x",
        evidence="****",
        related_articles=("9",),
    )
    decision = decide([f], cfg, files_scanned=1, laya_available=True)
    assert "FLAG_PRIVACY_REVIEW" in decision.reasons
    assert any("Art. 9" in n for n in decision.privacy_notes)


def test_art35_requires_strong_pii_with_dpia(git_repo: Path, stage):
    from gdprlint.finding import Finding, Category
    from gdprlint.engine import decide

    cfg = _cfg_secret_block()
    weak = Finding(
        rule="PII.PHONE",
        category=Category.PII.value,
        severity="low",
        confidence="possible",
        file="a.py",
        line=1,
        message="phone",
        remediation="x",
        evidence="***",
        related_articles=("5.1.c",),
    ).with_laya(dpia_signal="A")
    decision = decide([weak], cfg, files_scanned=1, laya_available=True)
    assert not any("Art. 35" in n for n in decision.privacy_notes)

    strong = Finding(
        rule="PII.EMAIL",
        category=Category.PII.value,
        severity="medium",
        confidence="high",
        file="a.py",
        line=2,
        message="email",
        remediation="x",
        evidence="a@b.co",
        related_articles=("5.1.c",),
    ).with_laya(dpia_signal="A")
    decision2 = decide([strong], cfg, files_scanned=1, laya_available=True)
    assert any("Art. 35" in n for n in decision2.privacy_notes)


def test_lockfile_default_excluded(git_repo: Path, stage):
    stage("package-lock.json", '{ "version": "1.0.30001757" }\n')
    cfg = _cfg_secret_block()
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    assert not any(f.file.endswith("package-lock.json") for f in decision.findings)
    assert not any(f.file.endswith("package-lock.json") for f in decision.findings)


def test_planted_api_ts_credentials_block(git_repo: Path, stage):
    """v0.2.0 regression: rentoy_online-style insecure login must block."""
    stage(
        "api.ts",
        """
    async login(identifier: string, password?: string): Promise<ApiUser> {
        console.log(`Intento - Usuario: ${identifier}, Password: ${password}`);
        const insecureUrl = `http://api.midominio.com/auth/login?username=${identifier}&password=${password}`;
        const res = await fetch(insecureUrl, { method: 'GET' });
        localStorage.setItem('auth_data', JSON.stringify({
            token: userData.token,
            user: identifier,
            pass: password
        }));
        return userData;
    },
""",
    )
    cfg = _cfg_secret_block()
    an = LayaAnalyzer(cfg, router=FakeRouter())
    decision = scan(git_repo, config=cfg, analyzer=an)
    rules_hit = {f.rule for f in decision.findings}
    assert "SECRET.CREDENTIALS_IN_URL" in rules_hit
    assert "SECURITY.LOG_CREDENTIAL" in rules_hit
    assert "SECURITY.LOCALSTORAGE_SECRET" in rules_hit
    blocking = {
        f.rule
        for f in decision.findings
        if f.laya_decision == Decision.BLOCK.value
    }
    assert "SECRET.CREDENTIALS_IN_URL" in blocking
    assert "SECURITY.LOG_CREDENTIAL" in blocking
    assert "SECURITY.LOCALSTORAGE_SECRET" in blocking
    assert decision.action == "block"
    assert decision.exit_code == 1
