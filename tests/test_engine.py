"""End-to-end engine tests: warn vs block, exceptions, exit codes."""

from pathlib import Path

from laya_guard.analyzer import RulesOnlyAnalyzer
from laya_guard.config import default_config, load_config
from laya_guard.engine import scan
from laya_guard.finding import Decision
from tests.conftest import FakeRouter
from laya_guard.analyzer import LayaAnalyzer


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
    stage("docs/users.md", "Contact: maria.garcia@example.com\n")
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
    stage("fixtures/email.md", "Email: maria.garcia@example.com\n")
    cfg = _cfg_secret_block()
    cfg.rules["PII.EMAIL"] = "block"
    cfg.min_block_confidence = "high"
    cfg.exceptions = []
    from laya_guard.config import ExceptionRule

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
