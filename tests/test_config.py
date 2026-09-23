"""Configuration loading and resolution tests."""

import json
from pathlib import Path

import pytest

from gdprlint.config import Config, ConfigError, default_config, load_config


def test_default_config_actions():
    cfg = default_config()
    assert cfg.action_for_rule("SECRET.API_KEY") == "block"
    assert cfg.action_for_rule("PII.EMAIL") == "warn"
    assert cfg.action_for_rule("SECURITY.EVAL") == "warn"
    assert cfg.mode == "block"


def test_load_missing_file_returns_defaults(tmp_path: Path):
    cfg = load_config(tmp_path)
    assert cfg.path is None
    assert cfg.action_for_rule("SECRET.AWS_ACCESS_KEY") == "block"


def test_load_custom_rules(tmp_path: Path):
    (tmp_path / ".gdprlint.json").write_text(
        json.dumps(
            {
                "mode": "block",
                "rules": {"SECRET.*": "block", "PII.EMAIL": "off", "SECURITY.*": "warn"},
                "exclude": ["fixtures/**"],
                "min_block_confidence": "high",
            }
        ),
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert cfg.action_for_rule("PII.EMAIL") == "off"
    assert cfg.action_for_rule("PII.PHONE") == "warn"  # default via PII.*
    assert cfg.action_for_rule("SECRET.X") == "block"
    assert cfg.is_excluded("fixtures/sanitized/a.txt")


def test_glob_specificity_longest_wins(tmp_path: Path):
    (tmp_path / ".gdprlint.json").write_text(
        json.dumps({"rules": {"PII.*": "warn", "PII.EMAIL": "block"}}),
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert cfg.action_for_rule("PII.EMAIL") == "block"


def test_exceptions_match_rule_file_line(tmp_path: Path):
    (tmp_path / ".gdprlint.json").write_text(
        json.dumps(
            {
                "exceptions": [
                    {"rule": "PII.EMAIL", "file": "docs/*.md", "line": 12},
                ]
            }
        ),
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert cfg.is_excepted("PII.EMAIL", "docs/examples.md", 12)
    assert not cfg.is_excepted("PII.EMAIL", "docs/examples.md", 13)
    assert not cfg.is_excepted("PII.PHONE", "docs/examples.md", 12)


def test_invalid_mode_raises(tmp_path: Path):
    (tmp_path / ".gdprlint.json").write_text(json.dumps({"mode": "nope"}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_invalid_rule_action_raises(tmp_path: Path):
    (tmp_path / ".gdprlint.json").write_text(
        json.dumps({"rules": {"SECRET.*": "explode"}}), encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_invalid_json_raises(tmp_path: Path):
    (tmp_path / ".gdprlint.json").write_text("{nope", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_laya_config_bounds(tmp_path: Path):
    (tmp_path / ".gdprlint.json").write_text(
        json.dumps({"laya": {"enabled": False, "min_confidence": 1.5}}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_gdpr_context_off(tmp_path: Path):
    (tmp_path / ".gdprlint.json").write_text(
        json.dumps({"gdpr_context": "off"}), encoding="utf-8"
    )
    cfg = load_config(tmp_path)
    assert cfg.gdpr_context_enabled() is False


def test_mode_off_never_blocks_via_config():
    cfg = default_config()
    cfg.mode = "off"
    assert cfg.mode == "off"


def test_default_excludes_lockfiles_and_min_js():
    cfg = default_config()
    assert cfg.is_excluded("package-lock.json")
    assert cfg.is_excluded("frontend/package-lock.json")
    assert cfg.is_excluded("yarn.lock")
    assert cfg.is_excluded("pnpm-lock.yaml")
    assert cfg.is_excluded("poetry.lock")
    assert cfg.is_excluded("Cargo.lock")
    assert cfg.is_excluded("vendor/app.min.js")
    assert cfg.is_excluded("app.min.css")
    assert not cfg.is_excluded("src/app.ts")
    assert not cfg.is_excluded("docker-compose.yml")


def test_exclude_defaults_false_disables_builtins(tmp_path: Path):
    (tmp_path / ".gdprlint.json").write_text(
        json.dumps({"exclude_defaults": False}), encoding="utf-8"
    )
    cfg = load_config(tmp_path)
    assert cfg.exclude_defaults is False
    assert not cfg.is_excluded("package-lock.json")


def test_weak_pw_rule_warns_by_default():
    cfg = default_config()
    assert cfg.action_for_rule("SECRET.HARDCODED_WEAK_PW") == "warn"
    assert cfg.action_for_rule("SECRET.AWS_ACCESS_KEY") == "block"


def test_credential_rules_block_by_default():
    cfg = default_config()
    assert cfg.action_for_rule("SECRET.CREDENTIALS_IN_URL") == "block"
    assert cfg.action_for_rule("SECURITY.LOG_CREDENTIAL") == "block"
    assert cfg.action_for_rule("SECURITY.LOCALSTORAGE_SECRET") == "block"
    # other security still warns
    assert cfg.action_for_rule("SECURITY.CORS_WILDCARD") == "warn"
