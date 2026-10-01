"""Custom rules: config parsing, action resolution and the custom scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gdprlint.config import Config, ConfigError, load_config_file
from gdprlint.engine import run_scanners
from gdprlint.git_ops import AddedLine, StagedDiff
from gdprlint.scanners.custom import CustomRuleScanner
from tests.conftest import run_cli, stage_file

TOKEN = "tok_" + "aB3" * 11  # 36-char match for tok_[A-Za-z0-9]{32}


def _write_cfg(tmp_path: Path, data: object) -> Path:
    path = tmp_path / ".gdprlint.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _load(tmp_path: Path, data: object) -> Config:
    return load_config_file(_write_cfg(tmp_path, data))


def test_custom_rule_defaults(tmp_path: Path):
    cfg = _load(
        tmp_path,
        {"custom_rules": [{"id": "CORP.INTERNAL_TOKEN", "pattern": r"tok_[A-Za-z0-9]{32}"}]},
    )
    (rule,) = cfg.custom_rules
    assert rule.id == "CORP.INTERNAL_TOKEN"
    assert rule.category == "secret"
    assert rule.action == "warn"
    assert rule.severity == "medium"
    assert rule.confidence == "likely"
    assert "CORP.INTERNAL_TOKEN" in rule.message
    assert rule.articles == ()
    assert rule.pattern.search(f"key = {TOKEN}")


def test_custom_rule_full_options(tmp_path: Path):
    cfg = _load(
        tmp_path,
        {
            "custom_rules": [
                {
                    "id": "CORP.EMAIL_LIST",
                    "pattern": r"emails:\s*\S+@\S+",
                    "flags": "i",
                    "category": "pii",
                    "action": "block",
                    "severity": "critical",
                    "confidence": "high",
                    "message": "Bulk email list committed",
                    "remediation": "Move the list to the CRM.",
                    "articles": ["5", 32],
                }
            ]
        },
    )
    (rule,) = cfg.custom_rules
    assert rule.category == "pii"
    assert rule.action == "block"
    assert rule.severity == "critical"
    assert rule.confidence == "high"
    assert rule.message == "Bulk email list committed"
    assert rule.remediation == "Move the list to the CRM."
    assert rule.articles == ("5", "32")
    assert rule.pattern.search("Emails: A@B.example")  # case-insensitive flag


@pytest.mark.parametrize(
    ("entry", "fragment"),
    [
        ({"id": "CORP.X", "pattern": "["}, "not a valid regex"),
        ({"id": "CORP.X", "pattern": "x", "flags": "q"}, "flags"),
        ({"id": "CORP.X", "pattern": "x", "category": "health"}, "category"),
        ({"id": "CORP.X", "pattern": "x", "action": "explode"}, "action"),
        ({"id": "CORP.X", "pattern": "x", "severity": "apocalyptic"}, "severity"),
        ({"id": "CORP.X", "pattern": "x", "confidence": "certain"}, "confidence"),
        ({"id": "corp.token", "pattern": "x"}, "VENDOR.RULE_NAME"),
        ({"id": "NOTOKEN", "pattern": "x"}, "VENDOR.RULE_NAME"),
        ({"id": "SECRET.MINE", "pattern": "x"}, "built-in"),
        ({"id": "PII.MINE", "pattern": "x"}, "built-in"),
        ({"pattern": "x"}, "requires an 'id'"),
        ({"id": "CORP.X"}, "requires a 'pattern'"),
        ({"id": "CORP.X", "pattern": "x", "articles": "32"}, "articles"),
    ],
)
def test_invalid_custom_rules(tmp_path: Path, entry: dict, fragment: str):
    with pytest.raises(ConfigError, match=fragment):
        _load(tmp_path, {"custom_rules": [entry]})


def test_duplicate_custom_rule_id(tmp_path: Path):
    entry = {"id": "CORP.X", "pattern": "x"}
    with pytest.raises(ConfigError, match="duplicated"):
        _load(tmp_path, {"custom_rules": [entry, dict(entry)]})


def test_custom_rules_must_be_a_list(tmp_path: Path):
    with pytest.raises(ConfigError, match="must be a list"):
        _load(tmp_path, {"custom_rules": {"id": "CORP.X"}})


def test_custom_rules_item_must_be_object(tmp_path: Path):
    with pytest.raises(ConfigError, match="must be an object"):
        _load(tmp_path, {"custom_rules": ["CORP.X"]})


def test_action_for_rule_custom_default(tmp_path: Path):
    cfg = _load(
        tmp_path,
        {"custom_rules": [{"id": "CORP.TOKEN", "pattern": "x", "action": "block"}]},
    )
    assert cfg.action_for_rule("CORP.TOKEN") == "block"
    # Unknown ids still fall through to warn
    assert cfg.action_for_rule("CORP.OTHER") == "warn"


def test_action_for_rule_user_exact_overrides_custom(tmp_path: Path):
    cfg = _load(
        tmp_path,
        {
            "custom_rules": [{"id": "CORP.TOKEN", "pattern": "x", "action": "block"}],
            "rules": {"CORP.TOKEN": "warn"},
        },
    )
    assert cfg.action_for_rule("CORP.TOKEN") == "warn"


def test_action_for_rule_user_glob_overrides_custom(tmp_path: Path):
    cfg = _load(
        tmp_path,
        {
            "custom_rules": [{"id": "CORP.TOKEN", "pattern": "x", "action": "block"}],
            "rules": {"CORP.*": "off"},
        },
    )
    assert cfg.action_for_rule("CORP.TOKEN") == "off"


def test_custom_scanner_match_is_redacted(tmp_path: Path):
    cfg = _load(
        tmp_path,
        {"custom_rules": [{"id": "CORP.INTERNAL_TOKEN", "pattern": r"tok_[A-Za-z0-9]{32}"}]},
    )
    scanner = CustomRuleScanner(cfg.custom_rules)
    (finding,) = scanner.scan_line("src/app.py", 7, f'api_key = "{TOKEN}"')
    assert finding.rule == "CORP.INTERNAL_TOKEN"
    assert finding.category == "secret"
    assert finding.file == "src/app.py"
    assert finding.line == 7
    assert finding.evidence is not None
    assert TOKEN not in finding.evidence
    assert scanner.scan_line("src/app.py", 8, "clean line") == []


def test_custom_scanner_multiple_rules(tmp_path: Path):
    cfg = _load(
        tmp_path,
        {
            "custom_rules": [
                {"id": "CORP.ONE", "pattern": "alpha-1234"},
                {"id": "CORP.TWO", "pattern": "beta-5678"},
            ]
        },
    )
    scanner = CustomRuleScanner(cfg.custom_rules)
    findings = scanner.scan_line("f.txt", 1, "alpha-1234 and beta-5678")
    assert [f.rule for f in findings] == ["CORP.ONE", "CORP.TWO"]


def test_run_scanners_includes_custom_rules(tmp_path: Path):
    cfg = _load(
        tmp_path,
        {
            "custom_rules": [
                {
                    "id": "CORP.INTERNAL_TOKEN",
                    "pattern": r"tok_[A-Za-z0-9]{32}",
                    "action": "block",
                }
            ],
            "plugins": False,
        },
    )
    diff = StagedDiff(
        files=["app.py"],
        added_lines=[AddedLine(path="app.py", line_no=3, text=f"key = {TOKEN}")],
    )
    findings, files_scanned = run_scanners(diff, cfg)
    assert files_scanned == 1
    assert [f.rule for f in findings] == ["CORP.INTERNAL_TOKEN"]


def test_scan_blocks_on_custom_rule(git_repo: Path):
    (git_repo / ".gdprlint.json").write_text(
        json.dumps(
            {
                "custom_rules": [
                    {
                        "id": "CORP.INTERNAL_TOKEN",
                        "pattern": r"tok_[A-Za-z0-9]{32}",
                        "action": "block",
                        "severity": "high",
                        "confidence": "high",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    stage_file(git_repo, "src/settings.py", f'API_KEY = "{TOKEN}"\n')
    code, out, _err = run_cli(["scan", "--no-laya"], git_repo)
    assert code == 1
    assert "CORP.INTERNAL_TOKEN" in out
    assert "Commit blocked." in out
    assert TOKEN not in out  # evidence stays redacted


def test_scan_custom_rule_warn_allows(git_repo: Path):
    (git_repo / ".gdprlint.json").write_text(
        json.dumps({"custom_rules": [{"id": "CORP.TOKEN", "pattern": r"tok_[A-Za-z0-9]{32}"}]}),
        encoding="utf-8",
    )
    stage_file(git_repo, "notes.md", f"see {TOKEN}\n")
    code, out, _err = run_cli(["scan", "--no-laya"], git_repo)
    assert code == 0
    assert "Commit allowed." in out


def test_list_rules_shows_custom_rules(git_repo: Path):
    (git_repo / ".gdprlint.json").write_text(
        json.dumps(
            {
                "custom_rules": [
                    {"id": "CORP.TOKEN", "pattern": "x", "action": "block"},
                ]
            }
        ),
        encoding="utf-8",
    )
    code, out, _err = run_cli(["list-rules"], git_repo)
    assert code == 0
    assert "Custom rules (1)" in out
    assert "block  CORP.TOKEN" in out

    code, out, _err = run_cli(["list-rules", "--format", "json"], git_repo)
    assert code == 0
    data = json.loads(out)
    assert data["custom_rules"] == [
        {"id": "CORP.TOKEN", "category": "secret", "action": "block"}
    ]
