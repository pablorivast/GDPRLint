"""Rule catalog: sync with scanners + list-rules output."""

from __future__ import annotations

import json
import re
from pathlib import Path

from gdprlint.cli import main
from gdprlint.config import Config, default_config
from gdprlint.rules import RULE_IDS, all_rule_ids, rules_dict

_SCANNERS_DIR = Path(__file__).resolve().parents[1] / "src" / "gdprlint" / "scanners"
_RULE_ID_PATTERN = re.compile(r'"((?:SECRET|PII|SECURITY)\.[A-Z0-9_]+)"')

_CATEGORY_FOR_FILE = {
    "secrets.py": "secret",
    "pii.py": "pii",
    "security.py": "security",
}


def _ids_in_scanner(filename: str) -> set[str]:
    text = (_SCANNERS_DIR / filename).read_text(encoding="utf-8")
    return set(_RULE_ID_PATTERN.findall(text))


def test_catalog_matches_rule_ids_used_by_scanners():
    for filename, category in _CATEGORY_FOR_FILE.items():
        scanned = _ids_in_scanner(filename)
        catalog = set(RULE_IDS[category])
        missing = scanned - catalog
        stale = catalog - scanned
        assert not missing, f"{filename} emits rules missing from catalog: {sorted(missing)}"
        assert not stale, f"{filename}: catalog lists rules that no longer exist: {sorted(stale)}"


def test_all_rule_ids_sorted_and_unique():
    ids = all_rule_ids()
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    assert len(ids) == 64


def test_rules_dict_uses_effective_actions():
    cfg = default_config()
    data = rules_dict(cfg)
    assert data["schema"] == "gdprlint/rules/v1"
    assert data["total"] == 64
    by_id = {r["id"]: r for r in data["rules"]}
    assert len(by_id) == 64
    assert by_id["SECRET.API_KEY"]["action"] == "block"
    assert by_id["SECRET.HARDCODED_WEAK_PW"]["action"] == "warn"
    assert by_id["PII.EMAIL"]["action"] == "warn"
    assert by_id["SECURITY.LOG_CREDENTIAL"]["action"] == "block"
    assert {r["category"] for r in data["rules"]} == {"secret", "pii", "security"}


def test_rules_dict_respects_user_config():
    cfg = Config()
    cfg.rules = {"PII.*": "off"}
    by_id = {r["id"]: r for r in rules_dict(cfg)["rules"]}
    assert by_id["PII.EMAIL"]["action"] == "off"
    assert by_id["SECRET.API_KEY"]["action"] == "block"


def test_cli_list_rules_text(capsys):
    code = main(["list-rules"])
    out = capsys.readouterr().out
    assert code == 0
    assert "64 built-in rules" in out
    assert "SECRET.GITHUB_TOKEN" in out
    assert "PII.SPECIAL_CATEGORY" in out
    assert "SECURITY.LOG_CREDENTIAL" in out
    assert "Secrets (28)" in out
    assert "PII (17)" in out
    assert "Security (19)" in out


def test_cli_list_rules_json(capsys):
    code = main(["list-rules", "--format", "json"])
    out = capsys.readouterr().out
    assert code == 0
    data = json.loads(out)
    assert data["total"] == 64
    assert len(data["rules"]) == 64
