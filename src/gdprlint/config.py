"""Configuration loading for ``.gdprlint.json``."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from gdprlint.rules import all_rule_ids

CONFIG_FILENAME = ".gdprlint.json"

VALID_ACTIONS = frozenset({"block", "warn", "off"})
VALID_MODES = frozenset({"block", "off"})
VALID_CONFIDENCE = frozenset({"possible", "likely", "high"})
VALID_CATEGORIES = frozenset({"secret", "pii", "security"})
VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

# Subset of inline regex flags accepted in custom_rules entries.
_CUSTOM_FLAG_MAP: dict[str, Any] = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "x": re.VERBOSE,
}
_CUSTOM_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]*\.[A-Z0-9_]+$")
_RESERVED_PREFIXES = ("SECRET.", "PII.", "SECURITY.")

# Lockfiles / generated bundles — high FP surface, low value for PII/secret scan.
DEFAULT_EXCLUDE: list[str] = [
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/poetry.lock",
    "**/uv.lock",
    "**/Cargo.lock",
    "**/composer.lock",
    "**/*.min.js",
    "**/*.min.css",
]


class ConfigError(Exception):
    """Raised when configuration is invalid."""


@dataclass
class LayaConfig:
    enabled: bool = True
    device: str = "cpu"
    min_confidence: float = 0.70
    suppress_fp_below: float = 0.85
    preload: bool = False
    show_gdpr_context: bool = True
    flag_special_category: bool = True
    flag_dpia_signal: bool = True


@dataclass
class ExceptionRule:
    rule: str
    file: str
    line: int | None = None

    def matches(self, finding_rule: str, finding_file: str, finding_line: int) -> bool:
        if not fnmatch.fnmatch(finding_rule, self.rule) and finding_rule != self.rule:
            return False
        if not fnmatch.fnmatch(finding_file, self.file) and finding_file != self.file:
            return False
        return self.line is None or self.line == finding_line


@dataclass
class CustomRule:
    """User-defined regex rule declared in ``custom_rules``."""

    id: str
    pattern: re.Pattern[str]
    category: str = "secret"
    action: str = "warn"
    severity: str = "medium"
    confidence: str = "likely"
    message: str = ""
    remediation: str = ""
    articles: tuple[str, ...] = ()


@dataclass
class Config:
    mode: str = "block"
    min_block_confidence: str = "high"
    rules: dict[str, str] = field(default_factory=dict)
    exclude: list[str] = field(default_factory=list)
    exclude_defaults: bool = True
    exceptions: list[ExceptionRule] = field(default_factory=list)
    laya: LayaConfig = field(default_factory=LayaConfig)
    gdpr_context: str = "informational"
    custom_rules: list[CustomRule] = field(default_factory=list)
    path: Path | None = None

    # Defaults when no config file / no matching rule.
    # Exact SECRET.HARDCODED_WEAK_PW must win over SECRET.* glob (dict order
    # is not used for builtins — action_for_rule prefers exact match first).
    DEFAULT_RULE_ACTIONS: ClassVar[dict[str, str]] = {
        "SECRET.*": "block",
        "PII.*": "warn",
        "SECURITY.*": "warn",
    }

    # Exact overrides before SECRET.* / SECURITY.* globs.
    # Critical credential-handling rules block; weak/dev defaults warn.
    DEFAULT_EXACT_ACTIONS: ClassVar[dict[str, str]] = {
        "SECRET.HARDCODED_WEAK_PW": "warn",
        "SECRET.CREDENTIALS_IN_URL": "block",
        "SECURITY.LOG_CREDENTIAL": "block",
        "SECURITY.LOCALSTORAGE_SECRET": "block",
    }

    def action_for_rule(self, rule: str) -> str:
        # Exact match first, then globs (longest pattern wins for specificity)
        if rule in self.rules:
            return self.rules[rule]
        if rule in self.DEFAULT_EXACT_ACTIONS:
            return self.DEFAULT_EXACT_ACTIONS[rule]
        best_pattern = ""
        best_action = ""
        for pattern, action in self.rules.items():
            if fnmatch.fnmatch(rule, pattern) and len(pattern) > len(best_pattern):
                best_pattern = pattern
                best_action = action
        if best_pattern:
            return best_action
        # Custom rules default action — after user globs so a broad
        # "CORP.*": "off" entry still overrides the rule's own action.
        for custom in self.custom_rules:
            if custom.id == rule:
                return custom.action
        # Built-in defaults
        for pattern, action in self.DEFAULT_RULE_ACTIONS.items():
            if fnmatch.fnmatch(rule, pattern):
                return action
        return "warn"

    def _match_exclude(self, normalized: str, pattern: str) -> bool:
        # fnmatch does not treat ** as recursive; translate common globs.
        if pattern.startswith("**/"):
            suffix = pattern[3:]
            if fnmatch.fnmatch(normalized, suffix) or fnmatch.fnmatch(
                normalized.split("/")[-1], suffix
            ):
                return True
            # match any path segment suffix: a/**/b
            if "/" in normalized:
                parts = normalized.split("/")
                for i in range(len(parts)):
                    if fnmatch.fnmatch("/".join(parts[i:]), suffix):
                        return True
        if fnmatch.fnmatch(normalized, pattern):
            return True
        # Also match basename-style patterns against full path segments
        return "/" not in pattern and fnmatch.fnmatch(normalized.split("/")[-1], pattern)

    def is_excluded(self, path: str) -> bool:
        normalized = path.replace("\\", "/")
        patterns = list(self.exclude)
        if self.exclude_defaults:
            patterns = DEFAULT_EXCLUDE + patterns
        return any(self._match_exclude(normalized, pattern) for pattern in patterns)

    def is_excepted(self, rule: str, file: str, line: int) -> bool:
        return any(exc.matches(rule, file, line) for exc in self.exceptions)

    def gdpr_context_enabled(self) -> bool:
        return self.gdpr_context != "off" and self.laya.show_gdpr_context


def default_config() -> Config:
    cfg = Config()
    cfg.rules = dict(cfg.DEFAULT_RULE_ACTIONS)
    return cfg


def _parse_exceptions(raw: Any) -> list[ExceptionRule]:
    if not isinstance(raw, list):
        raise ConfigError("'exceptions' must be a list")
    out: list[ExceptionRule] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError(f"exceptions[{i}] must be an object")
        rule = item.get("rule")
        file = item.get("file")
        if not rule or not file:
            raise ConfigError(f"exceptions[{i}] requires 'rule' and 'file'")
        line = item.get("line")
        if line is not None and not isinstance(line, int):
            raise ConfigError(f"exceptions[{i}].line must be an integer")
        out.append(ExceptionRule(rule=str(rule), file=str(file), line=line))
    return out


def _parse_laya(raw: Any) -> LayaConfig:
    if raw is None:
        return LayaConfig()
    if not isinstance(raw, dict):
        raise ConfigError("'laya' must be an object")
    cfg = LayaConfig()
    if "enabled" in raw:
        cfg.enabled = bool(raw["enabled"])
    if "device" in raw:
        cfg.device = str(raw["device"])
    if "min_confidence" in raw:
        val = float(raw["min_confidence"])
        if not 0.0 <= val <= 1.0:
            raise ConfigError("laya.min_confidence must be between 0 and 1")
        cfg.min_confidence = val
    if "suppress_fp_below" in raw:
        val = float(raw["suppress_fp_below"])
        if not 0.0 <= val <= 1.0:
            raise ConfigError("laya.suppress_fp_below must be between 0 and 1")
        cfg.suppress_fp_below = val
    if "preload" in raw:
        cfg.preload = bool(raw["preload"])
    if "show_gdpr_context" in raw:
        cfg.show_gdpr_context = bool(raw["show_gdpr_context"])
    if "flag_special_category" in raw:
        cfg.flag_special_category = bool(raw["flag_special_category"])
    if "flag_dpia_signal" in raw:
        cfg.flag_dpia_signal = bool(raw["flag_dpia_signal"])
    return cfg


def _parse_custom_rules(raw: Any) -> list[CustomRule]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError("'custom_rules' must be a list")
    builtin_ids = set(all_rule_ids())
    out: list[CustomRule] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        prefix = f"custom_rules[{i}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{prefix} must be an object")

        rid = item.get("id")
        if not isinstance(rid, str) or not rid:
            raise ConfigError(f"{prefix} requires an 'id' string")
        if not _CUSTOM_ID_RE.match(rid):
            raise ConfigError(
                f"{prefix}.id must look like 'VENDOR.RULE_NAME' (uppercase): {rid!r}"
            )
        if rid.startswith(_RESERVED_PREFIXES) or rid in builtin_ids:
            raise ConfigError(
                f"{prefix}.id {rid!r} collides with a built-in rule id or namespace"
            )
        if rid in seen:
            raise ConfigError(f"{prefix}.id {rid!r} is duplicated")
        seen.add(rid)

        pattern = item.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ConfigError(f"{prefix} requires a 'pattern' string")
        flags_raw = item.get("flags", "")
        if not isinstance(flags_raw, str) or any(c not in _CUSTOM_FLAG_MAP for c in flags_raw):
            raise ConfigError(
                f"{prefix}.flags must be a combination of {sorted(_CUSTOM_FLAG_MAP)}"
            )
        flags = 0
        for c in flags_raw:
            flags |= _CUSTOM_FLAG_MAP[c]
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            raise ConfigError(f"{prefix}.pattern is not a valid regex: {exc}") from exc

        category = item.get("category", "secret")
        if category not in VALID_CATEGORIES:
            raise ConfigError(
                f"{prefix}.category must be one of {sorted(VALID_CATEGORIES)}, "
                f"got {category!r}"
            )
        action = item.get("action", "warn")
        if action not in VALID_ACTIONS:
            raise ConfigError(
                f"{prefix}.action must be one of {sorted(VALID_ACTIONS)}, got {action!r}"
            )
        severity = item.get("severity", "medium")
        if severity not in VALID_SEVERITIES:
            raise ConfigError(
                f"{prefix}.severity must be one of {sorted(VALID_SEVERITIES)}, "
                f"got {severity!r}"
            )
        confidence = item.get("confidence", "likely")
        if confidence not in VALID_CONFIDENCE:
            raise ConfigError(
                f"{prefix}.confidence must be one of {sorted(VALID_CONFIDENCE)}, "
                f"got {confidence!r}"
            )

        articles_raw = item.get("articles", [])
        if not isinstance(articles_raw, list) or not all(
            isinstance(a, (str, int)) for a in articles_raw
        ):
            raise ConfigError(f"{prefix}.articles must be a list of strings")
        articles = tuple(str(a) for a in articles_raw)

        message = item.get("message")
        remediation = item.get("remediation")
        out.append(
            CustomRule(
                id=rid,
                pattern=compiled,
                category=str(category),
                action=str(action),
                severity=str(severity),
                confidence=str(confidence),
                message=str(message) if message else f"Custom rule {rid} matched.",
                remediation=(
                    str(remediation)
                    if remediation
                    else (
                        "Review this match and remove it or add an exception "
                        "in .gdprlint.json."
                    )
                ),
                articles=articles,
            )
        )
    return out


def load_config_file(path: Path) -> Config:
    """Load and validate an explicit ``.gdprlint.json`` file."""
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a JSON object")

    cfg = Config()
    cfg.path = path

    mode = raw.get("mode", "block")
    if mode not in VALID_MODES:
        raise ConfigError(f"mode must be one of {sorted(VALID_MODES)}, got {mode!r}")
    cfg.mode = mode

    mbc = raw.get("min_block_confidence", "high")
    if mbc not in VALID_CONFIDENCE:
        raise ConfigError(
            f"min_block_confidence must be one of {sorted(VALID_CONFIDENCE)}, got {mbc!r}"
        )
    cfg.min_block_confidence = mbc

    rules = raw.get("rules")
    if rules is None:
        cfg.rules = dict(cfg.DEFAULT_RULE_ACTIONS)
    else:
        if not isinstance(rules, dict):
            raise ConfigError("'rules' must be an object")
        for k, v in rules.items():
            if v not in VALID_ACTIONS:
                raise ConfigError(
                    f"rules[{k!r}] must be one of {sorted(VALID_ACTIONS)}, got {v!r}"
                )
        cfg.rules = {str(k): str(v) for k, v in rules.items()}

    exclude = raw.get("exclude", [])
    if not isinstance(exclude, list) or not all(isinstance(x, str) for x in exclude):
        raise ConfigError("'exclude' must be a list of strings")
    cfg.exclude = list(exclude)

    if "exclude_defaults" in raw:
        if not isinstance(raw["exclude_defaults"], bool):
            raise ConfigError("'exclude_defaults' must be a boolean")
        cfg.exclude_defaults = raw["exclude_defaults"]
    else:
        cfg.exclude_defaults = True

    cfg.exceptions = _parse_exceptions(raw.get("exceptions", []))
    cfg.laya = _parse_laya(raw.get("laya"))

    gdpr = raw.get("gdpr_context", "informational")
    if gdpr not in {"informational", "off"}:
        raise ConfigError("gdpr_context must be 'informational' or 'off'")
    cfg.gdpr_context = gdpr

    cfg.custom_rules = _parse_custom_rules(raw.get("custom_rules"))

    return cfg


def load_config(start_dir: Path | None = None) -> Config:
    """Load config from ``start_dir`` (or cwd) if present; else defaults."""
    base = Path(start_dir) if start_dir else Path.cwd()
    path = base / CONFIG_FILENAME
    if not path.is_file():
        cfg = default_config()
        cfg.path = None
        return cfg
    return load_config_file(path)


# Starter file written by ``gdprlint init`` — mirrors the built-in defaults
# so behaviour does not change on adoption; edit to override.
INIT_TEMPLATE: dict[str, Any] = {
    "mode": "block",
    "min_block_confidence": "high",
    "rules": {
        "SECRET.*": "block",
        "PII.*": "warn",
        "SECURITY.*": "warn",
    },
    "exclude": [],
    "exclude_defaults": True,
    "laya": {
        "enabled": True,
    },
    "gdpr_context": "informational",
    "custom_rules": [],
}


def write_config(path: Path, *, force: bool = False) -> Path:
    """Write the starter ``.gdprlint.json``. Raises ConfigError if it exists."""
    if path.exists() and not force:
        raise ConfigError(
            f"{path} already exists (use --force to overwrite)"
        )
    try:
        path.write_text(
            json.dumps(INIT_TEMPLATE, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ConfigError(f"cannot write {path}: {exc}") from exc
    return path
