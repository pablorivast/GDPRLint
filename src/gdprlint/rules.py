"""Catalog of built-in rule ids — source of truth for ``gdprlint list-rules``.

Kept in sync with the scanners by ``tests/test_rules.py``, which extracts
every rule-id literal from ``scanners/*.py`` and compares it here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gdprlint.config import Config

# category → rule ids (sorted)
RULE_IDS: dict[str, tuple[str, ...]] = {
    "secret": (
        "SECRET.API_KEY",
        "SECRET.AWS_ACCESS_KEY",
        "SECRET.AWS_SECRET_KEY",
        "SECRET.AZURE_CONNECTION",
        "SECRET.BASIC_AUTH_HEADER",
        "SECRET.BEARER_TOKEN",
        "SECRET.CONNECTION_STRING",
        "SECRET.CREDENTIALS_IN_URL",
        "SECRET.DIGITALOCEAN_TOKEN",
        "SECRET.DOCKER_CONFIG",
        "SECRET.ENCRYPTION_KEY",
        "SECRET.ENV_FILE_SECRET",
        "SECRET.GITHUB_TOKEN",
        "SECRET.GITLAB_TOKEN",
        "SECRET.GOOGLE_API_KEY",
        "SECRET.HARDCODED_WEAK_PW",
        "SECRET.HUGGINGFACE_TOKEN",
        "SECRET.JWT",
        "SECRET.NPM_TOKEN",
        "SECRET.OAUTH_REFRESH",
        "SECRET.OPENAI_KEY",
        "SECRET.PASSWORD",
        "SECRET.PRIVATE_KEY",
        "SECRET.PYPI_TOKEN",
        "SECRET.SENDGRID_KEY",
        "SECRET.SLACK_TOKEN",
        "SECRET.STRIPE_KEY",
        "SECRET.URL_CREDENTIALS",
    ),
    "pii": (
        "PII.CPF_BR",
        "PII.CREDIT_CARD",
        "PII.DATE_OF_BIRTH",
        "PII.EMAIL",
        "PII.GPS_COORDINATE",
        "PII.IBAN",
        "PII.IP_ADDRESS",
        "PII.LICENSE_PLATE_ES",
        "PII.LOG_PII",
        "PII.MAC_ADDRESS",
        "PII.NHS_UK",
        "PII.PASSPORT",
        "PII.PHONE",
        "PII.SPANISH_ID",
        "PII.SPECIAL_CATEGORY",
        "PII.SSN_US",
        "PII.URL_WITH_PII",
    ),
    "security": (
        "SECURITY.CHILD_PROCESS_EXEC",
        "SECURITY.COMMAND_INJECTION",
        "SECURITY.CORS_WILDCARD",
        "SECURITY.DANGEROUS_HTML",
        "SECURITY.DEBUG_TRUE",
        "SECURITY.EVAL",
        "SECURITY.EXEC",
        "SECURITY.LOCALSTORAGE_SECRET",
        "SECURITY.LOG_CREDENTIAL",
        "SECURITY.OPEN_REDIRECT",
        "SECURITY.OS_SYSTEM",
        "SECURITY.PATH_TRAVERSAL",
        "SECURITY.PICKLE_LOADS",
        "SECURITY.SQL_CONCAT",
        "SECURITY.SUBPROCESS_SHELL",
        "SECURITY.TLS_VERIFY_OFF",
        "SECURITY.WEAK_HASH",
        "SECURITY.WEAK_RANDOM_SECRET",
        "SECURITY.YAML_UNSAFE",
    ),
}

CATEGORY_TITLES = {
    "secret": "Secrets",
    "pii": "PII",
    "security": "Security",
}


def all_rule_ids() -> list[str]:
    """Every rule id, sorted alphabetically."""
    return sorted(rule for ids in RULE_IDS.values() for rule in ids)


def rules_dict(config: Config) -> dict[str, Any]:
    """Machine-readable catalog with the effective action per rule."""
    return {
        "schema": "gdprlint/rules/v1",
        "tool": {"name": "gdprlint"},
        "total": len(all_rule_ids()),
        "rules": [
            {"id": rule, "category": category, "action": config.action_for_rule(rule)}
            for category in ("secret", "pii", "security")
            for rule in RULE_IDS[category]
        ],
        "custom_rules": [
            {"id": c.id, "category": c.category, "action": config.action_for_rule(c.id)}
            for c in config.custom_rules
        ],
    }
