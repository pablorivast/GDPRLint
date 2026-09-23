"""Secret detection — local pattern rules only. Evidence is always redacted."""

from __future__ import annotations

import re
from typing import Sequence

from laya_guard.finding import Category, Confidence, Finding, Severity
from laya_guard.redact import redact_secret
from laya_guard.scanners.base import Scanner

# GDPR context tags are informational only — not legal advice.
_ART_32 = "32"
_ART_5F = "5.1.f"
_ART_33 = "33"


def _finding(
    rule: str,
    file: str,
    line: int,
    message: str,
    remediation: str,
    *,
    severity: str = Severity.HIGH.value,
    confidence: str = Confidence.HIGH.value,
    evidence: str,
    articles: tuple[str, ...] = (_ART_5F, _ART_32),
) -> Finding:
    return Finding(
        rule=rule,
        category=Category.SECRET.value,
        severity=severity,
        confidence=confidence,
        file=file,
        line=line,
        message=message,
        remediation=remediation,
        evidence=evidence,
        related_articles=articles,
    )


# --- High-signal provider tokens -------------------------------------------

_RULES: list[tuple[str, re.Pattern[str], str, str, str, str]] = [
    # rule, pattern, message, remediation, severity, confidence
    (
        "SECRET.AWS_ACCESS_KEY",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "Potential AWS access key detected.",
        "Remove the key and load credentials from the environment or an AWS secret store; rotate if it was ever committed.",
        Severity.CRITICAL.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.GITHUB_TOKEN",
        re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"
            r"|\bgithub_pat_[A-Za-z0-9_]{22,}"
        ),
        "Potential GitHub token detected.",
        "Revoke the token in GitHub settings and store the replacement outside the repository.",
        Severity.CRITICAL.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.GITLAB_TOKEN",
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
        "Potential GitLab personal access token detected.",
        "Revoke the token and load it from a secret manager at runtime.",
        Severity.CRITICAL.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.SLACK_TOKEN",
        re.compile(
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}"
            r"|hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"
        ),
        "Potential Slack token or webhook detected.",
        "Rotate the Slack credential and keep it out of source control.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.STRIPE_KEY",
        re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}"),
        "Potential Stripe live secret key detected.",
        "Revoke the key in the Stripe dashboard and use environment configuration.",
        Severity.CRITICAL.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.OPENAI_KEY",
        re.compile(r"\bsk-(?:proj-|ant-|or-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
        "Potential OpenAI/Anthropic API key detected.",
        "Rotate the key and inject it via environment variables or a secret manager.",
        Severity.CRITICAL.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Potential Google API key detected.",
        "Restrict and rotate the key; do not embed it in client-side code.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.HUGGINGFACE_TOKEN",
        re.compile(r"\bhf_[A-Za-z0-9]{30,}"),
        "Potential Hugging Face token detected.",
        "Revoke the token and read it from the environment at runtime.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.SENDGRID_KEY",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
        "Potential SendGrid API key detected.",
        "Rotate the SendGrid key and store it outside the repository.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.NPM_TOKEN",
        re.compile(r"\bnpm_[A-Za-z0-9]{30,}"),
        "Potential npm access token detected.",
        "Revoke the npm token and use a trusted publishing setup.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.PYPI_TOKEN",
        re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}"),
        "Potential PyPI API token detected.",
        "Revoke the token on PyPI and use scoped tokens from a secret store.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.DIGITALOCEAN_TOKEN",
        re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
        "Potential DigitalOcean token detected.",
        "Revoke the token and load it from a secret manager.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        "Private key material detected.",
        "Never commit private keys. Move the key to a secure store and rotate it.",
        Severity.CRITICAL.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "Potential JWT token detected.",
        "Do not hardcode JWTs; issue tokens at runtime and keep signing keys server-side.",
        Severity.HIGH.value,
        Confidence.LIKELY.value,
    ),
    (
        "SECRET.BASIC_AUTH_HEADER",
        re.compile(r"\bBasic\s+[A-Za-z0-9+/]{20,}={0,2}\b"),
        "Potential HTTP Basic credentials detected.",
        "Remove embedded credentials; use environment-provided auth.",
        Severity.HIGH.value,
        Confidence.LIKELY.value,
    ),
    (
        "SECRET.BEARER_TOKEN",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}"),
        "Potential bearer token detected.",
        "Do not hardcode Authorization bearer values.",
        Severity.HIGH.value,
        Confidence.LIKELY.value,
    ),
    (
        "SECRET.AWS_SECRET_KEY",
        re.compile(
            r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        "Potential AWS secret access key assignment detected.",
        "Rotate the secret and read it from the environment or AWS Secrets Manager.",
        Severity.CRITICAL.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.AZURE_CONNECTION",
        re.compile(r"(?i)\bAccountKey=[A-Za-z0-9+/=]{20,}"),
        "Potential Azure storage account key in connection string.",
        "Rotate the account key and store connection strings in a secret store.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.CONNECTION_STRING",
        re.compile(
            r"\b(?:postgresql|postgres|mysql|mariadb|mongodb|redis|amqp|rediss|mongodb\+srv)"
            r"://[^\s'\"<>]{8,}",
            re.IGNORECASE,
        ),
        "Potential database or broker connection string with credentials detected.",
        "Move credentials to environment variables and rotate the password.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
    (
        "SECRET.URL_CREDENTIALS",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+", re.IGNORECASE),
        "URL containing embedded user credentials detected.",
        "Strip credentials from URLs and inject them securely at runtime.",
        Severity.HIGH.value,
        Confidence.LIKELY.value,
    ),
    (
        "SECRET.API_KEY",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token"
            r"|client[_-]?secret|secret[_-]?key)\b\s*[:=]\s*['\"]"
            r"([A-Za-z0-9_\-./+=]{16,})['\"]"
        ),
        "Potential API credential assignment detected.",
        "Move the credential to an environment variable or secret manager.",
        Severity.HIGH.value,
        Confidence.LIKELY.value,
    ),
    (
        "SECRET.PASSWORD",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|db_password|db_pass)\b\s*[:=]\s*['\"]"
            r"([^'\"]{6,})['\"]"
        ),
        "Potential hardcoded password detected.",
        "Remove the password and load it from a secure configuration source.",
        Severity.HIGH.value,
        Confidence.LIKELY.value,
    ),
    (
        "SECRET.ENCRYPTION_KEY",
        re.compile(
            r"(?i)\b(?:encryption_key|secret_key|signing_key|private_key|jwt_secret"
            r"|session_secret)\b\s*[:=]\s*['\"]([A-Fa-f0-9]{32,}|[A-Za-z0-9+/=_-]{32,})['\"]"
        ),
        "Potential hardcoded cryptographic key detected.",
        "Store keys outside the codebase and rotate them.",
        Severity.CRITICAL.value,
        Confidence.LIKELY.value,
    ),
    (
        "SECRET.OAUTH_REFRESH",
        re.compile(
            r"(?i)\b(?:refresh_token|id_token|access_token)\b\s*[:=]\s*['\"]"
            r"([A-Za-z0-9._-]{20,})['\"]"
        ),
        "Potential hardcoded OAuth token detected.",
        "Do not persist tokens in source; refresh them at runtime.",
        Severity.HIGH.value,
        Confidence.LIKELY.value,
    ),
    (
        "SECRET.ENV_FILE_SECRET",
        re.compile(
            r"(?i)^\s*(?:[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY)[A-Z0-9_]*)="
            r"([^\s#\"']{8,})"
        ),
        "Potential secret value in environment-style assignment.",
        "Keep .env files out of version control and rotate exposed values.",
        Severity.HIGH.value,
        Confidence.LIKELY.value,
    ),
    (
        "SECRET.DOCKER_CONFIG",
        re.compile(r"\"auths\"\s*:\s*\{[^}]*\"auth\"\s*:\s*\"([A-Za-z0-9+/=]{20,})\""),
        "Potential Docker registry auth blob detected.",
        "Remove registry credentials from compose/config files.",
        Severity.HIGH.value,
        Confidence.HIGH.value,
    ),
]


class SecretScanner(Scanner):
    category = Category.SECRET.value

    def __init__(self) -> None:
        self._rules = list(_RULES)

    def scan_line(self, file: str, line_no: int, text: str) -> Sequence[Finding]:
        if not text or not text.strip():
            return []
        # Skip obvious placeholder / documentation examples with obvious fakes
        findings: list[Finding] = []
        for rule, pattern, message, remediation, severity, confidence in self._rules:
            m = pattern.search(text)
            if not m:
                continue
            raw = m.group(0)
            secret_val = m.group(1) if m.lastindex else raw
            if _is_likely_placeholder(secret_val, rule) or _is_likely_placeholder(
                raw, rule
            ):
                continue
            evidence = redact_secret(secret_val)
            articles: tuple[str, ...] = (_ART_5F, _ART_32)
            if rule.startswith("SECRET."):
                articles = (_ART_5F, _ART_32, _ART_33)
            findings.append(
                _finding(
                    rule,
                    file,
                    line_no,
                    message,
                    remediation,
                    severity=severity,
                    confidence=confidence,
                    evidence=evidence,
                    articles=articles,
                )
            )
        return findings


def _is_likely_placeholder(value: str, rule: str) -> bool:
    """Reduce obvious false positives in docs/tests/fixtures."""
    v = value.strip().strip("'\"")
    lowered = v.lower()
    # Only treat dedicated placeholder tokens as FPs — not hostnames like example.com
    exact_placeholders = {
        "example",
        "placeholder",
        "changeme",
        "redacted",
        "dummy",
        "fake",
        "sample",
        "your_api_key_here_please_change",
        "your_api_key_here",
        "xxx",
        "xxxx",
        "aaaa",
        "test123",
        "replaceme",
    }
    if lowered in exact_placeholders:
        return True
    # Assignment-style placeholders embedded in short secret-looking values
    embed_markers = (
        "your_",
        "your-",
        "example_",
        "example-",
        "placeholder",
        "changeme",
        "redacted",
        "dummy_",
        "fake_",
        "sample_",
        "<your",
        "${",
        "{{",
        "process.env",
        "os.environ",
        "os.getenv",
        "import.meta",
        "replaceme",
    )
    if any(p in lowered for p in embed_markers):
        return True
    # All same character repeated (aaaaaaaa…)
    alnum = [c for c in v if c.isalnum()]
    if len(alnum) >= 8 and len(set(alnum)) <= 2:
        return True
    if rule == "SECRET.OPENAI_KEY" and "sk-" in v:
        body = v.split("sk-", 1)[-1]
        # strip optional vendor segment
        for sep in ("proj-", "ant-", "or-", "svcacct-"):
            if body.startswith(sep):
                body = body[len(sep) :]
                break
        if body.isdigit() and len(body) < 20:
            return True
    return False
