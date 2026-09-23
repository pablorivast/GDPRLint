"""Lightweight dangerous-pattern detection (not a full SAST)."""

from __future__ import annotations

import re
from typing import Sequence

from gdprlint.finding import Category, Confidence, Finding, Severity
from gdprlint.redact import redact_generic
from gdprlint.scanners.base import Scanner

_ART_32 = "32"
_ART_25 = "25"

_PY_TS_JS = {".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_WEB = {".js", ".jsx", ".ts", ".tsx", ".html", ".vue", ".svelte"}


def _sec(
    rule: str,
    file: str,
    line: int,
    message: str,
    remediation: str,
    *,
    confidence: str = Confidence.LIKELY.value,
    severity: str = Severity.MEDIUM.value,
    evidence: str,
    articles: tuple[str, ...] = (_ART_32, _ART_25),
) -> Finding:
    return Finding(
        rule=rule,
        category=Category.SECURITY.value,
        severity=severity,
        confidence=confidence,
        file=file,
        line=line,
        message=message,
        remediation=remediation,
        evidence=evidence,
        related_articles=articles,
    )


_EVAL = re.compile(r"(?<![A-Za-z0-9_])eval\s*\(")
_EXEC = re.compile(r"(?<![A-Za-z0-9_])exec\s*\(")
_OS_SYSTEM = re.compile(r"(?<![A-Za-z0-9_.])os\.(?:system|popen)\s*\(")
_SUBPROCESS_SHELL = re.compile(r"shell\s*=\s*True")
_CHILD_EXEC = re.compile(r"child_process\.(?:exec|execSync)\s*\(")
_DANGEROUS_HTML = re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=")
_SQL_CONCAT = re.compile(
    r"(?i)(?:query|sql|stmt)\s*=\s*['\"].*['\"]\s*\+"
    r"|['\"][^'\"]*SELECT[^'\"]*['\"]\s*\+"
    r"|\+\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)\b"
    # f-string / % interpolation of identifiers into SQL — not param placeholders
    r"|f['\"][^'\"]*\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^'\"]*\{"
    r"|(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^'\"\n]*['\"]\s*%\s*(?:\(|\w)"
)
_PICKLE = re.compile(r"pickle\.(?:loads|load)\s*\(|marshal\.loads\s*\(")
_YAML_UNSAFE = re.compile(r"(?<!Safe)yaml\.load\s*\(")
_WEAK_HASH = re.compile(r"(?i)\b(?:md5|sha1)\s*\(")
_TLS_OFF = re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false", re.IGNORECASE)
_CORS_WILDCARD = re.compile(
    r"(?i)access-control-allow-origin\s*['\"]?\s*:\s*['\"]\*['\"]"
    r"|Access-Control-Allow-Origin:\s*\*"
    # Express / Socket.IO wildcard CORS (common planted pattern)
    r"|\borigin\s*[:=]\s*['\"]\*['\"]"
    r"|(?<![\w.])cors\s*\(\s*\)"
    r"|cors\s*\(\s*\{\s*\}"
)
_LOG_CREDENTIAL = re.compile(
    r"(?i)\b(?:console\.(?:log|info|error|warn|debug)|logger?\.(?:log|info|error|warn|debug)"
    r"|log(?:ger)?\s*\(|print(?:f)?\s*\(|System\.out)"
    r".*?\b(?:password|passwd|token|secret|credential)s?\b"
)
_LOG_CREDENTIAL_INTERP = re.compile(
    r"(?i)(?:"
    r"\$\{[^}]*\b(?:password|passwd|token|secret)\b[^}]*\}"
    r"|\b(?:password|passwd|token|secret)\b\s*\+"
    r"|\+\s*\b(?:password|passwd|token|secret)\b"
    r"|(?:password|passwd|token|secret)\s*,"
    r"|,\s*(?:password|passwd|token|secret)\b"
    r"|\b(?:password|passwd|token|secret)\s*[:=]"
    r")"
)
_LOCALSTORAGE_SECRET = re.compile(
    r"(?i)(?:localStorage|sessionStorage)\.setItem\s*\("
    r"[^;]{0,200}?"
    r"\b(?:password|passwd|pass|pwd|token|secret|credential|auth_data)\b"
)
_DEBUG_TRUE = re.compile(r"(?i)\b(?:debug|flask_debug|django_debug)\s*=\s*True\b|\bdebug\s*:\s*true\b")
_WEAK_RANDOM = re.compile(
    r"(?i)(?:Math\.random|random\.(?:random|randint))\s*\([^)]*\).{0,40}?"
    r"(?:token|secret|password|session|key)|(?:token|secret|password|session|key).{0,40}?"
    r"(?:Math\.random|random\.(?:random|randint))"
)
_OPEN_REDIRECT = re.compile(
    r"(?i)redirect\s*\(\s*(?:request\.|req\.|params|query|user|input|url)"
)
_PATH_TRAVERSAL = re.compile(r"(?:\.\./|\.\.\\\\).{0,40}?(?:open|read|send_file|FileReader)")
_CMD_INJECTION = re.compile(
    r"(?i)(?:system|exec|popen|subprocess)\s*\(\s*['\"][^'\"]*%s"
    r"|os\.system\s*\(\s*['\"][^'\"]*\+"
)

_EXTENSIONS_HINT = {
    "SECURITY.EVAL": _PY_TS_JS,
    "SECURITY.EXEC": _PY_TS_JS,
    "SECURITY.OS_SYSTEM": {".py"},
    "SECURITY.SUBPROCESS_SHELL": {".py"},
    "SECURITY.CHILD_PROCESS_EXEC": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    "SECURITY.DANGEROUS_HTML": _WEB,
}


class SecurityScanner(Scanner):
    category = Category.SECURITY.value

    def _ext(self, file: str) -> str:
        name = file.rsplit("/", 1)[-1]
        if "." not in name:
            return ""
        return "." + name.rsplit(".", 1)[-1].lower()

    def scan_line(self, file: str, line_no: int, text: str) -> Sequence[Finding]:
        if not text or not text.strip():
            return []
        findings: list[Finding] = []
        ext = self._ext(file)
        stripped = text.strip()
        # Skip comment-only lines for some rules (heuristic)
        is_comment = stripped.startswith("#") or stripped.startswith("//")

        def maybe(
            rule: str,
            pattern: re.Pattern[str],
            message: str,
            remediation: str,
            *,
            confidence: str = Confidence.LIKELY.value,
            severity: str = Severity.MEDIUM.value,
            require_ext: bool = False,
            skip_comment: bool = True,
        ) -> None:
            if require_ext:
                allowed = _EXTENSIONS_HINT.get(rule)
                if allowed and ext not in allowed:
                    return
            if skip_comment and is_comment:
                return
            m = pattern.search(text)
            if not m:
                return
            findings.append(
                _sec(
                    rule,
                    file,
                    line_no,
                    message,
                    remediation,
                    confidence=confidence,
                    severity=severity,
                    evidence=redact_generic(m.group(0), 32, 8),
                )
            )

        maybe(
            "SECURITY.EVAL",
            _EVAL,
            "Dynamic eval() on staged code.",
            "Avoid eval on untrusted input; use explicit parsing or a safe interpreter.",
        )
        maybe(
            "SECURITY.EXEC",
            _EXEC,
            "Dynamic exec() on staged code.",
            "Avoid executing dynamically constructed code.",
        )
        maybe(
            "SECURITY.OS_SYSTEM",
            _OS_SYSTEM,
            "os.system/os.popen usage detected.",
            "Use subprocess with a list argv and shell=False.",
        )
        maybe(
            "SECURITY.SUBPROCESS_SHELL",
            _SUBPROCESS_SHELL,
            "subprocess invoked with shell=True.",
            "Pass arguments as a list and keep shell=False to avoid injection.",
        )
        maybe(
            "SECURITY.CHILD_PROCESS_EXEC",
            _CHILD_EXEC,
            "child_process.exec usage detected.",
            "Prefer execFile/spawn with argument arrays; avoid shell interpolation.",
        )
        maybe(
            "SECURITY.DANGEROUS_HTML",
            _DANGEROUS_HTML,
            "Potentially unsafe HTML injection sink.",
            "Sanitize untrusted content or use framework-safe rendering APIs.",
        )
        maybe(
            "SECURITY.SQL_CONCAT",
            _SQL_CONCAT,
            "Possible SQL built via string concatenation.",
            "Use parameterized queries / prepared statements.",
            confidence=Confidence.POSSIBLE.value,
            severity=Severity.HIGH.value,
            skip_comment=False,
        )
        maybe(
            "SECURITY.PICKLE_LOADS",
            _PICKLE,
            "Unsafe deserialization (pickle/marshal).",
            "Never unpickle untrusted data; use JSON or a safe format.",
            severity=Severity.HIGH.value,
        )
        maybe(
            "SECURITY.YAML_UNSAFE",
            _YAML_UNSAFE,
            "yaml.load without SafeLoader.",
            "Use yaml.safe_load for untrusted input.",
        )
        maybe(
            "SECURITY.WEAK_HASH",
            _WEAK_HASH,
            "Weak hash algorithm (MD5/SHA-1) referenced.",
            "Use SHA-256+ for integrity; use bcrypt/scrypt/argon2 for passwords.",
            confidence=Confidence.POSSIBLE.value,
            severity=Severity.LOW.value,
        )
        maybe(
            "SECURITY.TLS_VERIFY_OFF",
            _TLS_OFF,
            "TLS certificate verification disabled.",
            "Enable certificate verification in production paths.",
            severity=Severity.HIGH.value,
        )
        maybe(
            "SECURITY.CORS_WILDCARD",
            _CORS_WILDCARD,
            "CORS wildcard origin detected.",
            "Restrict Access-Control-Allow-Origin to trusted origins.",
            confidence=Confidence.LIKELY.value,
        )
        # Credential logging: require real interpolation of password/token
        if _LOG_CREDENTIAL.search(text) and _LOG_CREDENTIAL_INTERP.search(text):
            findings.append(
                _sec(
                    "SECURITY.LOG_CREDENTIAL",
                    file,
                    line_no,
                    "Credential or token may be written to logs.",
                    "Never log passwords or tokens; redact sensitive fields.",
                    confidence=Confidence.HIGH.value,
                    severity=Severity.HIGH.value,
                    evidence=redact_generic(text.strip()[:80], 32, 8),
                )
            )
        maybe(
            "SECURITY.LOCALSTORAGE_SECRET",
            _LOCALSTORAGE_SECRET,
            "Credential or token stored in browser localStorage/sessionStorage.",
            "Do not persist passwords or long-lived tokens in web storage; use memory or httpOnly cookies.",
            confidence=Confidence.HIGH.value,
            severity=Severity.HIGH.value,
            skip_comment=False,
        )
        maybe(
            "SECURITY.DEBUG_TRUE",
            _DEBUG_TRUE,
            "Debug mode appears enabled in code.",
            "Ensure debug is off outside local development.",
            confidence=Confidence.POSSIBLE.value,
            severity=Severity.MEDIUM.value,
        )
        maybe(
            "SECURITY.WEAK_RANDOM_SECRET",
            _WEAK_RANDOM,
            "Weak RNG associated with a security-sensitive name.",
            "Use secrets/token generators for credentials and session IDs.",
            confidence=Confidence.POSSIBLE.value,
            severity=Severity.HIGH.value,
        )
        maybe(
            "SECURITY.OPEN_REDIRECT",
            _OPEN_REDIRECT,
            "Possible open redirect from user-controlled input.",
            "Validate redirect targets against an allow-list.",
            confidence=Confidence.POSSIBLE.value,
        )
        maybe(
            "SECURITY.PATH_TRAVERSAL",
            _PATH_TRAVERSAL,
            "Possible path traversal concatenation.",
            "Resolve paths safely and reject '..' segments.",
            confidence=Confidence.POSSIBLE.value,
            severity=Severity.HIGH.value,
        )
        maybe(
            "SECURITY.COMMAND_INJECTION",
            _CMD_INJECTION,
            "Possible command injection pattern.",
            "Avoid shell strings built from input; use argument arrays.",
            confidence=Confidence.POSSIBLE.value,
            severity=Severity.HIGH.value,
        )

        return findings
