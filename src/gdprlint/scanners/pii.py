"""PII detection — pattern rules with graduated confidence. No name detection."""

from __future__ import annotations

import re
from typing import Sequence

from gdprlint.finding import Category, Confidence, Finding, Severity
from gdprlint.redact import mask_digits, redact_email, redact_generic
from gdprlint.scanners.base import Scanner

_ART_5C = "5.1.c"
_ART_25 = "25"
_ART_9 = "9"
_ART_35 = "35"
_ART_32 = "32"


def _pii(
    rule: str,
    file: str,
    line: int,
    message: str,
    remediation: str,
    *,
    confidence: str,
    severity: str = Severity.MEDIUM.value,
    evidence: str,
    articles: tuple[str, ...] = (_ART_5C, _ART_25),
) -> Finding:
    return Finding(
        rule=rule,
        category=Category.PII.value,
        severity=severity,
        confidence=confidence,
        file=file,
        line=line,
        message=message,
        remediation=remediation,
        evidence=evidence,
        related_articles=articles,
    )


# --- Shared patterns -------------------------------------------------------

EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# International / ES phone: +34 612 345 679, 612345679, +1 555-123-4567
PHONE = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}(?!\w)"
)

# Spanish IBAN
IBAN_ES = re.compile(r"\bES\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{0,4}\b|\bES\d{22}\b")

# Common EU IBAN country codes (length validated loosely)
IBAN_INTL = re.compile(
    r"\b(?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BR|BY|CH|CR|CY|CZ|DE|DO|EE|EG|ES|FI|FO|FR|GB|GE|GI|GL|"
    r"GR|GT|HR|HU|IE|IL|IQ|IS|IT|JO|KW|KZ|LB|LC|LI|LT|LU|LV|LY|MC|MD|ME|MK|MR|MT|MU|NL|NO|"
    r"OM|PK|PL|PS|PT|QA|RO|RS|SA|SC|SE|SI|SK|SM|ST|SV|TL|TN|TR|UA|VA|VG|XK)"
    r"\d{2}[ ]?(?:[ ]?\d{4}){2,7}\d{0,2}\b"
)

BIC = re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")

SPANISH_DNI = re.compile(r"(?<!\d)\d{8}[A-Za-z](?!\d)")
SPANISH_NIE = re.compile(r"(?<![A-Za-z0-9])[XYZxyz]\d{7}[A-Za-z](?!\d)")

CREDIT_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

SSN_US = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
NHS_UK = re.compile(r"(?<!\d)\d{3}[ -]\d{3}[ -]\d{4}(?!\d)")
CPF_BR = re.compile(r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)")

IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
IPV6 = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"
    r"|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b"
)

MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")

GPS = re.compile(
    r"(?<!\d)(-?\d{1,2}\.\d{4,}),\s*(-?\d{1,3}\.\d{4,})(?!\d)"
)

DOB = re.compile(
    r"(?i)\b(?:born|birthdate|birth_date|dob|fecha\s+de\s+nacimiento)\b"
    r"[\s:=]+['\"]?\d{4}-\d{2}-\d{2}['\"]?"
    r"|\b(?:born|birthdate|dob)\b[\s:=]+['\"]?\d{1,2}[/-]\d{1,2}[/-]\d{2,4}['\"]?"
)

LICENSE_PLATE_ES = re.compile(r"(?<![A-Z0-9])\d{4}\s?[B-DF-HJ-NP-TV-Z]{3}(?![A-Z0-9])")

# Context keywords that raise confidence for weak formats
_DNI_CONTEXT = re.compile(r"(?i)\b(?:dni|nif|nie|documento\s+de\s+identidad|national\s+id)\b")
_PHONE_CONTEXT = re.compile(r"(?i)\b(?:tel[eé]fono|phone|mobile|m[oó]vil|contact\s+number)\b")
_PASSPORT_CONTEXT = re.compile(r"(?i)\b(?:pasaporte|passport)\b")
_PASSPORT_FORMAT = re.compile(r"(?<![A-Z0-9])[A-Z]\d{7}(?![A-Z0-9])")

# Special category (Art. 9) — strict context to limit FPs
_SPECIAL_HEALTH = re.compile(
    r"(?i)\b(?:diagnos[ei]s|diagn[oó]stico|patient|paciente|medical[_ ]?record"
    r"|historia[_ ]?cl[ií]nica|allerg(?:y|ies)|alergia|prescripci[oó]n|prescription"
    r"|icd-?10|nhs[_ ]?number|health[_ ]?insurance)\b"
)
_SPECIAL_BIOMETRIC = re.compile(
    r"(?i)\b(?:fingerprint|huella[_ ]?dactilar|iris[_ ]?scan|retina[_ ]?scan"
    r"|face[_ ]?embedding|biometric[_ ]?template)\b"
)
_SPECIAL_IDS = re.compile(
    r"(?<!\w)(?:\d{8}[A-Za-z]|[XYZ]\d{7}[A-Za-z]|\d{3}-\d{2}-\d{4})(?!\w)"
)

LOG_PII = re.compile(
    r"(?i)\b(?:console\.(?:log|info|error|warn)|logger\.(?:log|info|error|warn|debug)"
    r"|log(?:ger)?\s*\(|print(?:f)?\s*\(|System\.out)"
    r".*?\b(?:password|email|phone|ssn|iban|dni|token|secret)\b"
)

# Actual value interpolation / concatenation of a sensitive identifier into a log
LOG_PII_INTERPOLATION = re.compile(
    r"(?i)(?:"
    r"\$\{[^}]*\b(?:password|passwd|email|phone|ssn|iban|dni|token|secret)\b[^}]*\}"
    r"|\b(?:password|passwd|email|phone|ssn|iban|dni|token|secret)\b\s*\+"
    r"|\+\s*\b(?:password|passwd|email|phone|ssn|iban|dni|token|secret)\b"
    r"|(?:password|passwd|email|phone|ssn|iban|dni|token|secret)\s*,"
    r"|,\s*(?:password|passwd|email|phone|ssn|iban|dni|token|secret)\b"
    r"|\b(?:password|passwd|email|phone|ssn|iban|dni|token|secret)\s*[:=]"
    r")"
)

URL_WITH_PII = re.compile(
    r"(?i)[?&](?:email|e_mail|phone|tel|ssn|dni|iban|password|passwd|pwd"
    r"|username|user|token|access_token)=([^\s&\"']+)"
)

# Credential-only URL params — also covered by SECRET.CREDENTIALS_IN_URL (block)

# Placeholder / non-personal example addresses
_EMAIL_PLACEHOLDER_DOMAINS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "ejemplo.com",
        "ejemplo.org",
        "test.com",
        "test.local",
        "domain.com",
        "email.com",
        "sample.com",
        "localhost",
    }
)
_EMAIL_PLACEHOLDER_LOCALS = frozenset(
    {
        "user",
        "username",
        "name",
        "you",
        "yourname",
        "tucorreo",
        "tu_correo",
        "correo",
        "mail",
        "example",
        "ejemplo",
        "admin",
        "test",
        "demo",
        "foo",
        "bar",
        "noreply",
        "no-reply",
        "donotreply",
        "jenkins",
        "ci",
        "github",
    }
)

PRIVATE_IP_PREFIXES = (
    "127.",
    "10.",
    "192.168.",
    "0.0.0.0",
    "255.255.",
)


def _is_placeholder_email(email: str) -> bool:
    low = email.strip().lower()
    if "@" not in low:
        return True
    local, _, domain = low.partition("@")
    if domain in _EMAIL_PLACEHOLDER_DOMAINS:
        return True
    if local in _EMAIL_PLACEHOLDER_LOCALS:
        return True
    if local.startswith("tucorreo") or local.startswith("your"):
        return True
    if "noreply" in domain or "no-reply" in domain:
        return True
    if domain.endswith(".example") or domain.endswith(".test") or domain.endswith(".invalid"):
        return True
    return False


def _is_comment_line(text: str) -> bool:
    stripped = text.lstrip()
    if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("--"):
        return True
    if stripped.startswith("/*") or stripped.startswith("*"):
        return True
    return False


def _luhn_ok(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _context_near(text: str, pos: int, window: int = 48) -> str:
    start = max(0, pos - window)
    end = min(len(text), pos + window)
    return text[start:end]


class PIIScanner(Scanner):
    category = Category.PII.value

    def __init__(self, *, flag_special_category: bool = True) -> None:
        self.flag_special_category = flag_special_category

    def scan_line(self, file: str, line_no: int, text: str) -> Sequence[Finding]:
        if not text or not text.strip():
            return []
        findings: list[Finding] = []
        is_comment = _is_comment_line(text)

        # Email
        for m in EMAIL.finditer(text):
            if _is_placeholder_email(m.group(0)):
                continue
            conf = Confidence.POSSIBLE.value if is_comment else Confidence.HIGH.value
            findings.append(
                _pii(
                    "PII.EMAIL",
                    file,
                    line_no,
                    "Potential email address detected.",
                    "Avoid committing real personal emails; use fixtures or omit.",
                    confidence=conf,
                    severity=Severity.MEDIUM.value if conf == Confidence.HIGH.value else Severity.LOW.value,
                    evidence=redact_email(m.group(0)),
                )
            )

        # Spanish / intl IBAN (ES first to set high confidence)
        for m in IBAN_ES.finditer(text):
            findings.append(
                _pii(
                    "PII.IBAN",
                    file,
                    line_no,
                    "Potential Spanish IBAN detected.",
                    "Do not store bank account numbers in source; remove and rotate if real.",
                    confidence=Confidence.HIGH.value,
                    severity=Severity.HIGH.value,
                    evidence=mask_digits(m.group(0)),
                    articles=(_ART_5C, _ART_25),
                )
            )
        for m in IBAN_INTL.finditer(text):
            # Skip if already covered by ES pattern match on same span
            if any(f.line == line_no and f.rule == "PII.IBAN" and f.evidence for f in findings):
                # still add if not ES — check country code
                pass
            if m.group(0).startswith("ES"):
                continue
            findings.append(
                _pii(
                    "PII.IBAN",
                    file,
                    line_no,
                    "Potential international IBAN detected.",
                    "Do not store bank account numbers in source.",
                    confidence=Confidence.HIGH.value,
                    severity=Severity.HIGH.value,
                    evidence=mask_digits(m.group(0)),
                )
            )

        # Credit card (Luhn)
        for m in CREDIT_CARD.finditer(text):
            digits = re.sub(r"[^\d]", "", m.group(0))
            if len(digits) < 13 or len(digits) > 19:
                continue
            if not _luhn_ok(digits):
                continue
            # Skip if it looks like a timestamp-only long digit run without separators and not card prefix
            findings.append(
                _pii(
                    "PII.CREDIT_CARD",
                    file,
                    line_no,
                    "Potential payment card number (Luhn-valid) detected.",
                    "Remove card data immediately; never store PANs in the repository.",
                    confidence=Confidence.HIGH.value,
                    severity=Severity.CRITICAL.value,
                    evidence=mask_digits(m.group(0)),
                    articles=(_ART_5C, _ART_32, _ART_35),
                )
            )

        # Spanish DNI / NIE with context boost
        for m in SPANISH_DNI.finditer(text):
            near = _context_near(text, m.start())
            if _DNI_CONTEXT.search(near):
                conf = Confidence.LIKELY.value
            else:
                conf = Confidence.POSSIBLE.value
            findings.append(
                _pii(
                    "PII.SPANISH_ID",
                    file,
                    line_no,
                    "Potential Spanish DNI pattern detected.",
                    "Remove national ID numbers from the repository and test data.",
                    confidence=conf,
                    severity=Severity.HIGH.value,
                    evidence=mask_digits(m.group(0)),
                    articles=(_ART_5C, _ART_25),
                )
            )
        for m in SPANISH_NIE.finditer(text):
            near = _context_near(text, m.start())
            conf = (
                Confidence.LIKELY.value
                if _DNI_CONTEXT.search(near)
                else Confidence.POSSIBLE.value
            )
            findings.append(
                _pii(
                    "PII.SPANISH_ID",
                    file,
                    line_no,
                    "Potential Spanish NIE pattern detected.",
                    "Remove national ID numbers from the repository and test data.",
                    confidence=conf,
                    severity=Severity.HIGH.value,
                    evidence=mask_digits(m.group(0)),
                )
            )

        # Passport with context
        for m in _PASSPORT_FORMAT.finditer(text):
            near = _context_near(text, m.start())
            if _PASSPORT_CONTEXT.search(near):
                findings.append(
                    _pii(
                        "PII.PASSPORT",
                        file,
                        line_no,
                        "Potential passport number detected.",
                        "Remove passport numbers from source control.",
                        confidence=Confidence.LIKELY.value,
                        severity=Severity.HIGH.value,
                        evidence=mask_digits(m.group(0)),
                    )
                )

        # SSN US with context
        for m in SSN_US.finditer(text):
            near = _context_near(text, m.start())
            if re.search(r"(?i)\b(?:ssn|social\s+security)\b", near):
                findings.append(
                    _pii(
                        "PII.SSN_US",
                        file,
                        line_no,
                        "Potential US Social Security Number detected.",
                        "Remove SSN values from the repository.",
                        confidence=Confidence.LIKELY.value,
                        severity=Severity.HIGH.value,
                        evidence=mask_digits(m.group(0)),
                    )
                )
            else:
                # Still possible — format alone
                findings.append(
                    _pii(
                        "PII.SSN_US",
                        file,
                        line_no,
                        "Pattern matching US SSN format detected.",
                        "Verify this is not a real SSN; prefer synthetic test values.",
                        confidence=Confidence.POSSIBLE.value,
                        severity=Severity.MEDIUM.value,
                        evidence=mask_digits(m.group(0)),
                    )
                )

        # NHS UK with context
        for m in NHS_UK.finditer(text):
            near = _context_near(text, m.start())
            if re.search(r"(?i)\bnhs\b", near):
                findings.append(
                    _pii(
                        "PII.NHS_UK",
                        file,
                        line_no,
                        "Potential NHS number detected.",
                        "Remove NHS numbers from source.",
                        confidence=Confidence.LIKELY.value,
                        severity=Severity.HIGH.value,
                        evidence=mask_digits(m.group(0)),
                    )
                )

        # CPF BR with checksum-ish (basic digit count already in pattern)
        for m in CPF_BR.finditer(text):
            near = _context_near(text, m.start())
            conf = (
                Confidence.LIKELY.value
                if re.search(r"(?i)\bcpf\b", near)
                else Confidence.POSSIBLE.value
            )
            findings.append(
                _pii(
                    "PII.CPF_BR",
                    file,
                    line_no,
                    "Potential Brazilian CPF pattern detected.",
                    "Remove national IDs from the repository.",
                    confidence=conf,
                    severity=Severity.HIGH.value,
                    evidence=mask_digits(m.group(0)),
                )
            )

        # Phone — require phone context, leading +, or ES mobile shape.
        # Skip lockfiles, integrity hashes, and version-like digit runs.
        lower_file = file.lower()
        skip_phone_file = any(
            tok in lower_file
            for tok in (
                "lock",
                "package-lock",
                "yarn.lock",
                "pnpm-lock",
                "poetry.lock",
                "cargo.lock",
            )
        ) or lower_file.endswith(".lock")
        for m in PHONE.finditer(text):
            if skip_phone_file:
                continue
            raw = m.group(0)
            if "sha" in raw.lower() and "integrity" in text.lower():
                continue
            if re.search(r"(?i)\bintegrity\b", text) and "sha" in text.lower():
                # npm integrity lines
                if "sha512" in text.lower() or "sha1" in text.lower():
                    continue
            digits = re.sub(r"\D", "", raw)
            if len(digits) < 9 or len(digits) > 15:
                continue
            # Skip matches that are clearly IPs or card fragments already reported
            if IPV4.search(raw) and raw.count(".") == 3:
                continue
            if any(ch == "." for ch in raw) and raw.count(".") >= 3:
                continue
            near = _context_near(text, m.start())
            has_context = bool(_PHONE_CONTEXT.search(near))
            starts_plus = raw.strip().startswith("+")
            is_es_mobile = bool(
                re.fullmatch(r"(?:34)?[67]\d{2}[- ]?\d{3}[- ]?\d{3}", digits)
                or (len(digits) == 9 and digits[0] in "67")
            )
            if not (has_context or starts_plus or is_es_mobile):
                continue
            if has_context or starts_plus:
                conf = Confidence.LIKELY.value
            else:
                conf = Confidence.POSSIBLE.value
            # Avoid flagging pure years / short versions / npm ranges
            if len(digits) == 9 and digits[:2] in {"19", "20"} and digits[2:].isdigit():
                continue
            if re.fullmatch(r"\d{1,3}(?:\.\d+){1,4}", raw.strip()):
                continue
            findings.append(
                _pii(
                    "PII.PHONE",
                    file,
                    line_no,
                    "Potential telephone number detected.",
                    "Avoid committing personal phone numbers; use synthetic fixtures.",
                    confidence=conf,
                    severity=Severity.MEDIUM.value if conf != Confidence.POSSIBLE.value else Severity.LOW.value,
                    evidence=mask_digits(raw),
                )
            )

        # IPv4 public only
        for m in IPV4.finditer(text):
            ip = m.group(0)
            if ip.startswith(PRIVATE_IP_PREFIXES):
                continue
            if ip.startswith("172."):
                try:
                    second = int(ip.split(".")[1])
                    if 16 <= second <= 31:
                        continue
                except (ValueError, IndexError):
                    pass
            findings.append(
                _pii(
                    "PII.IP_ADDRESS",
                    file,
                    line_no,
                    "Potential public IPv4 address detected.",
                    "Confirm this is not a personal or customer endpoint.",
                    confidence=Confidence.LIKELY.value,
                    severity=Severity.LOW.value,
                    evidence=redact_generic(ip, 4, 4),
                )
            )

        # IPv6 global (skip ::1 and fe80 local)
        for m in IPV6.finditer(text):
            ip = m.group(0)
            if ip.startswith("::") or ip.lower().startswith("fe80") or ip == "::1":
                continue
            if ":" not in ip or ip.count(":") < 2:
                continue
            findings.append(
                _pii(
                    "PII.IP_ADDRESS",
                    file,
                    line_no,
                    "Potential IPv6 address detected.",
                    "Confirm this is not a personal or customer endpoint.",
                    confidence=Confidence.POSSIBLE.value,
                    severity=Severity.LOW.value,
                    evidence=redact_generic(ip, 4, 4),
                )
            )

        # MAC
        for m in MAC.finditer(text):
            findings.append(
                _pii(
                    "PII.MAC_ADDRESS",
                    file,
                    line_no,
                    "Potential MAC address detected.",
                    "Device identifiers may be personal data in some contexts; use synthetic values.",
                    confidence=Confidence.LIKELY.value,
                    severity=Severity.LOW.value,
                    evidence=redact_generic(m.group(0), 2, 2),
                )
            )

        # GPS
        for m in GPS.finditer(text):
            lat, lon = m.group(1), m.group(2)
            try:
                if not (-90 <= float(lat) <= 90 and -180 <= float(lon) <= 180):
                    continue
            except ValueError:
                continue
            # Skip version-like pairs
            if abs(float(lat)) < 1 and abs(float(lon)) < 1:
                continue
            findings.append(
                _pii(
                    "PII.GPS_COORDINATE",
                    file,
                    line_no,
                    "Potential GPS coordinate pair detected.",
                    "Locations can identify individuals; avoid committing real coordinates.",
                    confidence=Confidence.LIKELY.value,
                    severity=Severity.MEDIUM.value,
                    evidence=redact_generic(f"{lat},{lon}", 3, 3),
                )
            )

        # DOB
        for m in DOB.finditer(text):
            findings.append(
                _pii(
                    "PII.DATE_OF_BIRTH",
                    file,
                    line_no,
                    "Potential date of birth associated with a label.",
                    "Remove real birth dates from fixtures and code.",
                    confidence=Confidence.LIKELY.value,
                    severity=Severity.HIGH.value,
                    evidence=mask_digits(m.group(0)),
                )
            )

        # License plate ES with keyword nearby (reduce FPs)
        for m in LICENSE_PLATE_ES.finditer(text):
            near = _context_near(text, m.start())
            if re.search(r"(?i)\b(?:matr[ií]cula|license\s+plate|plate\s+number|veh[ií]culo)\b", near):
                findings.append(
                    _pii(
                        "PII.LICENSE_PLATE_ES",
                        file,
                        line_no,
                        "Potential Spanish license plate detected.",
                        "Vehicle identifiers can be personal data; remove if real.",
                        confidence=Confidence.LIKELY.value,
                        severity=Severity.MEDIUM.value,
                        evidence=mask_digits(m.group(0)),
                    )
                )

        # URL query PII
        for m in URL_WITH_PII.finditer(text):
            findings.append(
                _pii(
                    "PII.URL_WITH_PII",
                    file,
                    line_no,
                    "Personal data parameter in URL query string.",
                    "Avoid putting PII in URLs (logs, history, Referer leakage).",
                    confidence=Confidence.LIKELY.value,
                    severity=Severity.MEDIUM.value,
                    evidence=redact_generic(m.group(0), 12, 4),
                )
            )

        # Logging PII — only when a real log call interpolates/concatenates a
        # sensitive identifier (not bare keywords in api.login(...), warnings…)
        if LOG_PII.search(text) and LOG_PII_INTERPOLATION.search(text):
            findings.append(
                _pii(
                    "PII.LOG_PII",
                    file,
                    line_no,
                    "Logging statement may expose personal or secret data.",
                    "Redact sensitive fields before logging.",
                    confidence=Confidence.LIKELY.value,
                    severity=Severity.MEDIUM.value,
                    evidence=redact_generic(text.strip()[:80], 24, 8),
                )
            )

        # Special category Art. 9 — requires keyword + ID-like token on line
        if self.flag_special_category:
            special_hit = _SPECIAL_HEALTH.search(text) or _SPECIAL_BIOMETRIC.search(text)
            if special_hit:
                id_hit = (
                    _SPECIAL_IDS.search(text)
                    or EMAIL.search(text)
                    or PHONE.search(text)
                )
                if id_hit:
                    findings.append(
                        _pii(
                            "PII.SPECIAL_CATEGORY",
                            file,
                            line_no,
                            "Potential special-category personal data signal (health/biometric context).",
                            "Special-category data needs strict necessity, security and possibly a DPIA review.",
                            confidence=Confidence.LIKELY.value,
                            severity=Severity.HIGH.value,
                            evidence=redact_generic(id_hit.group(0), 4, 4),
                            articles=(_ART_5C, _ART_9, _ART_35),
                        )
                    )

        return findings
