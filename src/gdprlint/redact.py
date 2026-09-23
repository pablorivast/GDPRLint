"""Evidence redaction — never print full secrets or raw PII."""

from __future__ import annotations

import re

# Keep a short recognizable prefix (vendor tag) and last 4 chars when long enough.
_PREFIX_KEEP = 12
_SUFFIX_KEEP = 4


def redact_secret(value: str) -> str:
    """Redact a secret for display: ``sk-proj-************9f2a``."""
    if not value:
        return ""
    # Strip surrounding quotes the matcher may have included
    v = value.strip().strip("'\"")
    if len(v) <= _PREFIX_KEEP + _SUFFIX_KEEP:
        return "*" * min(len(v), 8)
    # Prefer keeping vendor-ish prefix up to first non-alnum boundary
    prefix = v[:_PREFIX_KEEP]
    # Trim prefix at a hyphen/underscore boundary if present within keep window
    m = re.match(r"^([A-Za-z0-9]+[-_])", v)
    if m and len(m.group(1)) <= _PREFIX_KEEP:
        prefix = m.group(1)
    suffix = v[-_SUFFIX_KEEP:]
    body_len = max(len(v) - len(prefix) - len(suffix), 4)
    return f"{prefix}{'*' * body_len}{suffix}"


def redact_email(value: str) -> str:
    """Partially mask an email: ``j***@e***.com``."""
    v = value.strip()
    if "@" not in v:
        return redact_secret(v)
    local, _, domain = v.partition("@")
    def mask_part(part: str) -> str:
        if not part:
            return "*"
        if len(part) <= 2:
            return part[0] + "*"
        return part[0] + "*" * max(len(part) - 2, 1) + part[-1]
    return f"{mask_part(local)}@{mask_part(domain)}"


def redact_generic(value: str, keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    v = value.strip()
    if len(v) <= keep_prefix + keep_suffix:
        return "*" * min(len(v), 8)
    return f"{v[:keep_prefix]}{'*' * max(len(v) - keep_prefix - keep_suffix, 4)}{v[-keep_suffix:]}"


def mask_digits(value: str) -> str:
    """Keep structure but hide digits: ``****-**-1234`` style for IDs/IBANs."""
    if not value:
        return ""
    # Keep last 4 alphanumeric chars visible
    alnum = [c for c in value if c.isalnum()]
    if len(alnum) <= 4:
        return "*" * len(value)
    visible_tail = "".join(alnum[-4:])
    # Rebuild: mask all but last 4 alnum
    out = []
    remaining = 4
    for i, c in enumerate(value):
        if c.isalnum():
            # count from end
            alnum_index = sum(1 for x in value[: i + 1] if x.isalnum())
            if alnum_index > len(alnum) - 4:
                out.append(c)
            else:
                out.append("*")
        else:
            out.append(c)
    # Ensure tail present
    result = "".join(out)
    if not result.endswith(visible_tail):
        result = result + f"…{visible_tail}" if len(result) > 4 else "*" * len(value)
    return result
