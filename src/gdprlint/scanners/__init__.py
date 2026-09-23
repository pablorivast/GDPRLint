"""Scanner registry."""

from __future__ import annotations

from gdprlint.scanners.base import Scanner
from gdprlint.scanners.pii import PIIScanner
from gdprlint.scanners.secrets import SecretScanner
from gdprlint.scanners.security import SecurityScanner

__all__ = [
    "Scanner",
    "SecretScanner",
    "PIIScanner",
    "SecurityScanner",
    "default_scanners",
]


def default_scanners(*, flag_special_category: bool = True) -> list[Scanner]:
    return [
        SecretScanner(),
        PIIScanner(flag_special_category=flag_special_category),
        SecurityScanner(),
    ]
