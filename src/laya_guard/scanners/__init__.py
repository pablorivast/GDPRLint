"""Scanner registry."""

from __future__ import annotations

from laya_guard.scanners.base import Scanner
from laya_guard.scanners.pii import PIIScanner
from laya_guard.scanners.secrets import SecretScanner
from laya_guard.scanners.security import SecurityScanner

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
