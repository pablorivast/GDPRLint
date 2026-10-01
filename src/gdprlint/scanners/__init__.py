"""Scanner registry."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from gdprlint.scanners.base import Scanner
from gdprlint.scanners.custom import CustomRuleScanner
from gdprlint.scanners.pii import PIIScanner
from gdprlint.scanners.secrets import SecretScanner
from gdprlint.scanners.security import SecurityScanner

if TYPE_CHECKING:
    from gdprlint.config import CustomRule

__all__ = [
    "CustomRuleScanner",
    "PIIScanner",
    "Scanner",
    "SecretScanner",
    "SecurityScanner",
    "default_scanners",
]


def default_scanners(
    *,
    flag_special_category: bool = True,
    custom_rules: Sequence[CustomRule] = (),
) -> list[Scanner]:
    scanners: list[Scanner] = [
        SecretScanner(),
        PIIScanner(flag_special_category=flag_special_category),
        SecurityScanner(),
    ]
    if custom_rules:
        scanners.append(CustomRuleScanner(custom_rules))
    return scanners
