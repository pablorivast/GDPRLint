"""Scanner registry."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, TextIO

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
    "load_plugin_scanners",
]

# Entry-point group third-party packages use to contribute scanners.
PLUGIN_GROUP = "gdprlint.scanners"


def load_plugin_scanners(*, err: TextIO | None = None) -> list[Scanner]:
    """Load scanners exposed by installed packages via entry points.

    Fail-safe: a plugin that cannot be loaded is reported to stderr and
    skipped so one broken package never breaks the whole scan.
    """
    out: list[Scanner] = []
    try:
        eps = entry_points(group=PLUGIN_GROUP)
    except Exception:  # noqa: BLE001 — broken metadata must not break scanning
        return out
    for ep in eps:
        try:
            obj = ep.load()
            candidate = obj() if isinstance(obj, type) or callable(obj) else obj
            if not isinstance(candidate, Scanner):
                raise TypeError("did not provide a Scanner class or factory")
            out.append(candidate)
        except Exception as exc:  # noqa: BLE001 — isolate plugin failures
            name = getattr(ep, "name", "<unknown>")
            print(f"gdprlint: plugin {name!r} failed to load: {exc}", file=err or sys.stderr)
    return out


def default_scanners(
    *,
    flag_special_category: bool = True,
    custom_rules: Sequence[CustomRule] = (),
    plugins: bool = True,
) -> list[Scanner]:
    scanners: list[Scanner] = [
        SecretScanner(),
        PIIScanner(flag_special_category=flag_special_category),
        SecurityScanner(),
    ]
    if custom_rules:
        scanners.append(CustomRuleScanner(custom_rules))
    if plugins:
        scanners.extend(load_plugin_scanners())
    return scanners
