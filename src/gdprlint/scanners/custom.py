"""Scanner for user-defined regex rules declared in ``custom_rules``."""

from __future__ import annotations

from collections.abc import Sequence

from gdprlint.config import CustomRule
from gdprlint.finding import Finding
from gdprlint.redact import redact_generic
from gdprlint.scanners.base import Scanner


class CustomRuleScanner(Scanner):
    """Match every custom rule against each line; evidence is redacted."""

    category = "secret"

    def __init__(self, rules: Sequence[CustomRule]) -> None:
        self.rules = list(rules)

    def scan_line(self, file: str, line_no: int, text: str) -> Sequence[Finding]:
        out: list[Finding] = []
        for rule in self.rules:
            m = rule.pattern.search(text)
            if m is None:
                continue
            out.append(
                Finding(
                    rule=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    file=file,
                    line=line_no,
                    message=rule.message,
                    remediation=rule.remediation,
                    evidence=redact_generic(m.group(0)),
                    related_articles=rule.articles,
                )
            )
        return out
