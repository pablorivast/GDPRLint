"""Scanner contract shared by all detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Sequence

from laya_guard.finding import Finding


@dataclass(frozen=True)
class ScanContext:
    """Optional context passed to scanners (file extension hints, etc.)."""

    file: str

    @property
    def ext(self) -> str:
        name = self.file.rsplit("/", 1)[-1]
        if "." not in name:
            return ""
        return "." + name.rsplit(".", 1)[-1].lower()


class Scanner(ABC):
    """Base class: scan a single line, return zero or more findings."""

    category: str

    @abstractmethod
    def scan_line(self, file: str, line_no: int, text: str) -> Sequence[Finding]:
        """Return findings for one staged line (evidence must be redacted)."""

    def scan_all(self, items: Sequence[tuple[str, int, str]]) -> list[Finding]:
        findings: list[Finding] = []
        for file, line_no, text in items:
            findings.extend(self.scan_line(file, line_no, text))
        return findings
