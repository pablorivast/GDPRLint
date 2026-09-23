"""Shared finding model produced by every scanner and refined by Laya."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    POSSIBLE = "possible"
    LIKELY = "likely"
    HIGH = "high"


class Category(str, Enum):
    SECRET = "secret"
    PII = "pii"
    SECURITY = "security"


class Decision(str, Enum):
    """Technical pipeline decision for a finding (not a legal determination)."""

    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"
    SUPPRESS_FP = "suppress_fp"
    ESCALATE_REVIEW = "escalate_review"


# Confidence ordering for thresholds
_CONFIDENCE_ORDER: dict[str, int] = {
    Confidence.POSSIBLE.value: 0,
    Confidence.LIKELY.value: 1,
    Confidence.HIGH.value: 2,
}


def confidence_rank(value: str | Confidence) -> int:
    raw = value.value if isinstance(value, Confidence) else value
    return _CONFIDENCE_ORDER.get(raw, -1)


@dataclass(frozen=True)
class Finding:
    """A single detection, with evidence already redacted for display."""

    rule: str
    category: str
    severity: str
    confidence: str
    file: str
    line: int
    message: str
    remediation: str
    evidence: str | None = None
    related_articles: tuple[str, ...] = field(default_factory=tuple)
    # Populated by LayaAnalyzer (gate mode)
    laya_true_positive: bool | None = None
    laya_risk: str | None = None
    laya_confidence: float | None = None
    laya_data_nature: str | None = None
    laya_breach_amplifier: str | None = None
    laya_remediation_family: str | None = None
    laya_dpia_signal: str | None = None
    laya_decision: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["related_articles"] = list(self.related_articles)
        return data

    def with_laya(
        self,
        *,
        true_positive: bool | None = None,
        risk: str | None = None,
        confidence: float | None = None,
        data_nature: str | None = None,
        breach_amplifier: str | None = None,
        remediation_family: str | None = None,
        dpia_signal: str | None = None,
        decision: str | None = None,
    ) -> Finding:
        return replace(
            self,
            laya_true_positive=true_positive,
            laya_risk=risk,
            laya_confidence=confidence,
            laya_data_nature=data_nature,
            laya_breach_amplifier=breach_amplifier,
            laya_remediation_family=remediation_family,
            laya_dpia_signal=dpia_signal,
            laya_decision=decision,
        )


@dataclass
class CommitDecision:
    """Aggregate technical decision for the staged changeset."""

    action: str  # allow | allow_warn | block
    exit_code: int
    reasons: list[str] = field(default_factory=list)
    privacy_notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    laya_available: bool = False
