"""Orchestration: staged diff → scanners → Laya gate → technical decision."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from laya_guard.analyzer import (
    REASON_BLOCK_SECRET_ROTATE,
    REASON_ESCALATE_REVIEW,
    REASON_FLAG_BREACH_CONTEXT,
    REASON_FLAG_PRIVACY_REVIEW,
    REASON_LAYA_UNAVAILABLE,
    REASON_SUPPRESS_FP,
    Analyzer,
    build_analyzer,
)
from laya_guard.config import Config, load_config
from laya_guard.finding import (
    CommitDecision,
    Confidence,
    Decision,
    Finding,
    confidence_rank,
)
from laya_guard.git_ops import GitError, StagedDiff, get_staged_diff
from laya_guard.scanners import default_scanners


def run_scanners(
    diff: StagedDiff,
    config: Config,
    *,
    findings: list[Finding] | None = None,
) -> tuple[list[Finding], int]:
    """Scan staged added lines; return (findings, files_scanned)."""
    scanners = default_scanners(
        flag_special_category=config.laya.flag_special_category,
    )
    items = [(ln.path, ln.line_no, ln.text) for ln in diff.added_lines]
    raw: list[Finding] = []
    for scanner in scanners:
        raw.extend(scanner.scan_all(items))

    # Apply exclude patterns
    included: list[Finding] = []
    for f in raw:
        if config.is_excluded(f.file):
            continue
        if config.is_excepted(f.rule, f.file, f.line):
            continue
        included.append(f)

    files = [p for p in diff.files if not config.is_excluded(p)]
    return included, len(files)


def apply_gate_decisions(findings: Sequence[Finding], config: Config) -> list[Finding]:
    """Annotate each finding with a technical pipeline decision."""
    out: list[Finding] = []
    min_block = config.min_block_confidence
    for f in findings:
        action = config.action_for_rule(f.rule)
        if action == "off":
            out.append(f.with_laya(decision=Decision.ALLOW.value))
            continue

        # Suppress clear false positives from Laya when confident
        if (
            f.laya_true_positive is False
            and f.laya_confidence is not None
            and f.laya_confidence >= config.laya.suppress_fp_below
        ):
            out.append(_annotated(f, Decision.SUPPRESS_FP))
            continue

        base_blocks = (
            action == "block"
            and confidence_rank(f.confidence) >= confidence_rank(min_block)
        )
        laya_ok = True
        if f.laya_true_positive is False:
            # low-confidence FP: do not block on laya alone suppression
            if f.laya_confidence is None or f.laya_confidence < config.laya.min_confidence:
                laya_ok = False
        elif f.laya_true_positive is None and f.laya_confidence is not None:
            # uncertain — only block if base is high and laya not strongly negative
            if f.laya_confidence < config.laya.min_confidence:
                laya_ok = base_blocks  # still allow base rules to block high secrets

        if base_blocks and laya_ok:
            out.append(_annotated(f, Decision.BLOCK))
        elif f.laya_true_positive is None and (
            f.laya_confidence is None or f.laya_confidence < config.laya.min_confidence
        ):
            out.append(_annotated(f, Decision.ESCALATE_REVIEW))
        elif action == "warn":
            out.append(_annotated(f, Decision.WARN))
        else:
            out.append(_annotated(f, Decision.ALLOW))
    return out


def _annotated(f: Finding, decision: Decision) -> Finding:
    """Set laya_decision while preserving other laya_* fields."""
    from dataclasses import replace

    return replace(f, laya_decision=decision.value)


def decide(
    findings: Sequence[Finding],
    config: Config,
    *,
    files_scanned: int,
    laya_available: bool,
) -> CommitDecision:
    reasons: list[str] = []
    privacy_notes: list[str] = []
    action = "allow"
    exit_code = 0

    if not laya_available and config.laya.enabled:
        reasons.append(REASON_LAYA_UNAVAILABLE)

    blocking = [
        f
        for f in findings
        if f.laya_decision == Decision.BLOCK.value
        and not config.is_excluded(f.file)
        and not config.is_excepted(f.rule, f.file, f.line)
    ]
    warns = [f for f in findings if f.laya_decision in (Decision.WARN.value, Decision.ESCALATE_REVIEW.value)]
    suppressed = [f for f in findings if f.laya_decision == Decision.SUPPRESS_FP.value]

    if suppressed:
        reasons.append(REASON_SUPPRESS_FP)

    escalate = [f for f in findings if f.laya_decision == Decision.ESCALATE_REVIEW.value]
    if escalate and config.mode == "block":
        # Escalate is informational unless the finding is also block-class
        pass

    # Privacy review flags (GDPR contextual — informational).
    # Strict thresholds: Art. 9 only on explicit SPECIAL_CATEGORY rule hits;
    # Art. 35 only when a DPIA signal coexists with high-confidence PII.
    special = [f for f in findings if f.rule == "PII.SPECIAL_CATEGORY"]
    privacy_flagged = False
    if special and config.laya.flag_special_category:
        privacy_flagged = True
        if config.gdpr_context_enabled():
            privacy_notes.append(
                "Special-category or high-sensitivity personal data signal "
                "(contextual reference: Art. 9). Human privacy review suggested."
            )

    dpia = [f for f in findings if f.laya_dpia_signal == "A"]
    strong_pii = [
        f
        for f in findings
        if f.category == "pii"
        and (f.confidence == "high" or f.rule == "PII.SPECIAL_CATEGORY")
    ]
    if dpia and strong_pii and config.laya.flag_dpia_signal:
        privacy_flagged = True
        if config.gdpr_context_enabled():
            privacy_notes.append(
                "Change may relate to large-scale or sensitive processing "
                "(contextual reference: Art. 35). Not a DPIA determination."
            )
    if privacy_flagged:
        reasons.append(REASON_FLAG_PRIVACY_REVIEW)

    # Breach context: secrets + PII together, or amplifier A
    secrets = [f for f in findings if f.category == "secret"]
    piis = [f for f in findings if f.category == "pii"]
    if (secrets and piis) or any(f.laya_breach_amplifier == "A" for f in findings):
        if secrets and piis:
            reasons.append(REASON_FLAG_BREACH_CONTEXT)
            if config.gdpr_context_enabled() and secrets and piis:
                privacy_notes.append(
                    "Credentials and personal data appear in the same staged changeset "
                    "(contextual reference: Art. 33 risk indicator if history were exposed)."
                )

    if secrets and any(f.laya_remediation_family == "rotate" for f in secrets):
        reasons.append(REASON_BLOCK_SECRET_ROTATE)

    if config.mode == "off":
        action = "allow"
        exit_code = 0
    elif blocking:
        action = "block"
        exit_code = 1
    elif warns:
        action = "allow_warn"
        exit_code = 0
    else:
        action = "allow"
        exit_code = 0

    # GDPR context off → strip notes
    if not config.gdpr_context_enabled():
        privacy_notes = []

    return CommitDecision(
        action=action,
        exit_code=exit_code,
        reasons=reasons,
        privacy_notes=privacy_notes,
        findings=list(findings),
        files_scanned=files_scanned,
        laya_available=laya_available,
    )


def scan(
    cwd: Path | None = None,
    *,
    config: Config | None = None,
    analyzer: Analyzer | None = None,
    diff: StagedDiff | None = None,
) -> CommitDecision:
    """Full pipeline for ``laya-guard scan``."""
    cfg = config if config is not None else load_config(cwd)
    if diff is None:
        diff = get_staged_diff(cwd)

    raw_findings, files_scanned = run_scanners(diff, cfg)

    an = analyzer if analyzer is not None else build_analyzer(cfg)
    analyzed = an.analyze(raw_findings)
    gated = apply_gate_decisions(analyzed, cfg)

    return decide(
        gated,
        cfg,
        files_scanned=files_scanned,
        laya_available=getattr(an, "available", False),
    )
