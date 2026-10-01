"""Console and machine-readable reports for scan results. Never prints full secrets."""

from __future__ import annotations

import json
from typing import Any, TextIO

from gdprlint import __version__
from gdprlint.finding import CommitDecision, Decision, Finding

DIVIDER = "────────────────────────────────────────"
DISCLAIMER = (
    "GDPRLint is a technical privacy and security guardrail. "
    "It does not certify legal or GDPR compliance."
)
JSON_SCHEMA = "gdprlint/report/v1"


def _severity_rank(f: Finding) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(f.severity, 9)


def _print_finding(out: TextIO, f: Finding, *, show_gdpr: bool) -> None:
    print(f"\n{f.rule}", file=out)
    print(f"{f.file}:{f.line}", file=out)
    print(file=out)
    print(f"  {f.message}", file=out)
    conf = f.confidence
    risk = f" | Laya risk: {f.laya_risk}" if f.laya_risk else ""
    tp = (
        f" | Laya TP: {f.laya_confidence:.2f}"
        if f.laya_true_positive is not None and f.laya_confidence is not None
        else ""
    )
    print(f"  Confidence: {conf}{risk}{tp}", file=out)
    if f.evidence:
        print(f"  Match: {f.evidence}", file=out)
    print(file=out)
    print("  Recommendation:", file=out)
    for chunk in f.remediation.split(". "):
        sentence = chunk.strip().rstrip(".")
        if sentence:
            print(f"    {sentence}.", file=out)
    if f.laya_remediation_family and f.laya_remediation_family != "none":
        print(f"    Family: {f.laya_remediation_family}", file=out)
    if show_gdpr and f.related_articles:
        arts = ", ".join(f"Art. {a}" for a in f.related_articles)
        print(file=out)
        print("  Related GDPR context (not a legal assessment):", file=out)
        print(f"    {arts}", file=out)


def render_blocked(decision: CommitDecision, out: TextIO) -> None:
    print("GDPRLint", file=out)
    print(DIVIDER, file=out)
    print(file=out)

    shown = [
        f
        for f in decision.findings
        if f.laya_decision
        in (Decision.BLOCK.value, Decision.ESCALATE_REVIEW.value, Decision.WARN.value)
    ]
    # Prefer block decisions first
    blocking = [f for f in decision.findings if f.laya_decision == Decision.BLOCK.value]
    others = [f for f in shown if f not in blocking]
    ordered = sorted(blocking, key=_severity_rank) + sorted(others, key=_severity_rank)

    if blocking:
        print(f"✗ {len(blocking)} high-confidence issue(s) found", file=out)
    else:
        print(f"✗ {len(ordered)} issue(s) found", file=out)
    print(DIVIDER, file=out)

    show_gdpr = (
        "FLAG_PRIVACY_REVIEW" in decision.reasons
        or "FLAG_BREACH_CONTEXT" in decision.reasons
    )
    # Show all blocking + escalate findings; cap long lists
    display = ordered[:20]
    for f in display:
        _print_finding(out, f, show_gdpr=show_gdpr)

    if len(ordered) > len(display):
        print(file=out)
        print(f"… and {len(ordered) - len(display)} more findings", file=out)

    if decision.privacy_notes:
        print(file=out)
        print("Privacy notes (contextual, not legal advice):", file=out)
        for note in decision.privacy_notes:
            print(f"  • {note}", file=out)

    if not decision.laya_available:
        print(file=out)
        print("⚠ Laya unavailable — rules-only mode", file=out)

    print(file=out)
    print("The staged changes contain potential exposures.", file=out)
    print("Remove the issue or explicitly configure an exception in .gdprlint.json.", file=out)
    print(file=out)
    print("Commit blocked.", file=out)
    print(file=out)
    print(DISCLAIMER, file=out)


def render(decision: CommitDecision, out: TextIO, *, fmt: str = "text") -> None:
    """Single entry used by CLI. ``fmt`` is ``text``, ``json`` or ``sarif``."""
    if fmt == "json":
        render_json(decision, out)
        return
    if fmt == "sarif":
        render_sarif(decision, out)
        return
    render_text(decision, out)


def _counts(findings: list[Finding]) -> dict[str, int]:
    by_category = {"secret": 0, "pii": 0, "security": 0}
    blocking = 0
    suppressed = 0
    for f in findings:
        if f.category in by_category:
            by_category[f.category] += 1
        if f.laya_decision == Decision.BLOCK.value:
            blocking += 1
        elif f.laya_decision == Decision.SUPPRESS_FP.value:
            suppressed += 1
    return {
        "total": len(findings),
        "blocking": blocking,
        "suppressed": suppressed,
        **by_category,
    }


def report_dict(decision: CommitDecision) -> dict[str, Any]:
    """Machine-readable report (JSON schema ``gdprlint/report/v1``)."""
    return {
        "schema": JSON_SCHEMA,
        "tool": {"name": "gdprlint", "version": __version__},
        "action": decision.action,
        "blocked": decision.action == "block",
        "exit_code": decision.exit_code,
        "files_scanned": decision.files_scanned,
        "mode": decision.mode,
        "laya_available": decision.laya_available,
        "reasons": list(decision.reasons),
        "privacy_notes": list(decision.privacy_notes),
        "counts": _counts(list(decision.findings)),
        "findings": [f.to_dict() for f in decision.findings],
        "disclaimer": DISCLAIMER,
    }


def render_json(decision: CommitDecision, out: TextIO) -> None:
    json.dump(report_dict(decision), out, indent=2, ensure_ascii=False)
    out.write("\n")


def _sarif_level(f: Finding) -> str | None:
    """Map the per-finding pipeline decision to a SARIF level (None → omit)."""
    if f.laya_decision == Decision.BLOCK.value:
        return "error"
    if f.laya_decision in (Decision.WARN.value, Decision.ESCALATE_REVIEW.value):
        return "warning"
    if f.laya_decision == Decision.SUPPRESS_FP.value:
        return None
    return "note"


def _sarif_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.rule in rules or _sarif_level(f) is None:
            continue
        rules[f.rule] = {
            "id": f.rule,
            "name": f.rule.replace(".", "_"),
            "shortDescription": {"text": f.message},
            "help": {"text": f.remediation},
            "properties": {"category": f.category},
        }
    return list(rules.values())


def sarif_dict(decision: CommitDecision) -> dict[str, Any]:
    """SARIF 2.1.0 report (GitHub code-scanning compatible)."""
    findings = list(decision.findings)
    results: list[dict[str, Any]] = []
    for f in findings:
        level = _sarif_level(f)
        if level is None:
            continue
        results.append(
            {
                "ruleId": f.rule,
                "level": level,
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": max(f.line, 1)},
                        }
                    }
                ],
                "properties": {
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "laya_decision": f.laya_decision,
                    "related_articles": list(f.related_articles),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GDPRLint",
                        "version": __version__,
                        "informationUri": "https://github.com/pablorivast/GDPRLint",
                        "rules": _sarif_rules(findings),
                    }
                },
                "results": results,
                "properties": {
                    "action": decision.action,
                    "exit_code": decision.exit_code,
                    "files_scanned": decision.files_scanned,
                    "mode": decision.mode,
                    "laya_available": decision.laya_available,
                    "reasons": list(decision.reasons),
                    "disclaimer": DISCLAIMER,
                },
            }
        ],
    }


def render_sarif(decision: CommitDecision, out: TextIO) -> None:
    json.dump(sarif_dict(decision), out, indent=2, ensure_ascii=False)
    out.write("\n")


def render_text(decision: CommitDecision, out: TextIO) -> None:
    if decision.action == "block":
        render_blocked(decision, out)
        return

    visible = [
        f
        for f in decision.findings
        if f.laya_decision != Decision.SUPPRESS_FP.value
    ]

    print("GDPRLint", file=out)
    print(DIVIDER, file=out)
    print(file=out)
    print(f"✓ {decision.files_scanned} files scanned", file=out)

    secrets = [f for f in visible if f.category == "secret"]
    pii_high = [
        f
        for f in visible
        if f.category == "pii" and f.confidence == "high"
    ]
    security = [f for f in visible if f.category == "security"]
    # Everything visible that is not already counted above
    counted_ids = {id(f) for f in (*secrets, *pii_high, *security)}
    additional = [f for f in visible if id(f) not in counted_ids]

    print(f"✓ {len(secrets)} secrets", file=out)
    print(f"✓ {len(pii_high)} high-confidence PII findings", file=out)
    if additional:
        print(f"✓ {len(additional)} additional warnings", file=out)
    print(f"✓ {len(security)} security findings", file=out)

    if "FLAG_PRIVACY_REVIEW" in decision.reasons or "FLAG_BREACH_CONTEXT" in decision.reasons:
        print("✓ privacy review flags", file=out)

    print(file=out)
    if not decision.laya_available:
        print("⚠ Laya unavailable — rules-only mode", file=out)
        print(file=out)

    if visible:
        print("Warnings (non-blocking):", file=out)
        for f in visible[:15]:
            print(f"  • {f.rule} {f.file}:{f.line} — {f.message}", file=out)
        if len(visible) > 15:
            print(f"  … and {len(visible) - 15} more", file=out)
        print(file=out)

    if decision.privacy_notes:
        print("Privacy notes (contextual, not legal advice):", file=out)
        for note in decision.privacy_notes:
            print(f"  • {note}", file=out)
        print(file=out)

    print("Commit allowed.", file=out)
