"""Laya gate analyzer + rules-only fallback.

Uses the Laya System 1 decision engine locally (Router) to annotate findings
with typed answers. Never sends code to external APIs. Article tags are
contextual risk indicators only — not legal advice or compliance certification.
"""

from __future__ import annotations

import sys
from typing import Any, Protocol, Sequence

from gdprlint.config import Config
from gdprlint.finding import Finding

# Stable decision reason codes (machine-readable)
REASON_SUPPRESS_FP = "SUPPRESS_FALSE_POSITIVE"
REASON_ESCALATE_REVIEW = "ESCALATE_REVIEW"
REASON_BLOCK_SECRET_ROTATE = "BLOCK_SECRET_ROTATE"
REASON_FLAG_PRIVACY_REVIEW = "FLAG_PRIVACY_REVIEW"
REASON_FLAG_BREACH_CONTEXT = "FLAG_BREACH_CONTEXT"
REASON_LAYA_UNAVAILABLE = "LAYA_FALLBACK_RULES_ONLY"

# Neutral label keys (avoid noul/yes-no label bias on English checkpoint)
QUESTIONS: dict[str, Any] = {
    "true_positive": {
        "type": "choice",
        "instructions": (
            "Is this staged-code finding a real privacy or security exposure "
            "in production-bound code?"
        ),
        "criteria": {
            "A": "yes, a genuine exposure that should be addressed",
            "B": "no, false positive: documentation, tests, fixtures, examples, placeholders",
            "C": "uncertain, needs human review",
        },
    },
    "risk_level": {
        "type": "choice",
        "instructions": "If this finding is real, how severe is the exposure?",
        "criteria": {
            "critical": "live credential or direct national-ID/payment data exposure",
            "high": "sensitive credential or clear personal data exposure",
            "medium": "partial or low-sensitivity personal/security data",
            "low": "defense-in-depth or hardening issue",
        },
    },
    "data_nature": {
        "type": "choice",
        "instructions": "What is the nature of the data involved in this finding?",
        "criteria": {
            "A": "not personal data — credential or security-only issue",
            "B": "personal data of an identifiable person",
            "C": "special category or high-sensitivity personal data",
            "D": "uncertain whether it is personal data",
        },
    },
    "breach_amplifier": {
        "type": "choice",
        "instructions": (
            "If git history containing this change were exposed, "
            "how much would it amplify a data breach?"
        ),
        "criteria": {
            "A": "live credentials and/or personal data would be in history",
            "B": "limited impact even if history is exposed (test/ephemeral)",
            "C": "uncertain",
        },
    },
    "remediation_family": {
        "type": "choice",
        "instructions": "Which remediation family best fits this finding?",
        "criteria": {
            "remove": "delete from code; use secret manager or environment variable",
            "minimise": "reduce fields; avoid real personal data in the repository",
            "pseudonymise": "hash or tokenize identifiers; keep keys elsewhere",
            "harden": "fix insecure API or pattern; encryption and safe defaults",
            "rotate": "treat as compromised: rotate or revoke credential",
            "review": "needs human or privacy review before merge",
            "none": "no action beyond optional hygiene",
        },
    },
    "dpia_signal": {
        "type": "choice",
        "instructions": (
            "Does this change suggest large-scale or sensitive processing "
            "that a human privacy reviewer should look at?"
        ),
        "criteria": {
            "A": "yes, worth human privacy review (structural concern)",
            "B": "no elevated structural privacy concern from this diff alone",
            "C": "uncertain",
        },
    },
}


class Analyzer(Protocol):
    available: bool

    def analyze(self, findings: Sequence[Finding]) -> list[Finding]: ...


class RulesOnlyAnalyzer:
    """Fail-safe fallback: pass findings through unchanged."""

    available = False

    def analyze(self, findings: Sequence[Finding]) -> list[Finding]:
        return list(findings)


class LayaAnalyzer:
    """Gate-mode analyzer backed by Laya Router (local inference)."""

    available = False

    def __init__(
        self,
        config: Config,
        *,
        router: Any | None = None,
        stderr: Any | None = None,
    ) -> None:
        self.config = config
        self._router = router
        self._stderr = stderr if stderr is not None else sys.stderr
        self._load_error: str | None = None
        if not config.laya.enabled:
            self._load_error = "laya.enabled=false"
            return
        if router is None:
            try:
                from laya import Router  # type: ignore

                kwargs: dict[str, Any] = {}
                if config.laya.preload:
                    kwargs["preload"] = True
                # Force CPU when configured (hooks must not OOM competing GPU procs)
                if config.laya.device in {"cpu", "cuda"}:
                    kwargs["device"] = config.laya.device
                self._router = self._load_router_silently(Router, kwargs, config)
            except Exception as exc:  # noqa: BLE001 — degrade safely
                self._load_error = f"{type(exc).__name__}: {exc}"
                self._router = None
                return
        self.available = True

    @staticmethod
    def _load_router_silently(router_cls: Any, kwargs: dict[str, Any], config: Config) -> Any:
        """Instantiate Router while muting HF progress bars and laya RuntimeWarnings."""
        import os
        import warnings

        env = {
            "HF_HUB_DISABLE_PROGRESS_BARS": "1",
            "TQDM_DISABLE": "1",
            "TRANSFORMERS_VERBOSITY": "error",
        }
        prev = {k: os.environ.get(k) for k in env}
        try:
            for k, v in env.items():
                os.environ[k] = v
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message=r".*invalid temperatures.*",
                    module=r"laya(\.|$)",
                )
                warnings.filterwarnings(
                    "ignore",
                    message=r".*invalid temperatures.*",
                )
                try:
                    return router_cls(**kwargs)
                except TypeError:
                    # Older laya without device kwarg
                    slim = {k: v for k, v in kwargs.items() if k != "device"}
                    if config.laya.device == "cpu":
                        os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")
                    return router_cls(**slim)
        finally:
            for k, old in prev.items():
                if old is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = old

    @property
    def load_error(self) -> str | None:
        return self._load_error

    def analyze(self, findings: Sequence[Finding]) -> list[Finding]:
        if not findings:
            return []
        if not self.available or self._router is None:
            for line in [
                f"gdprlint: Laya unavailable ({self._load_error or 'disabled'}); "
                "running rules-only mode."
            ]:
                print(line, file=self._stderr)
            return list(findings)

        try:
            return self._predict(findings)
        except Exception as exc:  # noqa: BLE001
            print(
                f"gdprlint: Laya predict failed ({type(exc).__name__}: {exc}); "
                "running rules-only mode for this scan.",
                file=self._stderr,
            )
            return list(findings)

    def _state_for(self, f: Finding) -> dict[str, str]:
        # Privacy: evidence is already redacted; snippet stays short.
        return {
            "rule": f.rule,
            "category": f.category,
            "severity": f.severity,
            "base_confidence": f.confidence,
            "file": f.file,
            "line": str(f.line),
            "message": f.message,
            "evidence_redacted": f.evidence or "",
            "remediation": f.remediation,
            "related_articles": ",".join(f.related_articles),
        }

    def _predict(self, findings: Sequence[Finding]) -> list[Finding]:
        states = [self._state_for(f) for f in findings]
        questions = dict(QUESTIONS)
        if not self.config.laya.flag_dpia_signal:
            questions.pop("dpia_signal", None)

        results: list[Any]
        if hasattr(self._router, "predict_batch"):
            results = self._router.predict_batch(states, questions)
        else:
            results = [self._router.predict(s, questions) for s in states]

        out: list[Finding] = []
        for f, res in zip(findings, results):
            out.append(self._merge(f, res))
        return out

    def _choice(self, answers: dict[str, Any], key: str) -> tuple[str | None, float | None]:
        block = answers.get(key)
        if not isinstance(block, dict):
            return None, None
        # choice answers: {"choice": "A", "confidence": 0.9, "probabilities": {...}}
        label = block.get("choice")
        conf = block.get("confidence")
        try:
            conf_f = float(conf) if conf is not None else None
        except (TypeError, ValueError):
            conf_f = None
        if isinstance(label, str):
            return label, conf_f
        return None, conf_f

    def _merge(self, f: Finding, result: Any) -> Finding:
        answers: dict[str, Any] = {}
        if isinstance(result, dict):
            raw = result.get("answers")
            if isinstance(raw, dict):
                answers = raw

        tp_label, tp_conf = self._choice(answers, "true_positive")
        risk_label, risk_conf = self._choice(answers, "risk_level")
        nature_label, _ = self._choice(answers, "data_nature")
        breach_label, _ = self._choice(answers, "breach_amplifier")
        rem_label, _ = self._choice(answers, "remediation_family")
        dpia_label, _ = self._choice(answers, "dpia_signal")

        true_positive: bool | None = None
        if tp_label == "A":
            true_positive = True
        elif tp_label == "B":
            true_positive = False
        elif tp_label == "C":
            true_positive = None

        conf = tp_conf if tp_conf is not None else risk_conf

        # Map choice keys to internal enums where useful
        risk_map = {
            "critical": "critical",
            "critical ": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        risk = risk_map.get((risk_label or "").strip().lower())

        # Default decision left to engine; analyzer only annotates.
        return f.with_laya(
            true_positive=true_positive,
            risk=risk,
            confidence=conf,
            data_nature=nature_label,
            breach_amplifier=breach_label,
            remediation_family=rem_label,
            dpia_signal=dpia_label,
        )


def build_analyzer(config: Config, *, router: Any | None = None) -> Analyzer:
    if not config.laya.enabled:
        return RulesOnlyAnalyzer()
    return LayaAnalyzer(config, router=router)
