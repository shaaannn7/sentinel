"""
SENTINEL Brain — Main Orchestrator
====================================
Single entry point for all brain intelligence.

Usage
-----
  from app.brain.orchestrator import Brain

  result = Brain.analyse(parsed_email, deterministic_score, investigation_id)
  # result.verdict   → "MALICIOUS" | "PHISHING" | "SUSPICIOUS" | "BENIGN"
  # result.risk_score → 0–100
  # result.report    → full structured report dict

Architecture
------------
  ParsedEmail
       │
       ├─── Feature extractor (80 signals)
       │         │
       │         └─→ ML Ensemble Classifier  ──┐
       │                                        │
       ├─── Advanced Rule Engine (200+ rules) ──┤──→ Weighted Fusion ──→ Final Verdict
       │                                        │
       └─── Threat Memory Store ────────────────┘
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BrainResult:
    """Full intelligence output from the brain."""
    verdict:       str            # BENIGN / SUSPICIOUS / PHISHING / MALICIOUS
    risk_score:    int            # 0 – 100
    confidence:    str            # LOW / MEDIUM / HIGH
    explanation:   str            # human-readable summary
    ml_prediction: Dict[str, Any] = field(default_factory=dict)
    rule_signals:  List[Dict[str, Any]] = field(default_factory=list)
    report:        Dict[str, Any] = field(default_factory=dict)
    elapsed_ms:    int = 0


class Brain:
    """
    Stateless orchestrator — all state lives in singletons (classifier, memory).
    """

    @staticmethod
    def analyse(
        parsed: Any,
        deterministic_score: Any,          # ScoreResult from scoring/engine.py
        investigation_id: Optional[str] = None,
        persist_memory: bool = True,
    ) -> BrainResult:
        """
        Run the full brain pipeline and return a BrainResult.

        Parameters
        ----------
        parsed               : ParsedEmail object from the email parser
        deterministic_score  : ScoreResult from app.services.scoring.engine
        investigation_id     : str | None  — used for memory correlation
        persist_memory       : bool — record this verdict in the threat memory store
        """
        t0 = time.perf_counter()

        # ── 1. Advanced Rule Engine ──────────────────────────────────────
        rule_result = _run_rule_engine(parsed)

        # ── 2. Ensemble Fusion (ML + Rules + Memory) ─────────────────────
        fusion = _run_ensemble(parsed, deterministic_score, rule_result, investigation_id)

        # ── 3. Final verdict (fusion wins over deterministic alone) ───────
        verdict     = fusion["verdict"]
        risk_score  = fusion["risk_score"]
        confidence  = fusion["confidence"]
        explanation = fusion["explanation"]

        # ── 4. Record in threat memory ───────────────────────────────────
        if persist_memory and verdict in ("PHISHING", "MALICIOUS", "SUSPICIOUS"):
            try:
                from app.brain.memory.store import MemoryStore
                MemoryStore.get().record(parsed, verdict, investigation_id)
            except Exception as exc:
                logger.warning("brain.orchestrator: memory record failed — %s", exc)

        elapsed = int((time.perf_counter() - t0) * 1000)

        # ── 5. Build full report ─────────────────────────────────────────
        report = _build_report(fusion, rule_result, deterministic_score, elapsed)

        result = BrainResult(
            verdict      = verdict,
            risk_score   = risk_score,
            confidence   = confidence,
            explanation  = explanation,
            ml_prediction= fusion.get("ml_prediction", {}),
            rule_signals = [_signal_to_dict(s) for s in rule_result.signals],
            report       = report,
            elapsed_ms   = elapsed,
        )
        logger.info(
            "brain.orchestrator: inv=%s verdict=%s score=%d ml=%s rules=%s elapsed=%dms",
            investigation_id or "?", verdict, risk_score,
            fusion.get("ml_label", "?"),
            rule_result.verdict,
            elapsed,
        )
        return result

    @staticmethod
    def retrain(n_per_class: int = 3000) -> Dict[str, Any]:
        """Retrain the ML model and return evaluation metrics."""
        from app.brain.ml.classifier import BrainClassifier
        return BrainClassifier.get().retrain(n_per_class=n_per_class)

    @staticmethod
    def memory_stats() -> Dict[str, Any]:
        from app.brain.memory.store import MemoryStore
        return MemoryStore.get().stats()

    @staticmethod
    def confirm_threat(investigation_id: str, parsed: Any, verdict: str = "PHISHING") -> None:
        from app.brain.memory.store import MemoryStore
        MemoryStore.get().confirm_threat(investigation_id, parsed, verdict)

    @staticmethod
    def confirm_safe(investigation_id: str) -> None:
        from app.brain.memory.store import MemoryStore
        MemoryStore.get().confirm_safe(investigation_id)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_rule_engine(parsed: Any):
    try:
        from app.brain.rules.engine import AdvancedRuleEngine
        return AdvancedRuleEngine().evaluate(parsed)
    except Exception as exc:
        logger.error("brain.orchestrator: rule engine failed — %s", exc)
        from app.brain.rules.engine import RuleEngineResult
        return RuleEngineResult()


def _run_ensemble(
    parsed: Any,
    deterministic_score: Any,
    rule_result: Any,
    investigation_id: Optional[str],
) -> Dict[str, Any]:
    try:
        from app.brain.ensemble.engine import get_engine
        fusion = get_engine().analyse(parsed, deterministic_score, investigation_id)
        # Blend with advanced rule verdict
        fusion["ml_prediction"] = {
            "label":        fusion.pop("ml_label", "?"),
            "confidence":   fusion.pop("ml_confidence", 0.0),
            "probabilities": fusion.pop("ml_probabilities", {}),
        }
        # Override if advanced rules are more severe
        _severity_idx = {"BENIGN": 0, "SUSPICIOUS": 1, "PHISHING": 2, "MALICIOUS": 3}
        if _severity_idx.get(rule_result.verdict, 0) > _severity_idx.get(fusion["verdict"], 0):
            # Boost the fused verdict by the rule engine signal
            fusion["verdict"] = rule_result.verdict
            fusion["risk_score"] = min(100, max(fusion["risk_score"], rule_result.total_points))
            fusion["explanation"] += f" Advanced rule engine elevated verdict to {rule_result.verdict}."
        return fusion
    except Exception as exc:
        logger.error("brain.orchestrator: ensemble failed — %s", exc)
        # Graceful fallback to deterministic-only
        score = getattr(deterministic_score, "score", 0)
        verdict = getattr(deterministic_score, "verdict", "BENIGN").upper()
        return {
            "verdict":          verdict,
            "risk_score":       int(score),
            "confidence":       "LOW",
            "fused_threat_prob": score / 100,
            "ml_prediction":    {},
            "rule_verdict":     rule_result.verdict,
            "rule_score":       rule_result.total_points,
            "ensemble_weights": {},
            "explanation":      "ML ensemble unavailable — using deterministic score only.",
        }


def _build_report(
    fusion: Dict[str, Any],
    rule_result: Any,
    det_score: Any,
    elapsed_ms: int,
) -> Dict[str, Any]:
    return {
        "brain_version":     "2.0",
        "verdict":           fusion["verdict"],
        "risk_score":        fusion["risk_score"],
        "confidence":        fusion["confidence"],
        "fused_threat_prob": fusion.get("fused_threat_prob", 0.0),
        "explanation":       fusion.get("explanation", ""),
        "ml": {
            "label":        fusion.get("ml_prediction", {}).get("label", "?"),
            "confidence":   fusion.get("ml_prediction", {}).get("confidence", 0.0),
            "probabilities": fusion.get("ml_prediction", {}).get("probabilities", {}),
        },
        "rules": {
            "verdict":       rule_result.verdict,
            "total_points":  rule_result.total_points,
            "risk_level":    rule_result.risk_level,
            "signals_fired": len(rule_result.signals),
            "top_signals": [
                _signal_to_dict(s)
                for s in sorted(rule_result.signals, key=lambda x: -x.points)[:5]
            ],
        },
        "deterministic": {
            "score":      getattr(det_score, "score", 0),
            "verdict":    getattr(det_score, "verdict", "BENIGN"),
            "confidence": getattr(det_score, "confidence", "LOW"),
        },
        "ensemble_weights": fusion.get("ensemble_weights", {}),
        "elapsed_ms":       elapsed_ms,
    }


def _signal_to_dict(s: Any) -> Dict[str, Any]:
    return {
        "rule_id":     getattr(s, "rule_id", ""),
        "signal_type": getattr(s, "signal_type", ""),
        "severity":    getattr(s, "severity", ""),
        "points":      getattr(s, "points", 0),
        "description": getattr(s, "description", ""),
        "evidence":    getattr(s, "evidence", ""),
    }
