"""
SENTINEL Brain — Ensemble Intelligence Engine
=============================================
Combines three independent signal sources into a single unified verdict:

  1. ML Classifier      — probabilistic prediction from 80-feature vector
  2. Deterministic Rules— existing scoring engine (heuristic, evidence-backed)
  3. Memory / ThreatIntel— pattern recall from past investigations

Fusion strategy
---------------
  Weighted average of calibrated probabilities:
    ml_score  × 0.55  (highest weight — trained on patterns)
    rule_score× 0.35  (deterministic, explainable)
    memory    × 0.10  (recall boost when pattern seen before)

  Final verdict thresholds:
    MALICIOUS   ≥ 0.70
    PHISHING    ≥ 0.55  (subset of MALICIOUS in display)
    SUSPICIOUS  ≥ 0.35
    BENIGN      < 0.35
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import numpy as np

from app.services.email_parser.models import ParsedEmail
from app.services.scoring.engine import ScoreResult

logger = logging.getLogger(__name__)

# Fusion weights (must sum to 1.0)
W_ML     = 0.55
W_RULE   = 0.35
W_MEMORY = 0.10

# Verdict thresholds (probability that email is threat)
T_MALICIOUS  = 0.70
T_PHISHING   = 0.55
T_SUSPICIOUS = 0.35


class EnsembleEngine:
    """
    Unified brain engine.  Call `analyse()` to get a fused verdict.
    """

    def __init__(self) -> None:
        # Lazy-load the ML classifier to avoid slowing startup
        self._clf = None

    def _get_clf(self):
        if self._clf is None:
            from app.brain.ml.classifier import BrainClassifier
            self._clf = BrainClassifier.get()
        return self._clf

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def analyse(
        self,
        parsed: ParsedEmail,
        rule_score: ScoreResult,
        investigation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run the full ensemble and return an enriched verdict dict.

        Parameters
        ----------
        parsed           : ParsedEmail from the email parser
        rule_score       : ScoreResult from the deterministic scoring engine
        investigation_id : optional, used for memory store lookup

        Returns
        -------
        dict with keys:
          verdict, risk_score, confidence, ml_label, ml_probabilities,
          rule_verdict, fused_threat_prob, ensemble_weights, explanation
        """
        # ── 1. ML signal ────────────────────────────────────────────────
        ml_result = self._ml_signal(parsed)
        ml_threat_prob = self._ml_threat_prob(ml_result["probabilities"])

        # ── 2. Rule signal ───────────────────────────────────────────────
        rule_threat_prob = self._rule_threat_prob(rule_score)

        # ── 3. Memory signal ─────────────────────────────────────────────
        memory_boost = self._memory_signal(parsed, investigation_id)

        # ── 4. Weighted fusion ───────────────────────────────────────────
        fused = (
            W_ML     * ml_threat_prob +
            W_RULE   * rule_threat_prob +
            W_MEMORY * memory_boost
        )
        fused = float(np.clip(fused, 0.0, 1.0))

        # ── 5. Verdict mapping ───────────────────────────────────────────
        # Deterministic evidence must not be downgraded by an uncertain ML
        # prediction. Rules are explainable and are the safety floor.
        if rule_score.verdict == "MALICIOUS" or rule_score.score >= 70:
            verdict = "MALICIOUS"
            risk_score = max(70, int(rule_score.score), int(fused * 100))
        elif rule_score.verdict == "PHISHING" and rule_score.score >= 45:
            verdict = "PHISHING"
            risk_score = max(55, int(rule_score.score), int(fused * 100))
        elif fused >= T_MALICIOUS:
            verdict = "MALICIOUS"
            risk_score = 70 + int(fused * 30)
        elif fused >= T_PHISHING:
            verdict = "PHISHING"
            risk_score = 55 + int((fused - T_PHISHING) / (T_MALICIOUS - T_PHISHING) * 15)
        elif fused >= T_SUSPICIOUS:
            verdict = "SUSPICIOUS"
            risk_score = 25 + int((fused - T_SUSPICIOUS) / (T_PHISHING - T_SUSPICIOUS) * 30)
        else:
            verdict = "BENIGN"
            risk_score = int(fused / T_SUSPICIOUS * 25)

        risk_score = int(np.clip(risk_score, 0, 100))

        # ── 6. Confidence from agreement ─────────────────────────────────
        agreement = 1.0 - abs(ml_threat_prob - rule_threat_prob)
        if agreement >= 0.8:
            confidence = "HIGH"
        elif agreement >= 0.5:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        # ── 7. Explanation ───────────────────────────────────────────────
        explanation = self._explain(ml_result, rule_score, fused, verdict)

        return {
            "verdict":          verdict,
            "risk_score":       risk_score,
            "confidence":       confidence,
            "fused_threat_prob": round(fused, 4),
            "ml_label":         ml_result["label_name"],
            "ml_confidence":    round(ml_result["confidence"], 4),
            "ml_probabilities": {k: round(v, 4) for k, v in ml_result["probabilities"].items()},
            "rule_verdict":     rule_score.verdict,
            "rule_score":       rule_score.score,
            "ensemble_weights": {"ml": W_ML, "rules": W_RULE, "memory": W_MEMORY},
            "explanation":      explanation,
        }

    # ------------------------------------------------------------------
    # Signal extractors
    # ------------------------------------------------------------------

    def _ml_signal(self, parsed: ParsedEmail) -> Dict[str, Any]:
        try:
            from app.brain.features import extract
            vec = extract(parsed)
            return self._get_clf().predict_one(vec)
        except Exception as exc:
            logger.warning("brain.ensemble: ML signal failed — %s", exc)
            return {
                "label": 0, "label_name": "BENIGN",
                "confidence": 0.5,
                "probabilities": {"BENIGN": 0.5, "SUSPICIOUS": 0.2, "PHISHING": 0.2, "MALICIOUS": 0.1},
            }

    def _ml_threat_prob(self, proba: Dict[str, float]) -> float:
        """Aggregate probability of being a threat (not benign)."""
        return float(proba.get("SUSPICIOUS", 0) * 0.3 +
                     proba.get("PHISHING", 0)   * 0.7 +
                     proba.get("MALICIOUS", 0)  * 1.0)

    def _rule_threat_prob(self, score: ScoreResult) -> float:
        """Convert deterministic score (0–100) to a probability-like [0,1]."""
        return float(np.clip(score.score / 100.0, 0.0, 1.0))

    def _memory_signal(
        self,
        parsed: ParsedEmail,
        investigation_id: Optional[str],
    ) -> float:
        """
        Return a small recall boost (0.0–1.0) if we've seen this sender
        or similar URL patterns classified as malicious before.
        """
        try:
            from app.brain.memory.store import MemoryStore
            mem = MemoryStore.get()
            return mem.threat_boost(parsed)
        except Exception:
            return 0.0

    def _explain(
        self,
        ml_result: Dict[str, Any],
        rule_score: ScoreResult,
        fused: float,
        verdict: str,
    ) -> str:
        lines = [
            f"Fused threat probability: {fused:.1%}.",
            f"ML model: {ml_result['label_name']} ({ml_result['confidence']:.1%} confidence).",
            f"Deterministic rules: {rule_score.verdict} (score {rule_score.score:.0f}/100).",
        ]
        if verdict in ("MALICIOUS", "PHISHING"):
            lines.append("High-confidence threat indicators detected across multiple signal layers.")
        elif verdict == "SUSPICIOUS":
            lines.append("Mixed signals — manual review recommended.")
        else:
            lines.append("No significant threat signals detected.")
        return " ".join(lines)


# Singleton accessor
_engine: Optional[EnsembleEngine] = None


def get_engine() -> EnsembleEngine:
    global _engine
    if _engine is None:
        _engine = EnsembleEngine()
    return _engine
