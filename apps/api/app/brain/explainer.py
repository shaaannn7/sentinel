"""
SENTINEL Brain — Feature Importance Explainer
===============================================
Explains *why* the brain classified an email the way it did.

Uses three complementary methods:
  1. RandomForest feature_importances_  (from the base learner)
  2. Rule engine signals                (deterministic, human-readable)
  3. Named feature deltas               (which features pushed verdict)

Public API
----------
  from app.brain.explainer import explain
  report = explain(parsed_email, investigation_id=None)
  # report.top_features   — list of (feature_name, importance, direction)
  # report.top_rules      — list of fired rules sorted by severity/points
  # report.narrative      — one-paragraph plain-English explanation
  # report.verdict        — final verdict
  # report.risk_score     — 0–100
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

import numpy as np

logger = logging.getLogger(__name__)

_LABEL_NAMES = {0: "BENIGN", 1: "SUSPICIOUS", 2: "PHISHING", 3: "MALICIOUS"}

# Colour hints for CLI rendering (severity → direction word)
_DIRECTION = {
    "increases_risk": "▲ risk",
    "decreases_risk": "▼ risk",
    "neutral":        "  —   ",
}


@dataclass
class FeatureContribution:
    name:        str
    value:       float        # actual value in this email's feature vector
    importance:  float        # RF importance (0–1 range, normalised)
    direction:   str          # "increases_risk" | "decreases_risk" | "neutral"
    description: str          # human-readable label


@dataclass
class RuleHit:
    rule_id:     str
    signal_type: str
    severity:    str
    points:      int
    description: str


@dataclass
class ExplainReport:
    verdict:       str
    risk_score:    int
    confidence:    str
    ml_label:      str
    ml_confidence: float
    top_features:  List[FeatureContribution] = field(default_factory=list)
    top_rules:     List[RuleHit]             = field(default_factory=list)
    narrative:     str = ""
    raw_proba:     Dict[str, float]          = field(default_factory=dict)


# Feature descriptions — short, human-readable labels for each of the 80 features
_FEATURE_DESCRIPTIONS: Dict[str, str] = {
    # Auth
    "spf_pass":                   "SPF authentication passed",
    "spf_fail":                   "SPF hard fail — server not authorised",
    "spf_softfail":               "SPF soft fail — marginal authorisation",
    "spf_none":                   "SPF record missing",
    "dkim_pass":                  "DKIM signature verified",
    "dkim_fail":                  "DKIM signature invalid",
    "dkim_none":                  "No DKIM signature",
    "dmarc_pass":                 "DMARC policy passed",
    "dmarc_fail":                 "DMARC policy violated — phishing risk",
    "dmarc_none":                 "No DMARC policy",
    "auth_none_all":              "Completely unauthenticated email",
    # Sender
    "sender_has_suspicious_tld":  "Sender uses high-risk TLD (.xyz, .top, …)",
    "sender_free_mailer":         "Sender uses free webmail (Gmail, Yahoo, …)",
    "sender_lookalike":           "Sender domain is a brand typosquat",
    "sender_ip_literal":          "From address contains raw IP instead of hostname",
    "sender_long_domain":         "Sender domain unusually long (DGA pattern)",
    "sender_numeric_label":       "Sender domain contains numeric labels",
    "sender_subdomain_depth":     "Deep subdomain chain in sender domain",
    # URLs
    "url_count":                  "Number of URLs in email",
    "urls_to_ip_address":         "URLs pointing directly to IP addresses",
    "url_uses_shortener":         "URL shortener detected (destination hidden)",
    "url_has_suspicious_tld":     "URL uses high-risk TLD",
    "url_has_redirect_param":     "Open redirect parameter in URL",
    "url_has_obfuscation":        "URL contains obfuscated characters",
    "url_lookalike_host":         "URL hostname is a brand typosquat",
    "url_has_data_uri":           "Inline data URI (potential embedded payload)",
    # Content
    "urgency_match_count":        "Urgency-inducing language count",
    "credential_match_count":     "Credential-harvest language count",
    "payment_match_count":        "Payment/BEC language count",
    "brand_match_count":          "Known brand name mentions",
    "lookalike_brand_in_body":    "Typosquat brand name in body",
    "macro_instruction":          "Instructions to enable macros",
    "click_here_link":            "Generic 'click here' call-to-action",
    "html_only_no_plain":         "HTML-only email (no plain-text alternative)",
    "short_body":                 "Very short body (<20 words)",
    # Attachments
    "has_executable_attachment":  "Executable file attachment (.exe, .bat, …)",
    "has_macro_attachment":       "Office macro-enabled document (.docm, .xlsm)",
    "has_archive_attachment":     "Archive attachment (.zip, .rar, …)",
    "has_double_extension":       "Double-extension filename (e.g., invoice.pdf.exe)",
    "attachment_is_suspicious":   "Attachment flagged by magic-byte analysis",
}


def explain(
    parsed: Any,
    investigation_id: str | None = None,
    top_n: int = 10,
) -> ExplainReport:
    """
    Generate a full explanation report for why the brain classified this email.

    Parameters
    ----------
    parsed           : ParsedEmail object
    investigation_id : optional, for logging
    top_n            : number of top features to include in report

    Returns
    -------
    ExplainReport with top features, fired rules, narrative, and verdict
    """
    from app.brain.features import extract, FEATURE_NAMES
    from app.brain.ml.classifier import BrainClassifier
    from app.brain.rules.engine import AdvancedRuleEngine
    from app.brain.orchestrator import Brain
    from app.services.scoring.engine import calculate

    # ── 1. Extract features ─────────────────────────────────────────────
    vec = extract(parsed)

    # ── 2. ML predict ───────────────────────────────────────────────────
    clf      = BrainClassifier.get()
    ml_res   = clf.predict_one(vec)

    # ── 3. Feature importances from RF base learner ──────────────────────
    try:
        rf_pipe = clf._pipe.named_steps["scaler"]  # noqa: just check pipe exists
        # The stacking pipeline: scaler → stacking_clf
        # RF is the first named_estimator inside StackingClassifier
        stacking = clf._pipe.named_steps["clf"]
        rf = dict(stacking.named_estimators_).get("rf")
        if rf is not None and hasattr(rf, "feature_importances_"):
            importances = rf.feature_importances_   # shape (80,)
        else:
            importances = np.ones(len(FEATURE_NAMES)) / len(FEATURE_NAMES)
    except Exception:
        importances = np.ones(len(FEATURE_NAMES)) / len(FEATURE_NAMES)

    # Sort by importance descending, take top_n
    top_idx = np.argsort(importances)[::-1][:top_n]
    top_features: List[FeatureContribution] = []
    for idx in top_idx:
        fname       = FEATURE_NAMES[idx]
        fval        = float(vec[idx])
        imp         = float(importances[idx])
        # Heuristic direction: if feature value > 0 and feature name suggests threat → increases risk
        threat_names = {
            "fail", "none", "suspicious", "lookalike", "ip_literal",
            "shortener", "redirect", "obfuscation", "urgency", "credential",
            "payment", "macro", "executable", "double_extension",
        }
        is_threat = any(t in fname for t in threat_names)
        is_safe   = any(t in fname for t in {"pass",})
        if fval > 0 and is_threat:
            direction = "increases_risk"
        elif fval > 0 and is_safe:
            direction = "decreases_risk"
        else:
            direction = "neutral"

        top_features.append(FeatureContribution(
            name        = fname,
            value       = round(fval, 4),
            importance  = round(imp, 6),
            direction   = direction,
            description = _FEATURE_DESCRIPTIONS.get(fname, fname.replace("_", " ").title()),
        ))

    # ── 4. Rule engine signals ───────────────────────────────────────────
    rule_eng    = AdvancedRuleEngine()
    rule_result = rule_eng.evaluate(parsed)
    top_rules: List[RuleHit] = [
        RuleHit(
            rule_id     = s.rule_id,
            signal_type = s.signal_type,
            severity    = s.severity,
            points      = s.points,
            description = s.description,
        )
        for s in sorted(rule_result.signals, key=lambda x: (-_sev_order(x.severity), -x.points))[:8]
    ]

    # ── 5. Brain full verdict ────────────────────────────────────────────
    score = calculate([], 0, parsed)
    brain = Brain.analyse(parsed, score, investigation_id=investigation_id, persist_memory=False)

    # ── 6. Narrative ─────────────────────────────────────────────────────
    narrative = _build_narrative(brain.verdict, brain.risk_score, ml_res, rule_result, top_features, top_rules)

    return ExplainReport(
        verdict       = brain.verdict,
        risk_score    = brain.risk_score,
        confidence    = brain.confidence,
        ml_label      = ml_res["label_name"],
        ml_confidence = round(ml_res["confidence"], 4),
        top_features  = top_features,
        top_rules     = top_rules,
        narrative     = narrative,
        raw_proba     = {k: round(v, 4) for k, v in ml_res["probabilities"].items()},
    )


def _sev_order(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(sev, 0)


def _build_narrative(
    verdict:     str,
    risk_score:  int,
    ml_res:      Dict,
    rule_result: Any,
    features:    List[FeatureContribution],
    rules:       List[RuleHit],
) -> str:
    threat_feats = [f for f in features if f.direction == "increases_risk"]
    safe_feats   = [f for f in features if f.direction == "decreases_risk"]
    crit_rules   = [r for r in rules if r.severity in ("CRITICAL", "HIGH")]

    lines = [
        f"The brain classified this email as {verdict} with a risk score of {risk_score}/100.",
        f"The ML model predicted {ml_res['label_name']} with {ml_res['confidence']:.0%} confidence.",
    ]

    if crit_rules:
        rule_descs = "; ".join(r.description.split("—")[-1].strip() for r in crit_rules[:3])
        lines.append(f"Critical/high-severity rules fired: {rule_descs}.")

    if threat_feats:
        feat_names = ", ".join(f.description for f in threat_feats[:3])
        lines.append(f"Top threat signals driving the verdict: {feat_names}.")

    if safe_feats:
        safe_names = ", ".join(f.description for f in safe_feats[:2])
        lines.append(f"Mitigating factors: {safe_names}.")

    if verdict == "BENIGN":
        lines.append("No significant threat patterns were found across any detection layer.")
    elif verdict == "SUSPICIOUS":
        lines.append("Manual review is recommended — signals are mixed but below the phishing threshold.")
    elif verdict == "PHISHING":
        lines.append("This email shows strong phishing indicators. Do not click links or provide credentials.")
    elif verdict == "MALICIOUS":
        lines.append("HIGH CONFIDENCE THREAT. This email contains malicious content. Delete and report immediately.")

    return " ".join(lines)
