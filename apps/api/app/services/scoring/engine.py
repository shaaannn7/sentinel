"""Transparent bounded score and conservative verdict calculation."""

from collections import defaultdict
from app.services.analysis.models import FindingDraft, ScoreResult

CATEGORY_CAPS = {"AUTHENTICATION": 25, "SENDER": 20, "URL": 20, "DOMAIN": 20,
                 "ATTACHMENT": 20, "CONTENT": 15, "INFRASTRUCTURE": 15, "HEADER": 15, "IP": 10}


def calculate(findings: list[FindingDraft], evidence_count: int, parsed) -> ScoreResult:
    raw = defaultdict(float)
    for finding in findings:
        raw[finding.category] += max(0, finding.points)
    capped = {category: min(value, CATEGORY_CAPS.get(category, 15)) for category, value in raw.items()}
    breakdown = {category: capped.get(category, 0) for category in CATEGORY_CAPS}
    score = min(100.0, float(sum(breakdown.values())))
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    has_strong_technical = sum(1 for f in findings if f.category in {"AUTHENTICATION", "DOMAIN", "URL"} and f.points >= 10) >= 2
    social = sum(1 for f in findings if f.category == "CONTENT" and f.points >= 5) >= 1
    major = sum(1 for f in findings if f.points >= 10) >= 3
    if evidence_count == 0 or (not parsed.headers and not parsed.plain_body and not parsed.indicators):
        verdict = "INCONCLUSIVE"
    elif major and has_strong_technical:
        verdict = "MALICIOUS"
    elif has_strong_technical and social:
        verdict = "PHISHING"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"
    completeness_parts = [bool(parsed.headers), bool(parsed.auth_results), bool(parsed.hops),
                          bool(parsed.plain_body or parsed.html_body), bool(parsed.indicators), bool(parsed.attachments)]
    completeness = round(sum(completeness_parts) / len(completeness_parts) * 100, 1)
    confidence = "HIGH" if completeness >= 80 and evidence_count >= 4 else "MEDIUM" if completeness >= 40 else "LOW"
    from app.core.config import settings
    return ScoreResult(score, level, verdict, confidence, completeness, breakdown, score_version=settings.SCORE_VERSION)
