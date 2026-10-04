"""Configurable, evidence-backed content signal rules."""

import re
from app.services.email_parser.models import ParsedEmail
from app.services.email_parser.body import strip_html
from app.services.analysis.models import AnalyzerResult, EvidenceItem, FindingDraft
from app.services.analysis.evidence import evidence, safe_excerpt

RULES = (
    ("urgency", re.compile(r"\b(within\s+\d+\s*(hours?|days?)|immediately|urgent|act now|final warning)\b", re.I),
     "Urgency-based social engineering language detected.", 5),
    ("suspension", re.compile(r"\b(account|access).{0,30}(suspend|disabled|locked)\b", re.I),
     "Account suspension language observed.", 4),
    ("credentials", re.compile(r"\b(verify|confirm|provide|enter).{0,40}(password|login|credential|security code|one[- ]time code)\b", re.I),
     "Credential request language observed.", 10),
    ("payment", re.compile(r"\b(gift cards?|wire transfer|payment|invoice|bank account)\b", re.I),
     "Payment-related request language observed.", 5),
    ("reset", re.compile(r"\b(password reset|reset your password|security verification)\b", re.I),
     "Password-reset or security-verification language observed.", 4),
)


def analyze(parsed: ParsedEmail) -> AnalyzerResult:
    result = AnalyzerResult(stage="CONTENT_ANALYSIS")
    text = parsed.plain_body or strip_html(parsed.html_body or "")
    if not text:
        result.warnings.append("No plain-text content observed")
    for key, pattern, title, points in RULES:
        match = pattern.search(text)
        if not match:
            continue
        excerpt = safe_excerpt(text[max(0, match.start() - 60):match.end() + 100])
        ev = evidence(EvidenceItem("CONTENT", "plain-text body", excerpt,
                                   f"Content excerpt matched the configured {key} rule.", {"rule": key}))
        result.evidence.append(ev)
        severity = "MEDIUM" if key in {"credentials", "urgency"} else "LOW"
        result.findings.append(FindingDraft(severity, "CONTENT", title,
            "This rule match is a social-engineering signal; keyword presence alone does not prove phishing.",
            [ev], "content", points))
    result.data = {"rules_evaluated": len(RULES), "content_available": bool(text)}
    return result
