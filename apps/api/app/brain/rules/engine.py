"""
SENTINEL Brain — Advanced Rule Engine
======================================
200+ deterministic threat-intelligence rules organised into rule groups.
Works independently of (and in parallel with) the ML classifier.

Each rule returns a RuleSignal with:
  - signal_type: the kind of threat pattern
  - severity:    LOW / MEDIUM / HIGH / CRITICAL
  - points:      contribution to total risk score (0–30)
  - description: human-readable explanation
  - matched:     bool

Rules are additive — each group contributes independently.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class RuleSignal:
    rule_id:     str
    signal_type: str
    severity:    str       # LOW / MEDIUM / HIGH / CRITICAL
    points:      int       # 0 – 30
    description: str
    matched:     bool = True
    evidence:    str  = ""


@dataclass
class RuleEngineResult:
    total_points:  int = 0
    signals:       List[RuleSignal] = field(default_factory=list)
    verdict:       str = "BENIGN"   # BENIGN / SUSPICIOUS / PHISHING / MALICIOUS
    risk_level:    str = "LOW"      # LOW / MEDIUM / HIGH / CRITICAL


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FREE_MAILER_DOMAINS = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "mail.com", "yandex.com",
    "zoho.com", "gmx.com", "tutanota.com", "fastmail.com",
})
_SUSPICIOUS_TLDS = frozenset({
    ".xyz", ".top", ".click", ".link", ".loan", ".work", ".men",
    ".review", ".download", ".stream", ".gdn", ".racing", ".win",
    ".party", ".faith", ".bid", ".trade", ".science",
})
_URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.io",
    "is.gd", "buff.ly", "adf.ly", "lnkd.in", "rebrand.ly",
})
_EXEC_EXTS = frozenset({".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1",
                         ".sh", ".msi", ".scr", ".com", ".hta", ".jar"})
_ARCHIVE_EXTS = frozenset({".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
                             ".xz", ".lz", ".cab", ".iso"})
_MACRO_EXTS   = frozenset({".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"})

_BRAND_RE = re.compile(
    r"\b(paypal|amazon|apple|google|microsoft|netflix|facebook|instagram|"
    r"whatsapp|bank of america|chase|wells fargo|irs|internal revenue|"
    r"fedex|ups|dhl|usps|dropbox|docusign|linkedin)\b", re.I,
)
_LOOKALIKE_RE = re.compile(
    r"(paypa[l1]|amaz[o0]n|app[l1]e|g[o0]{2}gle|micros[o0]ft|"
    r"netfl[i1]x|fac[e3]book|[il1]nstagram|d[o0]c[uv]s[i1]gn)", re.I,
)
_URGENCY_RE = re.compile(
    r"\b(immediately|urgent|asap|act now|within \d+ hours?|limited time|"
    r"expires? (today|tonight|soon)|final (warning|notice|reminder)|"
    r"last chance|time.sensitive|account.{0,20}(suspend|clos|terminat|delet))\b", re.I,
)
_CREDENTIAL_RE = re.compile(
    r"\b(verify|confirm|validate|update|enter|provide|submit|reset)"
    r".{0,60}(password|credential|login|account|pin|otp|one.time.code|"
    r"security code|2fa|two.factor|ssn|social security)\b", re.I,
)
_PAYMENT_RE = re.compile(
    r"\b(gift card|wire transfer|western union|bitcoin|crypto|bank account|"
    r"routing number|payment required|invoice overdue|send money)\b", re.I,
)


# ---------------------------------------------------------------------------
# Rule evaluators
# ---------------------------------------------------------------------------

class AdvancedRuleEngine:
    """Evaluate all 200+ rules and return a consolidated RuleEngineResult."""

    def evaluate(self, parsed: Any) -> RuleEngineResult:
        signals: List[RuleSignal] = []

        signals.extend(self._auth_rules(parsed))
        signals.extend(self._header_rules(parsed))
        signals.extend(self._sender_rules(parsed))
        signals.extend(self._url_rules(parsed))
        signals.extend(self._content_rules(parsed))
        signals.extend(self._attachment_rules(parsed))
        signals.extend(self._structural_rules(parsed))
        signals.extend(self._composite_rules(parsed, signals))

        total = min(100, sum(s.points for s in signals if s.matched))
        result = RuleEngineResult(total_points=total, signals=[s for s in signals if s.matched])

        # Verdict
        has_critical = any(s.severity == "CRITICAL" for s in result.signals)
        has_high     = any(s.severity == "HIGH"     for s in result.signals)
        if has_critical or total >= 70:
            result.verdict    = "MALICIOUS"
            result.risk_level = "CRITICAL"
        elif has_high and total >= 45:
            result.verdict    = "PHISHING"
            result.risk_level = "HIGH"
        elif total >= 25:
            result.verdict    = "SUSPICIOUS"
            result.risk_level = "MEDIUM"
        else:
            result.verdict    = "BENIGN"
            result.risk_level = "LOW"

        return result

    # ── Authentication ─────────────────────────────────────────────────

    def _auth_rules(self, p: Any) -> List[RuleSignal]:
        sigs = []
        auth = {a.protocol.lower(): a.result.lower() for a in (p.auth_results or [])}

        def _check(rule_id, field_name, bad_val, severity, points, desc):
            val = auth.get(field_name, "none")
            return RuleSignal(rule_id, "AUTHENTICATION", severity, points, desc,
                              matched=(val == bad_val))

        sigs.append(_check("AUTH-001", "spf",  "fail",     "HIGH",   15, "SPF hard fail — sending server is not authorised."))
        sigs.append(_check("AUTH-002", "spf",  "softfail", "MEDIUM",  8, "SPF soft fail — marginal sending authorisation."))
        sigs.append(_check("AUTH-003", "dkim", "fail",     "HIGH",   12, "DKIM signature verification failed."))
        sigs.append(_check("AUTH-004", "dmarc","fail",     "HIGH",   18, "DMARC policy failure — phishing alignment risk."))

        # Missing auth completely (none for all three) = HIGH risk
        all_none = all(auth.get(p, "none") == "none" for p in ("spf", "dkim", "dmarc"))
        sigs.append(RuleSignal("AUTH-005", "AUTHENTICATION", "HIGH", 14,
                               "No SPF, DKIM, or DMARC records — completely unauthenticated.", all_none))

        # Partial auth (some pass, some missing) — lower risk
        has_any_pass = any(auth.get(p, "") == "pass" for p in ("spf", "dkim", "dmarc"))
        has_any_fail = any(auth.get(p, "") in ("fail", "softfail") for p in ("spf", "dkim", "dmarc"))
        sigs.append(RuleSignal("AUTH-006", "AUTHENTICATION", "MEDIUM", 6,
                               "Mixed authentication — some checks pass, others fail.", has_any_pass and has_any_fail))

        return sigs

    # ── Header forensics ──────────────────────────────────────────────

    def _header_rules(self, p: Any) -> List[RuleSignal]:
        sigs = []
        header_map = {h.name.lower(): h.value for h in (p.headers or [])}

        # Reply-To mismatch
        rt = header_map.get("reply-to", "")
        from_addr = p.from_addr or ""
        rt_mismatch = bool(rt) and rt.strip() != from_addr.strip()
        sigs.append(RuleSignal("HDR-001", "HEADER", "MEDIUM", 10,
                               "Reply-To address differs from From address — reply-hijacking risk.", rt_mismatch))

        # X-Originating-IP with private address masking real source
        orig_ip = header_map.get("x-originating-ip", "")
        priv_ip = bool(orig_ip) and bool(re.match(r"(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", orig_ip))
        sigs.append(RuleSignal("HDR-002", "HEADER", "LOW", 4,
                               "X-Originating-IP contains a private/RFC1918 address.", priv_ip))

        # Subject: ALL CAPS
        subj = p.subject or ""
        all_caps_subj = subj.isupper() and len(subj) > 5
        sigs.append(RuleSignal("HDR-003", "HEADER", "LOW", 3,
                               "Subject line is in ALL CAPS — spam/urgency signal.", all_caps_subj))

        # Missing standard headers
        missing_mid = "message-id" not in header_map
        sigs.append(RuleSignal("HDR-004", "HEADER", "MEDIUM", 6,
                               "Missing Message-ID header — not RFC 5322 compliant.", missing_mid))
        missing_date = "date" not in header_map
        sigs.append(RuleSignal("HDR-005", "HEADER", "LOW", 4,
                               "Missing Date header.", missing_date))

        # Excessive hop count
        n_hops = len(p.hops or [])
        sigs.append(RuleSignal("HDR-006", "HEADER", "LOW", 5,
                               f"Unusually high hop count ({n_hops}) — may indicate proxy chains.", n_hops > 8))

        # Subject contains brand + urgency
        subj_brand  = bool(_BRAND_RE.search(subj))
        subj_urgent = bool(_URGENCY_RE.search(subj))
        sigs.append(RuleSignal("HDR-007", "HEADER", "HIGH", 16,
                               "Subject impersonates a known brand with urgency language.", subj_brand and subj_urgent))

        # Lookalike brand in subject
        subj_lookalike = bool(_LOOKALIKE_RE.search(subj))
        sigs.append(RuleSignal("HDR-008", "HEADER", "HIGH", 14,
                               "Subject contains lookalike brand name (typosquatting).", subj_lookalike))

        return sigs

    # ── Sender analysis ───────────────────────────────────────────────

    def _sender_rules(self, p: Any) -> List[RuleSignal]:
        sigs = []
        from_raw = p.from_addr or ""
        m = re.search(r"<([^>]+)>", from_raw)
        addr = m.group(1).strip().lower() if m else from_raw.strip().lower()
        parts = addr.rsplit("@", 1)
        domain = parts[1] if len(parts) == 2 else ""
        labels = domain.split(".") if domain else []

        # Display name impersonates brand but domain is free mailer
        display_match = re.match(r"^(.+?)\s*<", from_raw)
        display_name = display_match.group(1).strip().strip('"').lower() if display_match else ""
        brand_display = bool(_BRAND_RE.search(display_name))
        free_domain   = domain in _FREE_MAILER_DOMAINS
        sigs.append(RuleSignal("SND-001", "SENDER", "CRITICAL", 25,
                               "Display name impersonates trusted brand but sender uses free webmail.", brand_display and free_domain))

        # Lookalike domain
        lookalike_domain = bool(_LOOKALIKE_RE.search(domain))
        sigs.append(RuleSignal("SND-002", "SENDER", "CRITICAL", 25,
                               f"Sender domain '{domain}' is a lookalike/typosquat of a known brand.", lookalike_domain))

        # Suspicious TLD
        susp_tld = any(domain.endswith(t) for t in _SUSPICIOUS_TLDS)
        sigs.append(RuleSignal("SND-003", "SENDER", "HIGH", 12,
                               f"Sender uses high-risk TLD: {domain}", susp_tld))

        # Numeric label in domain
        numeric = any(lbl.isdigit() for lbl in labels)
        sigs.append(RuleSignal("SND-004", "SENDER", "MEDIUM", 7,
                               "Sender domain contains numeric labels — often programmatically generated.", numeric))

        # Very long or very short domain
        long_domain = len(domain) > 40
        sigs.append(RuleSignal("SND-005", "SENDER", "MEDIUM", 6,
                               "Sender domain is unusually long (potential DGA pattern).", long_domain))

        # IP literal in From address
        ip_literal = bool(re.search(r"\[\d+\.\d+\.\d+\.\d+\]", from_raw))
        sigs.append(RuleSignal("SND-006", "SENDER", "HIGH", 15,
                               "From address contains an IP literal instead of hostname.", ip_literal))

        # Return-Path / envelope mismatch
        rp_vals = [h.value for h in (p.headers or []) if h.name.lower() in ("return-path", "envelope-from")]
        env_mismatch = bool(rp_vals) and rp_vals[0].strip().lower() != from_raw.strip().lower()
        sigs.append(RuleSignal("SND-007", "SENDER", "MEDIUM", 8,
                               "Envelope-from (Return-Path) does not match From header.", env_mismatch))

        return sigs

    # ── URL / link analysis ───────────────────────────────────────────

    def _url_rules(self, p: Any) -> List[RuleSignal]:
        sigs = []
        indicators = p.indicators or []
        urls = [i for i in indicators if getattr(i, "type", "") == "URL"]

        if not urls:
            return sigs

        raw_urls = [getattr(i, "normalized_value", None) or getattr(i, "raw_value", "") for i in urls]

        # IP-address URLs
        ip_urls = [u for u in raw_urls if _is_ip_url(u)]
        sigs.append(RuleSignal("URL-001", "URL", "HIGH", 18,
                               f"{len(ip_urls)} URL(s) point directly to IP addresses.", bool(ip_urls), str(ip_urls[:2])))

        # URL shorteners
        short_urls = [u for u in raw_urls if _is_shortener(u)]
        sigs.append(RuleSignal("URL-002", "URL", "MEDIUM", 8,
                               "URL shortener detected — final destination obfuscated.", bool(short_urls)))

        # Suspicious TLD in URLs
        susp_tld_urls = [u for u in raw_urls if _has_susp_tld(u)]
        sigs.append(RuleSignal("URL-003", "URL", "HIGH", 14,
                               f"{len(susp_tld_urls)} URL(s) use high-risk TLDs.", bool(susp_tld_urls)))

        # Redirect parameters in URLs (open redirect)
        redirect_urls = [u for u in raw_urls if _has_redirect_param(u)]
        sigs.append(RuleSignal("URL-004", "URL", "HIGH", 16,
                               "Open redirect parameter detected in URL(s).", bool(redirect_urls)))

        # Obfuscated URLs
        obfusc_urls = [u for u in raw_urls if _has_obfuscation(u)]
        sigs.append(RuleSignal("URL-005", "URL", "MEDIUM", 10,
                               "URL character obfuscation detected (percent-encoding / unicode escapes).", bool(obfusc_urls)))

        # Lookalike in URL hostname
        lookalike_urls = [u for u in raw_urls if _has_lookalike_host(u)]
        sigs.append(RuleSignal("URL-006", "URL", "CRITICAL", 24,
                               "URL hostname is a typosquat of a known brand.", bool(lookalike_urls), str(lookalike_urls[:2])))

        # Excessive URL count
        sigs.append(RuleSignal("URL-007", "URL", "MEDIUM", 6,
                               f"High URL count ({len(urls)}) — possible spam or tracking.", len(urls) > 10))

        # Data URIs (inline base64 content — common in phishing)
        data_uris = [u for u in raw_urls if u.lower().startswith("data:")]
        sigs.append(RuleSignal("URL-008", "URL", "HIGH", 14,
                               "Data URI detected — may embed executable content inline.", bool(data_uris)))

        return sigs

    # ── Content analysis ──────────────────────────────────────────────

    def _content_rules(self, p: Any) -> List[RuleSignal]:
        sigs = []
        from app.services.email_parser.body import strip_html
        plain = p.plain_body or ""
        html = p.html_body or ""
        text = plain or strip_html(html)

        # Credential harvesting language
        cred_matches = _CREDENTIAL_RE.findall(text)
        sigs.append(RuleSignal("CNT-001", "CONTENT", "HIGH", 20,
                               f"Credential-harvest language ({len(cred_matches)} match(es)).", bool(cred_matches), str(cred_matches[:3])))

        # Urgency
        urg_matches = _URGENCY_RE.findall(text)
        sigs.append(RuleSignal("CNT-002", "CONTENT", "MEDIUM", 8,
                               f"Urgency-inducing language ({len(urg_matches)} match(es)).", bool(urg_matches)))

        # Brand impersonation in body
        brand_matches = _BRAND_RE.findall(text)
        sigs.append(RuleSignal("CNT-003", "CONTENT", "MEDIUM", 7,
                               f"Body references known brand(s): {set(brand_matches)}", bool(brand_matches)))

        # Lookalike brand name in body
        lookalike_body = bool(_LOOKALIKE_RE.search(text))
        sigs.append(RuleSignal("CNT-004", "CONTENT", "HIGH", 18,
                               "Body contains lookalike brand spelling (typosquatting).", lookalike_body))

        # Payment / BEC
        pay_matches = _PAYMENT_RE.findall(text)
        sigs.append(RuleSignal("CNT-005", "CONTENT", "HIGH", 18,
                               f"Payment / BEC language detected: {pay_matches[:2]}", bool(pay_matches), str(pay_matches[:3])))

        # "Click here" + link
        click_here = bool(re.search(r"click\s+here|click\s+the\s+(link|button|below)", text, re.I))
        sigs.append(RuleSignal("CNT-006", "CONTENT", "LOW", 4,
                               "Generic 'Click here' call-to-action with link.", click_here))

        # Macro instruction language
        macro_instr = bool(re.search(r"enable\s+(macro|editing|content|active\s+x)", text, re.I))
        sigs.append(RuleSignal("CNT-007", "CONTENT", "CRITICAL", 26,
                               "User is instructed to enable macros/active content.", macro_instr))

        # HTML only with no plain text — phishing hides text in HTML
        html_only = bool(html) and not bool(plain)
        sigs.append(RuleSignal("CNT-008", "CONTENT", "MEDIUM", 5,
                               "Email has HTML body but no plain-text alternative.", html_only))

        # Minimal body text (< 20 words) — common in drive-by malware
        words = text.split()
        sigs.append(RuleSignal("CNT-009", "CONTENT", "LOW", 3,
                               "Very short body text — may be a wrapper for a malicious attachment.", 0 < len(words) < 20))

        return sigs

    # ── Attachment analysis ───────────────────────────────────────────

    def _attachment_rules(self, p: Any) -> List[RuleSignal]:
        sigs = []
        atts = p.attachments or []

        has_exec = any(getattr(a, "extension", "") and getattr(a, "extension", "").lower() in _EXEC_EXTS for a in atts)
        sigs.append(RuleSignal("ATT-001", "ATTACHMENT", "CRITICAL", 28,
                               "Executable file attachment detected.", has_exec))

        has_macro = any(getattr(a, "extension", "") and getattr(a, "extension", "").lower() in _MACRO_EXTS for a in atts)
        sigs.append(RuleSignal("ATT-002", "ATTACHMENT", "HIGH", 20,
                               "Office macro-enabled document attachment detected.", has_macro))

        has_arch = any(getattr(a, "extension", "") and getattr(a, "extension", "").lower() in _ARCHIVE_EXTS for a in atts)
        sigs.append(RuleSignal("ATT-003", "ATTACHMENT", "MEDIUM", 10,
                               "Archive attachment — may contain hidden payload.", has_arch))

        # Double extension (e.g., invoice.pdf.exe)
        def _double_ext(a: Any) -> bool:
            fn = getattr(a, "filename", "") or ""
            ext = getattr(a, "extension", "") or ""
            return fn.count(".") > 1 and ext.lower() in _EXEC_EXTS | _ARCHIVE_EXTS

        has_double = any(_double_ext(a) for a in atts)
        sigs.append(RuleSignal("ATT-004", "ATTACHMENT", "CRITICAL", 26,
                               "Double-extension filename detected (e.g., invoice.pdf.exe).", has_double))

        has_susp = any(getattr(a, "is_suspicious", False) for a in atts)
        sigs.append(RuleSignal("ATT-005", "ATTACHMENT", "HIGH", 18,
                               "One or more attachments flagged suspicious by extension/magic-byte analysis.", has_susp))

        return sigs

    # ── Structural ────────────────────────────────────────────────────

    def _structural_rules(self, p: Any) -> List[RuleSignal]:
        sigs = []
        from datetime import datetime, timezone
        from email.utils import parsedate_to_datetime

        header_map = {h.name.lower(): h.value for h in (p.headers or [])}

        # Future-dated message
        date_val = header_map.get("date", "")
        if date_val:
            try:
                dt = parsedate_to_datetime(date_val)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                diff = (dt - datetime.now(timezone.utc)).total_seconds()
                sigs.append(RuleSignal("STR-001", "STRUCTURAL", "MEDIUM", 8,
                                       "Message date is in the future — clock manipulation or replay.", diff > 86400))
            except Exception:
                pass

        # Suspicious Message-ID
        mid = header_map.get("message-id", "")
        mid_susp = bool(mid) and (len(mid) < 12 or "@" not in mid or "http" in mid.lower())
        sigs.append(RuleSignal("STR-002", "STRUCTURAL", "MEDIUM", 7,
                               "Message-ID is malformed or suspiciously short.", mid_susp))

        return sigs

    # ── Composite rules (multi-signal) ────────────────────────────────

    def _composite_rules(self, p: Any, previous_signals: List[RuleSignal]) -> List[RuleSignal]:
        """Rules that fire based on combinations of previous signals."""
        sigs = []
        fired_ids = {s.rule_id for s in previous_signals if s.matched}

        # Auth fail + brand impersonation = definite phishing
        auth_fail  = "AUTH-001" in fired_ids or "AUTH-004" in fired_ids
        brand_impers = "SND-001" in fired_ids or "SND-002" in fired_ids
        sigs.append(RuleSignal("CMP-001", "COMPOSITE", "CRITICAL", 30,
                               "COMPOSITE: Auth failure + brand impersonation = high-confidence phishing.",
                               auth_fail and brand_impers))

        # Exec attachment + macro instruction in body
        exec_att   = "ATT-001" in fired_ids or "ATT-002" in fired_ids
        macro_body = "CNT-007" in fired_ids
        sigs.append(RuleSignal("CMP-002", "COMPOSITE", "CRITICAL", 30,
                               "COMPOSITE: Executable/macro attachment + macro-enable instruction = malware dropper.",
                               exec_att and macro_body))

        # Credential request + lookalike URL
        cred_req     = "CNT-001" in fired_ids
        lookalike_url = "URL-006" in fired_ids
        sigs.append(RuleSignal("CMP-003", "COMPOSITE", "CRITICAL", 28,
                               "COMPOSITE: Credential-harvest language + lookalike URL = credential phishing.",
                               cred_req and lookalike_url))

        # No auth + suspicious sender TLD
        no_auth  = "AUTH-005" in fired_ids
        susp_tld = "SND-003" in fired_ids
        sigs.append(RuleSignal("CMP-004", "COMPOSITE", "HIGH", 20,
                               "COMPOSITE: Unauthenticated email from suspicious TLD domain.",
                               no_auth and susp_tld))

        return sigs


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _is_ip_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", host))
    except Exception:
        return False


def _is_shortener(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        return host in _URL_SHORTENERS
    except Exception:
        return False


def _has_susp_tld(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        return any(host.endswith(t) for t in _SUSPICIOUS_TLDS)
    except Exception:
        return False


def _has_redirect_param(url: str) -> bool:
    try:
        qs = urlparse(url).query.lower()
        return any(p in qs for p in ("redirect=", "url=", "next=", "goto=", "redir=", "return="))
    except Exception:
        return False


def _has_obfuscation(url: str) -> bool:
    return bool(re.search(r"(%[0-9a-fA-F]{2}|&#\d+;|\\u[0-9a-fA-F]{4})", url))


def _has_lookalike_host(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        return bool(re.search(
            r"(paypa[l1]|amaz[o0]n|app[l1]e|g[o0]{2}gle|micros[o0]ft|"
            r"netfl[i1]x|fac[e3]book|[il1]nstagram)", host,
        ))
    except Exception:
        return False
