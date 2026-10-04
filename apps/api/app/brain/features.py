"""
SENTINEL Brain — Feature Engineering
=====================================
Extracts 80+ evidence signals from a ParsedEmail into a normalised
numpy feature vector consumed by ML classifiers.

Feature groups
--------------
  G1  Header / routing forensics      (15 features)
  G2  Authentication signals          (10 features)
  G3  Sender / domain heuristics      (12 features)
  G4  URL / link analysis             (10 features)
  G5  Content / social engineering    (15 features)
  G6  Attachment risk                 (8 features)
  G7  Structural / meta signals       (10 features)
"""

from __future__ import annotations

import math
import re
from typing import Dict, List
from urllib.parse import urlparse

import numpy as np

from app.services.email_parser.models import ParsedEmail

# ---------------------------------------------------------------------------
# Phishing lexicon
# ---------------------------------------------------------------------------
_URGENCY_RE = re.compile(
    r"\b(immediately|urgent|asap|right now|act now|within \d+ hours?|"
    r"limited time|expires? (today|tonight|soon)|final (warning|notice|reminder)|"
    r"last chance|time.sensitive)\b", re.I,
)
_CREDENTIAL_RE = re.compile(
    r"\b(verify|confirm|validate|update|enter|provide|submit|reset)"
    r".{0,50}(password|credential|login|account|pin|otp|one.time.code|"
    r"security code|2fa|two.factor)\b", re.I,
)
_PAYMENT_RE = re.compile(
    r"\b(gift cards?|wire transfer|western union|bitcoin|crypto|bank account|"
    r"routing number|payment required|invoice overdue)\b", re.I,
)
_THREAT_RE = re.compile(
    r"\b(suspend(ed)?|terminat(e|ed|ion)|disabl(e|ed)|lock(ed)?|restrict(ed)?|"
    r"block(ed)?|closed|deleted) (account|access|profile)\b", re.I,
)
_IMPERSONATION_RE = re.compile(
    r"\b(paypal|amazon|apple|google|microsoft|netflix|facebook|instagram|"
    r"whatsapp|bank of america|chase|wells fargo|irs|internal revenue|"
    r"fedex|ups|dhl|usps)\b", re.I,
)
_LOOKALIKE_RE = re.compile(
    r"(paypa[l1]|amaz[o0]n|app[l1]e|g[o0]{2}gle|micros[o0]ft|"
    r"netfl[i1]x|fac[e3]book|[il1]nstagram)", re.I,
)
_OBFUSCATION_RE = re.compile(r"(%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|&#\d+;|\\u[0-9a-fA-F]{4})")
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

# ---------------------------------------------------------------------------
# Feature name registry
# ---------------------------------------------------------------------------
FEATURE_NAMES: List[str] = []


def _register(names: List[str]) -> List[str]:
    FEATURE_NAMES.extend(names)
    return names


_G1 = _register([
    "hop_count", "has_hops", "max_hop_delay_seconds", "total_hop_delay_seconds",
    "hop_timestamp_anomaly", "received_loop_detected", "hops_crossing_country",
    "header_count", "has_reply_to", "reply_to_differs_from_sender",
    "has_x_mailer", "has_x_originating_ip", "has_list_unsubscribe",
    "subject_re_fwd_prefix", "subject_empty",
])
_G2 = _register([
    "spf_pass", "spf_fail", "spf_softfail", "spf_none",
    "dkim_pass", "dkim_fail", "dkim_none",
    "dmarc_pass", "dmarc_fail", "dmarc_none",
])
_G3 = _register([
    "sender_is_free_mailer", "sender_has_suspicious_tld",
    "sender_domain_numeric_label", "sender_domain_depth",
    "sender_subdomain_count", "sender_has_plus_addressing",
    "from_display_name_differs", "from_display_is_brand",
    "from_domain_lookalike", "sender_domain_length",
    "envelope_from_differs", "from_has_ip_literal",
])
_G4 = _register([
    "url_count", "unique_domain_count", "urls_to_ip_address",
    "url_uses_shortener", "url_max_depth", "url_has_suspicious_tld",
    "url_has_obfuscation", "url_redirect_chain_suspected",
    "url_auth_params_detected", "url_mismatched_anchor_text",
])
_G5 = _register([
    "urgency_match_count", "credential_match_count",
    "payment_match_count", "threat_match_count",
    "impersonation_match_count", "body_word_count",
    "body_unique_word_ratio", "html_to_text_ratio",
    "excessive_html_entities", "all_caps_ratio",
    "exclamation_count", "question_count",
    "body_entropy", "lookalike_brand_in_body",
    "obfuscation_chars_in_body",
])
_G6 = _register([
    "attachment_count", "has_executable_attachment",
    "has_double_extension", "has_archive_attachment",
    "has_office_macro_extension", "attachment_is_suspicious",
    "max_attachment_size_kb", "zero_byte_attachment",
])
_G7 = _register([
    "is_multipart", "has_html_part", "has_plain_part",
    "has_both_parts", "message_id_present", "message_id_suspicious",
    "date_header_present", "date_future_by_days", "date_past_by_days",
    "total_indicator_count",
])

N_FEATURES = len(FEATURE_NAMES)
assert N_FEATURES == 80, f"Expected 80 features, got {N_FEATURES}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract(parsed: ParsedEmail) -> np.ndarray:
    """Return float32 feature vector of shape (N_FEATURES,)."""
    vec: List[float] = []
    vec.extend(_g1_headers(parsed))
    vec.extend(_g2_auth(parsed))
    vec.extend(_g3_sender(parsed))
    vec.extend(_g4_urls(parsed))
    vec.extend(_g5_content(parsed))
    vec.extend(_g6_attachments(parsed))
    vec.extend(_g7_structural(parsed))
    assert len(vec) == N_FEATURES
    return np.array(vec, dtype=np.float32)


def extract_named(parsed: ParsedEmail) -> Dict[str, float]:
    """Return {feature_name: value} dict for interpretability."""
    return dict(zip(FEATURE_NAMES, extract(parsed).tolist()))


# ---------------------------------------------------------------------------
# Group extractors
# ---------------------------------------------------------------------------

def _g1_headers(p: ParsedEmail) -> List[float]:
    from datetime import datetime, timezone
    from email.utils import parsedate_to_datetime

    hops = p.hops or []
    hop_count = float(len(hops))
    has_hops = float(hop_count > 0)

    parsed_times: List[datetime] = []
    for hop in hops:
        if hop.timestamp:
            try:
                dt = parsedate_to_datetime(hop.timestamp)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                parsed_times.append(dt.astimezone(timezone.utc))
            except Exception:
                pass

    delays = [abs((b - a).total_seconds()) for a, b in zip(parsed_times, parsed_times[1:])]
    # Clamp delays to at most 7 days to prevent multi-year parsing artifacts from missing timezones
    delays = [min(d, 86400.0 * 7) for d in delays]
    max_delay = float(max(delays)) if delays else 0.0
    total_delay = float(sum(delays))
    anomaly = float(any(d > 3600 for d in delays))
    loop = float(len({h.from_host for h in hops if h.from_host}) < hop_count * 0.6 and hop_count > 2)
    crossing = min(hop_count, 5.0)

    header_names = [h.name.lower() for h in (p.headers or [])]
    header_count = float(len(header_names))
    has_reply_to = float("reply-to" in header_names)
    reply_differs = 0.0
    if has_reply_to:
        rt_vals = [h.value for h in (p.headers or []) if h.name.lower() == "reply-to"]
        reply_differs = float(bool(rt_vals and p.from_addr and rt_vals[0].strip() != p.from_addr.strip()))
    has_x_mailer = float("x-mailer" in header_names)
    has_x_orig_ip = float("x-originating-ip" in header_names)
    has_unsub = float("list-unsubscribe" in header_names)

    subj = (p.subject or "").strip()
    re_fwd = float(bool(re.match(r"^(re|fwd?):\s", subj, re.I)))
    subj_empty = float(not subj)

    return [
        hop_count, has_hops, max_delay, total_delay,
        anomaly, loop, crossing,
        header_count, has_reply_to, reply_differs,
        has_x_mailer, has_x_orig_ip, has_unsub,
        re_fwd, subj_empty,
    ]


def _g2_auth(p: ParsedEmail) -> List[float]:
    auth = {a.protocol.lower(): a.result.lower() for a in (p.auth_results or [])}
    spf = auth.get("spf", "none")
    dkim = auth.get("dkim", "none")
    dmarc = auth.get("dmarc", "none")
    return [
        float(spf == "pass"), float(spf == "fail"), float(spf == "softfail"), float(spf == "none"),
        float(dkim == "pass"), float(dkim == "fail"), float(dkim == "none"),
        float(dmarc == "pass"), float(dmarc == "fail"), float(dmarc == "none"),
    ]


def _g3_sender(p: ParsedEmail) -> List[float]:
    from_raw = p.from_addr or ""
    m = re.search(r"<([^>]+)>", from_raw)
    addr = m.group(1).strip() if m else from_raw.strip()
    parts = addr.rsplit("@", 1)
    domain = parts[1].lower() if len(parts) == 2 else ""
    labels = domain.split(".") if domain else []

    is_free = float(domain in _FREE_MAILER_DOMAINS)
    susp_tld = float(any(domain.endswith(t) for t in _SUSPICIOUS_TLDS))
    numeric_label = float(any(lbl.isdigit() for lbl in labels))
    domain_depth = float(len(labels))
    subdomain_count = float(max(0, len(labels) - 2))
    plus_addr = float("+" in (parts[0] if len(parts) == 2 else ""))

    display_match = re.match(r"^(.+?)\s*<", from_raw)
    display_name = display_match.group(1).strip().strip('"') if display_match else ""
    display_differs = float(bool(display_name) and display_name.lower() != addr.lower())
    display_is_brand = float(bool(display_name and _IMPERSONATION_RE.search(display_name)))
    from_lookalike = float(bool(_LOOKALIKE_RE.search(domain)))
    domain_len = float(len(domain))

    rp_vals = [h.value for h in (p.headers or []) if h.name.lower() in ("return-path", "envelope-from")]
    env_differs = float(bool(rp_vals and rp_vals[0].strip() != from_raw.strip()))
    ip_literal = float(bool(re.search(r"\[\d+\.\d+\.\d+\.\d+\]", from_raw)))

    return [
        is_free, susp_tld, numeric_label, domain_depth,
        subdomain_count, plus_addr, display_differs, display_is_brand,
        from_lookalike, domain_len, env_differs, ip_literal,
    ]


def _g4_urls(p: ParsedEmail) -> List[float]:
    indicators = p.indicators or []
    urls = [i for i in indicators if i.type == "URL"]
    url_count = float(len(urls))
    if not urls:
        return [0.0] * 10

    domains: set = set()
    ip_count = 0
    shortener_count = 0
    max_depth = 0
    susp_tld = 0
    obfusc = 0
    auth_params = 0

    for ind in urls:
        raw = ind.normalized_value or ind.raw_value
        try:
            parsed = urlparse(raw)
            host = parsed.hostname or ""
            domains.add(host)
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                ip_count += 1
            if host in _URL_SHORTENERS:
                shortener_count += 1
            path_depth = len([s for s in parsed.path.split("/") if s])
            max_depth = max(max_depth, path_depth)
            if any(host.endswith(t) for t in _SUSPICIOUS_TLDS):
                susp_tld += 1
            if _OBFUSCATION_RE.search(raw):
                obfusc += 1
            qs = parsed.query.lower()
            if any(qp in qs for qp in ("redirect=", "url=", "next=", "goto=", "redir=")):
                auth_params += 1
        except Exception:
            pass

    return [
        url_count, float(len(domains)), float(ip_count),
        float(shortener_count > 0), float(max_depth),
        float(susp_tld > 0), float(obfusc > 0),
        float(auth_params > 0), float(auth_params),
        0.0,  # url_mismatched_anchor_text — requires anchor context
    ]


def _g5_content(p: ParsedEmail) -> List[float]:
    from app.services.email_parser.body import strip_html
    plain = p.plain_body or ""
    html_stripped = strip_html(p.html_body or "") if p.html_body else ""
    text = plain or html_stripped

    urgency = float(len(_URGENCY_RE.findall(text)))
    credential = float(len(_CREDENTIAL_RE.findall(text)))
    payment = float(len(_PAYMENT_RE.findall(text)))
    threat = float(len(_THREAT_RE.findall(text)))
    impersonation = float(len(_IMPERSONATION_RE.findall(text)))

    words = text.split()
    word_count = float(len(words))
    unique_ratio = float(len(set(words)) / max(len(words), 1))

    html_len = float(len(p.html_body or ""))
    plain_len = float(len(plain))
    html_ratio = html_len / max(plain_len + html_len, 1)

    entity_count = float(len(re.findall(r"&[a-z]+;", (p.html_body or ""))))
    excessive_entities = float(entity_count > 50)

    caps_count = sum(1 for w in words if w.isupper() and len(w) > 2)
    caps_ratio = float(caps_count / max(len(words), 1))
    excl = float(text.count("!"))
    quest = float(text.count("?"))

    entropy = _shannon_entropy(text[:2000]) if text else 0.0
    lookalike_body = float(bool(_LOOKALIKE_RE.search(text)))
    obfusc_body = float(len(_OBFUSCATION_RE.findall(text)))

    return [
        urgency, credential, payment, threat, impersonation,
        word_count, unique_ratio, html_ratio, excessive_entities,
        caps_ratio, excl, quest, entropy, lookalike_body, obfusc_body,
    ]


def _g6_attachments(p: ParsedEmail) -> List[float]:
    atts = p.attachments or []
    count = float(len(atts))
    if count == 0:
        return [0.0] * 8

    _EXEC = {".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".sh", ".msi", ".scr", ".com"}
    _ARCH = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".lz", ".cab", ".iso"}
    _MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}

    execs = sum(1 for a in atts if a.extension and a.extension.lower() in _EXEC)
    doubles = sum(1 for a in atts if a.filename and a.filename.count(".") > 1
                  and a.extension and a.extension.lower() in _EXEC | _ARCH)
    archives = sum(1 for a in atts if a.extension and a.extension.lower() in _ARCH)
    macros = sum(1 for a in atts if a.extension and a.extension.lower() in _MACRO)
    suspicious = sum(1 for a in atts if a.is_suspicious)
    max_size = max((a.size or 0 for a in atts), default=0)
    zero_byte = sum(1 for a in atts if (a.size or 0) == 0)

    return [
        count, float(execs > 0), float(doubles > 0), float(archives > 0),
        float(macros > 0), float(suspicious > 0), float(max_size / 1024),
        float(zero_byte > 0),
    ]


def _g7_structural(p: ParsedEmail) -> List[float]:
    from datetime import datetime, timezone
    from email.utils import parsedate_to_datetime

    is_multipart = float(bool(p.html_body and p.plain_body))
    has_html = float(bool(p.html_body))
    has_plain = float(bool(p.plain_body))
    has_both = float(bool(p.html_body and p.plain_body))

    mid_vals = [h.value for h in (p.headers or []) if h.name.lower() == "message-id"]
    has_mid = float(bool(mid_vals))
    mid_susp = 0.0
    if mid_vals:
        mid = mid_vals[0]
        mid_susp = float(len(mid) < 10 or "@" not in mid or "http" in mid.lower())

    date_vals = [h.value for h in (p.headers or []) if h.name.lower() == "date"]
    has_date = float(bool(date_vals))
    future_days = 0.0
    past_days = 0.0
    if date_vals:
        try:
            dt = parsedate_to_datetime(date_vals[0])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            diff_days = (dt - now).total_seconds() / 86400
            # Future date anomaly: email claimed to be sent in the future
            future_days = min(float(max(0.0, diff_days)), 30.0)
            # Past date anomaly: only flag if predates email RFC era or unix epoch forgery (< 1990)
            past_days = float(dt.year < 1990)
        except Exception:
            pass

    indicator_count = float(len(p.indicators or []))
    return [
        is_multipart, has_html, has_plain, has_both,
        has_mid, mid_susp, has_date, future_days, past_days,
        indicator_count,
    ]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return float(-sum((c / total) * math.log2(c / total) for c in freq.values()))
