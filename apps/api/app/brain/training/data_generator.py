"""
SENTINEL Brain — Synthetic Training Data Generator
===================================================
Generates a large, balanced, realistic labelled dataset for training
the brain's ML classifiers entirely offline — no external data required.

Labels  (multi-class)
---------------------
  0  BENIGN       — legitimate email
  1  SUSPICIOUS   — ambiguous signals, possible spam/grey
  2  PHISHING     — social-engineering, credential harvesting
  3  MALICIOUS    — malware distribution, RAT dropper, ransomware lure
"""

from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# We build ParsedEmail-compatible dicts and pass them through features.extract()
# to avoid duplicating feature logic here.

# ---------------------------------------------------------------------------
# Label constants
# ---------------------------------------------------------------------------
LABEL_BENIGN     = 0
LABEL_SUSPICIOUS = 1
LABEL_PHISHING   = 2
LABEL_MALICIOUS  = 3
LABEL_NAMES = {0: "BENIGN", 1: "SUSPICIOUS", 2: "PHISHING", 3: "MALICIOUS"}

# ---------------------------------------------------------------------------
# Corpus pools used to synthesise realistic data
# ---------------------------------------------------------------------------
_BENIGN_SUBJECTS = [
    "Meeting notes from today", "Q3 budget review", "Re: project update",
    "Invoice #12345", "Welcome to the team!", "Your order has shipped",
    "Newsletter: Top stories this week", "Fwd: Conference details",
    "Happy birthday!", "Reminder: dentist appointment", "Team lunch Thursday",
    "Your monthly statement is ready", "Job application confirmation",
    "Feedback requested on proposal", "Git pull request approved",
]
_PHISHING_SUBJECTS = [
    "Urgent: Your account has been suspended",
    "Action required: Verify your PayPal account",
    "Your Apple ID was used to sign in to iCloud",
    "Final warning: Update your billing information",
    "Your Amazon order cannot be shipped — verify now",
    "Security alert: Unusual sign-in activity detected",
    "Important: Your Microsoft account requires attention",
    "URGENT: IRS tax refund — claim within 24 hours",
    "Your Netflix membership has been suspended",
    "Wells Fargo: Confirm your identity to avoid closure",
    "Verify your account immediately — limited time",
    "Password reset required — act now",
]
_MALWARE_SUBJECTS = [
    "Invoice attached — please review",
    "PO #87432 — quotation enclosed",
    "Your document is ready to download",
    "Fwd: Important contract — signature required",
    "DHL: Your shipment requires customs verification",
    "Payslip for this period",
    "Scanned document from HR",
]
_BENIGN_SENDERS = [
    "alice@company.com", "hr@yourcompany.org", "noreply@github.com",
    "newsletter@medium.com", "support@slack.com", "billing@amazon.com",
    "no-reply@google.com", "notifications@linkedin.com", "info@zoom.us",
    "team@notion.so", "hello@stripe.com", "contact@example.com",
]
_PHISHING_SENDERS = [
    "security-noreply@paypa1-secure.xyz", "apple-id@account-alert.top",
    "support@amazon-billing.click", "no-reply@microsoft-security.link",
    "irs-refund@gov-taxrefund.com", "noreply@netfl1x-billing.info",
    "security@wellsfarg0.com", "verify@amazonsupport.xyz",
    "account@paypal.servicesecure.net", "admin@faceb00k-login.top",
]
_MALWARE_SENDERS = [
    "invoices@cheapsupplier.ru", "accounts@finance-dept.cn",
    "hr-payroll@staffingsolutions.biz", "noreply@document-delivery.top",
    "delivery@dhl-customs-fee.xyz", "no-reply@invoice-portal.link",
]
_PHISHING_BODIES = [
    "Dear Customer,\n\nWe have detected suspicious activity on your account. "
    "Please verify your identity within 24 hours or your account will be suspended.\n"
    "Click here to verify: http://paypa1-secure.xyz/verify?token=abc123\n\nPayPal Security Team",

    "Your Apple ID has been locked due to unusual activity. "
    "Enter your password and billing info at: https://apple-id.account-alert.top/unlock\n"
    "Failure to verify within 48 hours will result in permanent account deletion.",

    "URGENT: The IRS has detected an error in your tax return. "
    "You are owed a refund of $2,847.00. To claim your refund, "
    "please confirm your bank account details at: http://gov-taxrefund.link/claim",
]
_MALWARE_BODIES = [
    "Please find the attached invoice for services rendered this month. "
    "Kindly review and process payment at your earliest convenience.",

    "Dear Sir/Madam, Please see the attached purchase order #87432. "
    "Open the document and follow the instructions inside.",

    "Your scanned document is attached. To view it, you may need to "
    "enable macros in Microsoft Word. Please open the attachment.",
]
_BENIGN_BODIES = [
    "Hi team,\n\nJust a quick reminder that our Q3 review meeting is scheduled for Thursday at 2pm. "
    "Please prepare your department updates beforehand.\n\nBest,\nAlice",

    "Your order #123-456-789 has shipped! Expected delivery: 2-3 business days. "
    "Track your package at: https://amazon.com/track",

    "This month's newsletter covers our top engineering articles, open source picks, "
    "and upcoming community events. Read more at medium.com",
    "Your password was changed successfully from the Security Settings page. "
    "If you made this change, no action is needed. Contact IT through the internal portal if not.",
    "Attached is the approved invoice from our vendor. The purchase order and payment terms "
    "are available in the finance system at https://finance.company.com/invoices.",
    "Your two-factor authentication code was requested for a sign-in. If you did not request it, "
    "review recent activity from the account settings page without replying to this message.",
]
_EXEC_EXTENSIONS = [".exe", ".bat", ".vbs", ".js", ".ps1", ".scr"]
_ARCHIVE_EXTENSIONS = [".zip", ".rar", ".7z", ".iso"]
_OFFICE_MACRO_EXTENSIONS = [".docm", ".xlsm", ".pptm"]
_BENIGN_EXTENSIONS = [".pdf", ".docx", ".xlsx", ".png", ".jpg", ".txt", ".csv"]


# ---------------------------------------------------------------------------
# Synthetic record builder
# ---------------------------------------------------------------------------

def _rand_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_domain(suspicious: bool = False) -> str:
    tlds = [".xyz", ".top", ".click"] if suspicious else [".com", ".org", ".net"]
    length = random.randint(8, 18) if suspicious else random.randint(4, 12)
    name = "".join(random.choices(string.ascii_lowercase, k=length))
    return name + random.choice(tlds)


def _rand_message_id(suspicious: bool = False) -> str:
    if suspicious:
        return f"<{''.join(random.choices(string.digits, k=4))}>"
    host = _rand_domain()
    uid = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return f"<{uid}@{host}>"


def _make_hop(num: int, suspicious: bool = False) -> Dict[str, Any]:
    from_host = _rand_domain(suspicious)
    by_host = _rand_domain(suspicious)
    return {
        "hop_number": num,
        "from_host": from_host,
        "by_host": by_host,
        "ip_address": _rand_ip() if suspicious else _rand_ip(),
        "timestamp": "Sat, 01 Jan 2026 12:00:00 +0000",
    }


def _make_parsed_dict(
    label: int,
    rng: random.Random,
) -> Dict[str, Any]:
    """Build a dict that mimics ParsedEmail field structure."""
    is_phish = label == LABEL_PHISHING
    is_mal = label == LABEL_MALICIOUS
    is_susp = label == LABEL_SUSPICIOUS
    is_benign = label == LABEL_BENIGN

    # Subject
    if is_phish:
        subject = rng.choice(_PHISHING_SUBJECTS)
    elif is_mal:
        subject = rng.choice(_MALWARE_SUBJECTS)
    elif is_susp:
        subject = rng.choice(_PHISHING_SUBJECTS[:4] + _BENIGN_SUBJECTS[:4])
    else:
        subject = rng.choice(_BENIGN_SUBJECTS)

    # Sender
    if is_phish:
        from_addr = rng.choice(_PHISHING_SENDERS)
    elif is_mal:
        from_addr = rng.choice(_MALWARE_SENDERS)
    elif is_susp:
        from_addr = rng.choice(_PHISHING_SENDERS[:3] + _BENIGN_SENDERS[:3])
    else:
        from_addr = rng.choice(_BENIGN_SENDERS)

    # Auth results
    if is_phish or is_mal:
        spf = rng.choice(["fail", "softfail", "none", "none"])
        dkim = rng.choice(["fail", "none", "none"])
        dmarc = rng.choice(["fail", "none", "none"])
    elif is_susp:
        spf = rng.choice(["softfail", "none", "pass"])
        dkim = rng.choice(["none", "fail", "pass"])
        dmarc = rng.choice(["none", "fail", "pass"])
    else:
        spf = rng.choice(["pass", "pass", "pass", "none"])
        dkim = rng.choice(["pass", "pass", "pass", "none"])
        dmarc = rng.choice(["pass", "pass", "none"])

    auth_results = [
        {"protocol": "spf", "result": spf, "details": ""},
        {"protocol": "dkim", "result": dkim, "details": ""},
        {"protocol": "dmarc", "result": dmarc, "details": ""},
    ]

    # Hops
    n_hops = rng.randint(3, 7) if (is_phish or is_mal) else rng.randint(1, 4)
    hops = [_make_hop(i + 1, suspicious=(is_phish or is_mal)) for i in range(n_hops)]

    # Body
    if is_phish:
        plain_body = rng.choice(_PHISHING_BODIES)
        html_body = f"<html><body>{plain_body.replace(chr(10), '<br>')}</body></html>"
    elif is_mal:
        plain_body = rng.choice(_MALWARE_BODIES)
        html_body = None
    elif is_susp:
        plain_body = rng.choice(_PHISHING_BODIES[:1] + _BENIGN_BODIES[:1])
        html_body = f"<html><body>{plain_body}</body></html>"
    else:
        plain_body = rng.choice(_BENIGN_BODIES)
        html_body = f"<html><body><p>{plain_body}</p></body></html>"

    # Vary wording and delivery patterns so the model learns combinations of
    # evidence rather than memorising a few exact templates.
    if is_phish and rng.random() < 0.35:
        plain_body += rng.choice([
            "\nPlease use the secure portal below to confirm your identity.",
            "\nFailure to act today may result in account closure.",
            "\nPayment must be completed with gift cards to avoid service interruption.",
        ])
    elif is_mal and rng.random() < 0.45:
        plain_body += rng.choice([
            "\nThe archive is password protected; use the password in this message.",
            "\nEnable content or macros if the document appears blank.",
            "\nRun the attached installer to view the complete document.",
        ])
    elif is_susp and rng.random() < 0.35:
        plain_body += "\nThis message was sent to a large distribution list."
    if html_body:
        html_body = f"<html><body>{plain_body.replace(chr(10), '<br>')}</body></html>"

    # URLs / indicators
    indicators = []
    if is_phish:
        n_urls = rng.randint(1, 4)
        for _ in range(n_urls):
            host = rng.choice([
                _rand_domain(True),
                "bit.ly",
                "xn--80ak6aa92e.com",
            ])
            path = rng.choice(["/verify", "/login", "/secure/account"])
            query = rng.choice([
                "token=" + "".join(rng.choices(string.ascii_lowercase, k=16)),
                "redirect=https%3A%2F%2Flogin.example.com",
                "url=https%3A%2F%2Faccount.example.com",
            ])
            url = f"http://{host}{path}?{query}"
            indicators.append({"type": "URL", "raw_value": url, "normalized_value": url, "is_private": False})
        # also domain indicators
        dom = _rand_domain(True)
        indicators.append({"type": "DOMAIN", "raw_value": dom, "normalized_value": dom, "is_private": False})
    elif is_mal:
        n_urls = rng.randint(0, 2)
        for _ in range(n_urls):
            url = f"http://{_rand_domain(True)}/download/payload.exe"
            indicators.append({"type": "URL", "raw_value": url, "normalized_value": url, "is_private": False})
    elif is_benign:
        n_urls = rng.randint(0, 3)
        for _ in range(n_urls):
            url = f"https://www.{_rand_domain()}/page"
            indicators.append({"type": "URL", "raw_value": url, "normalized_value": url, "is_private": False})

    # Attachments
    attachments = []
    if is_mal and rng.random() > 0.2:
        ext = rng.choice(_EXEC_EXTENSIONS + _ARCHIVE_EXTENSIONS + _OFFICE_MACRO_EXTENSIONS)
        fname = "document" + ext if rng.random() > 0.5 else f"invoice.pdf{ext}"
        attachments.append({
            "filename": fname,
            "extension": ext,
            "mime_type": "application/octet-stream",
            "size": rng.randint(10000, 2000000),
            "sha256": "a" * 64,
            "is_suspicious": True,
            "magic_bytes": None,
        })
    elif is_phish and rng.random() > 0.6:
        ext = rng.choice(_OFFICE_MACRO_EXTENSIONS + [".pdf"])
        attachments.append({
            "filename": "form" + ext,
            "extension": ext,
            "mime_type": "application/octet-stream",
            "size": rng.randint(50000, 500000),
            "sha256": "b" * 64,
            "is_suspicious": ext in _OFFICE_MACRO_EXTENSIONS,
            "magic_bytes": None,
        })
    elif is_benign and rng.random() > 0.6:
        ext = rng.choice(_BENIGN_EXTENSIONS)
        attachments.append({
            "filename": "document" + ext,
            "extension": ext,
            "mime_type": "application/pdf",
            "size": rng.randint(20000, 500000),
            "sha256": "c" * 64,
            "is_suspicious": False,
            "magic_bytes": None,
        })

    # Headers - match realistic header depth so header_count is realistic
    message_id = _rand_message_id(suspicious=(is_phish or is_mal))
    headers = [
        {"name": "Return-Path", "value": f"<{from_addr}>"},
        {"name": "Delivered-To", "value": "user@company.com"},
        {"name": "Received", "value": f"from mail.{_rand_domain(is_phish or is_mal)} by mx.company.com"},
        {"name": "Received", "value": f"from internal.{_rand_domain(is_phish or is_mal)} by relay.company.com"},
        {"name": "From", "value": from_addr},
        {"name": "To", "value": "user@company.com"},
        {"name": "Subject", "value": subject},
        {"name": "Date", "value": "Sat, 01 Jan 2026 12:00:00 +0000"},
        {"name": "Message-ID", "value": message_id},
        {"name": "MIME-Version", "value": "1.0"},
        {"name": "Content-Type", "value": "multipart/alternative" if html_body else "text/plain"},
        {"name": "Content-Transfer-Encoding", "value": "7bit"},
        {"name": "X-Priority", "value": "1" if is_phish else "3"},
        {"name": "User-Agent", "value": "Thunderbird/115.0" if is_benign else "PHPMailer 6.0"},
    ]
    if is_phish and rng.random() > 0.4:
        headers.append({"name": "Reply-To", "value": f"reply@{_rand_domain(True)}"})
    if is_benign and rng.random() > 0.5:
        headers.append({"name": "List-Unsubscribe", "value": "<mailto:unsub@list.example.com>"})
    if rng.random() > 0.5:
        headers.append({"name": "X-Mailer", "value": "PHPMailer 6.0" if (is_phish or is_mal) else "Apple Mail"})

    # Always ensure sender domain and IP are indicators
    indicators.append({"type": "DOMAIN", "raw_value": from_addr.split("@")[-1], "normalized_value": from_addr.split("@")[-1], "is_private": False})
    indicators.append({"type": "IP", "raw_value": _rand_ip(), "normalized_value": _rand_ip(), "is_private": False})

    return {
        "subject": subject,
        "from_addr": from_addr,
        "plain_body": plain_body,
        "html_body": html_body,
        "auth_results": auth_results,
        "hops": hops,
        "indicators": indicators,
        "attachments": attachments,
        "headers": headers,
    }


# ---------------------------------------------------------------------------
# ParsedEmail-compatible lightweight namedtuple stubs
# ---------------------------------------------------------------------------

class _Stub:
    """Turn a dict into an attribute-accessible object recursively."""
    def __init__(self, d: Dict[str, Any]):
        for k, v in d.items():
            if isinstance(v, list):
                setattr(self, k, [_Stub(i) if isinstance(i, dict) else i for i in v])
            elif isinstance(v, dict):
                setattr(self, k, _Stub(v))
            else:
                setattr(self, k, v)

    def __getattr__(self, name: str):
        return None  # graceful miss


# ---------------------------------------------------------------------------
# Dataset generation
# ---------------------------------------------------------------------------

def generate_dataset(
    n_per_class: int = 3000,
    seed: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate a balanced synthetic dataset.
    Returns
    -------
    X : ndarray of shape (n_samples, N_FEATURES), dtype float32
    y : ndarray of shape (n_samples,), dtype int32  — class labels
    """
    from app.brain.features import extract  # lazy import to avoid circular

    rng = random.Random(seed)
    labels_list = [LABEL_BENIGN, LABEL_SUSPICIOUS, LABEL_PHISHING, LABEL_MALICIOUS]

    X_rows: List[np.ndarray] = []
    y_rows: List[int] = []

    for label in labels_list:
        for _ in range(n_per_class):
            d = _make_parsed_dict(label, rng)
            stub = _Stub(d)
            try:
                vec = extract(stub)  # type: ignore[arg-type]
                X_rows.append(vec)
                y_rows.append(label)
            except Exception:
                pass  # skip broken synthetic records

    X = np.stack(X_rows, axis=0).astype(np.float32)
    y = np.array(y_rows, dtype=np.int32)
    return X, y
