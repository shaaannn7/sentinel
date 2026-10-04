"""Domain structure and configurable lookalike analysis."""

import ipaddress
from urllib.parse import urlsplit
from difflib import SequenceMatcher
from app.services.email_parser.models import ParsedEmail
from app.services.analysis.models import AnalyzerResult, EvidenceItem, FindingDraft
from app.services.analysis.evidence import evidence

PROTECTED_DOMAINS = {"paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com"}
COMMON_MULTI_TLDS = {"co.uk", "com.au", "co.jp", "co.in", "org.uk"}


def domain_parts(hostname: str) -> dict:
    host = hostname.lower().rstrip(".")
    labels = host.split(".")
    suffix = ".".join(labels[-2:]) if len(labels) >= 2 else ""
    if suffix in COMMON_MULTI_TLDS and len(labels) >= 3:
        registrable = ".".join(labels[-3:])
        subdomain = ".".join(labels[:-3])
        tld = suffix
    else:
        registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
        subdomain = ".".join(labels[:-2])
        tld = labels[-1] if labels else ""
    return {"hostname": host, "registrable_domain": registrable, "subdomain": subdomain, "tld": tld,
            "label_count": len(labels), "length": len(host), "punycode": any(x.startswith("xn--") for x in labels)}


def analyze(parsed: ParsedEmail, protected_domains: set[str] | None = None) -> AnalyzerResult:
    result = AnalyzerResult(stage="DOMAIN_ANALYSIS")
    protected = protected_domains or PROTECTED_DOMAINS
    hosts = []
    for ind in parsed.indicators:
        if ind.type == "DOMAIN":
            hosts.append(ind.normalized_value)
    for item in parsed.indicators:
        if item.type != "URL":
            continue
        raw_val = item.normalized_value or ""
        candidate = raw_val if "://" in raw_val else f"http://{raw_val}"
        host = urlsplit(candidate).hostname or ""
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError:
            hosts.append(host)
    seen = set()
    for host in hosts:
        parts = domain_parts(host)
        if parts["hostname"] in seen:
            continue
        seen.add(parts["hostname"])
        ev = evidence(EvidenceItem("DOMAIN", "email indicator", parts["hostname"],
                                   f"Observed domain {parts['hostname']}.", parts))
        result.evidence.append(ev)
        target = None
        similarity = 0.0
        for known in protected:
            observed_label = parts["registrable_domain"].split(".", 1)[0].split("-", 1)[0]
            known_label = known.split(".", 1)[0].replace("-", "")
            score = SequenceMatcher(None, observed_label, known_label).ratio()
            if (score >= 0.78 and abs(len(observed_label) - len(known_label)) <= 2
                    and parts["registrable_domain"] != known and score > similarity):
                target, similarity = known, score
        if target:
            result.findings.append(FindingDraft("MEDIUM", "DOMAIN", "Potential lookalike domain",
                f"Observed domain is similar to protected domain {target} (character similarity {similarity:.0%}). This is a potential impersonation signal, not a phishing determination.",
                [ev], "domains", 15, "MEDIUM"))
    result.data = {"domains": [domain_parts(h) for h in seen]}
    return result
