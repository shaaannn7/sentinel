"""Safe URL normalization and signal analysis; no URLs are fetched."""

import re
import ipaddress
from urllib.parse import urlsplit
from app.services.email_parser.models import ParsedEmail
from app.services.analysis.models import AnalyzerResult, EvidenceItem, FindingDraft
from app.services.analysis.evidence import evidence

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
_TRAILING = ".,;:!?)>]}'\""


def normalize(raw: str) -> dict:
    raw = raw.strip().rstrip(_TRAILING)
    candidate = raw if "://" in raw else f"http://{raw}"
    p = urlsplit(candidate)
    host = (p.hostname or "").lower().rstrip(".")
    return {"raw_url": raw, "normalized_url": f"{p.scheme.lower()}://{host}{(':'+str(p.port)) if p.port else ''}{p.path or ''}{('?'+p.query) if p.query else ''}{('#'+p.fragment) if p.fragment else ''}",
            "scheme": p.scheme.lower(), "hostname": host, "port": p.port, "path": p.path, "query": p.query, "fragment": p.fragment}


def analyze(parsed: ParsedEmail) -> AnalyzerResult:
    result = AnalyzerResult(stage="URL_ANALYSIS")
    urls = [i.raw_value for i in parsed.indicators if i.type == "URL"]
    normalized = []
    signal_keys: set[str] = set()
    for raw in urls:
        try:
            item = normalize(raw)
        except ValueError:
            result.warnings.append("A URL with an invalid port was ignored")
            continue
        host = item["hostname"]
        if not host:
            continue
        ev = evidence(EvidenceItem("URL", "email content", item["normalized_url"],
                                   f"Observed URL: {item['normalized_url']}.", item))
        result.evidence.append(ev)
        normalized.append(item)
        try:
            ipaddress.ip_address(host)
            key = "ip"
            if key not in signal_keys:
                result.findings.append(FindingDraft("LOW", "URL", "URL uses an IP address instead of a domain.",
                    "An observed URL targets an IP literal rather than a domain name.", [ev], "urls", 10))
                signal_keys.add(key)
        except ValueError:
            pass
        if item["port"] and item["port"] not in {80, 443} and "port" not in signal_keys:
            result.findings.append(FindingDraft("INFO", "URL", "Non-standard web port observed.",
                f"The URL uses port {item['port']}; a non-standard port is a signal, not proof of maliciousness.", [ev], "urls", 3))
            signal_keys.add("port")
        if host in SHORTENERS and "shortener" not in signal_keys:
            result.findings.append(FindingDraft("LOW", "URL", "URL shortening service detected.",
                "A configured URL-shortening service was observed; the destination is not inferred.", [ev], "urls", 5))
            signal_keys.add("shortener")
        if host.startswith("xn--") or ".xn--" in host:
            result.findings.append(FindingDraft("INFO", "DOMAIN", "Internationalized/punycode domain observed.",
                "The URL hostname contains punycode. This is an observation and is not automatically malicious.", [ev], "urls", 2))
        if host.count(".") >= 3 and "subdomains" not in signal_keys:
            result.findings.append(FindingDraft("INFO", "DOMAIN", "Many hostname labels observed.",
                "The URL contains multiple subdomain labels; this can be legitimate and should be reviewed in context.", [ev], "urls", 2))
            signal_keys.add("subdomains")
        if sum(1 for c in raw if c == "%") >= 3 and "encoding" not in signal_keys:
            result.findings.append(FindingDraft("LOW", "URL", "Encoded URL characteristics observed.",
                "The URL contains repeated percent-encoding sequences.", [ev], "urls", 5))
            signal_keys.add("encoding")
    result.data = {"urls": normalized}
    return result
