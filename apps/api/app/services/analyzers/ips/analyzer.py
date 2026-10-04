"""Standard-library IP classification and external lookup safety."""

import ipaddress
from app.services.email_parser.models import ParsedEmail
from app.services.analysis.models import AnalyzerResult, EvidenceItem
from app.services.analysis.evidence import evidence


def classify_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "INVALID"
    if address.is_loopback: return "LOOPBACK"
    if address.is_link_local: return "LINK_LOCAL"
    if address.is_multicast: return "MULTICAST"
    if address.is_private: return "PRIVATE"
    if address.is_reserved: return "RESERVED"
    return "PUBLIC"


def is_safe_for_external_lookup(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def analyze(parsed: ParsedEmail) -> AnalyzerResult:
    result = AnalyzerResult(stage="IP_ANALYSIS")
    values = {i.normalized_value for i in parsed.indicators if i.type == "IP"}
    for hop in parsed.hops:
        if hop.ip_address:
            values.add(hop.ip_address)
    data = []
    for value in values:
        kind = classify_ip(value)
        ev = evidence(EvidenceItem("IP", "email indicator", value, f"Observed IP classified as {kind}.",
                                   {"classification": kind, "safe_for_external_lookup": kind == "PUBLIC"}))
        result.evidence.append(ev)
        data.append({"ip": value, "classification": kind, "safe_for_external_lookup": kind == "PUBLIC"})
    result.data = {"ips": data}
    return result
