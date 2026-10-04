"""Received-header forensics and conservative anomaly detection."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from app.services.email_parser.models import ParsedEmail
from app.services.analysis.models import AnalyzerResult, EvidenceItem, FindingDraft
from app.services.analysis.evidence import evidence


def analyze(parsed: ParsedEmail) -> AnalyzerResult:
    result = AnalyzerResult(stage="HEADER_ANALYSIS")
    parsed_times: list[datetime] = []
    for hop in parsed.hops:
        value = " | ".join(filter(None, [hop.from_host, hop.by_host, hop.ip_address, hop.timestamp]))
        ev = evidence(EvidenceItem("HEADER", "Received", value, f"Observed mail path hop {hop.hop_number}.",
                                   {"hop_number": hop.hop_number, "timestamp": hop.timestamp}))
        result.evidence.append(ev)
        if hop.timestamp:
            try:
                dt = parsedate_to_datetime(hop.timestamp)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
                parsed_times.append(dt)
            except (TypeError, ValueError, OverflowError):
                result.findings.append(FindingDraft("LOW", "HEADER", "Malformed Received timestamp",
                    "A Received header timestamp could not be parsed; the raw value is preserved for review.",
                    [ev], "headers", 2, "HIGH"))
    # Header order is preserved as observed. A decreasing timestamp sequence is an observation only.
    if len(parsed_times) > 1 and any(a < b for a, b in zip(parsed_times, parsed_times[1:])):
        result.findings.append(FindingDraft("LOW", "HEADER", "Received timestamp ordering anomaly",
            "Two observed Received timestamps appear out of chronological order. This is an observation, not attribution.",
            result.evidence, "headers", 3))
    result.data = {"hop_count": len(parsed.hops), "received_hops": [h.model_dump() for h in parsed.hops]}
    return result
