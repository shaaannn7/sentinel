"""Forensic timeline builder, retaining artifact versus analysis time."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from app.services.analysis.models import TimelineItem, AnalyzerResult
from app.services.email_parser.models import ParsedEmail


def _timestamp(value):
    if value and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def build(parsed: ParsedEmail, results: list[AnalyzerResult], completed_at: datetime | None = None) -> list[TimelineItem]:
    items: list[TimelineItem] = []
    artifact_time = None
    if parsed.date:
        try:
            artifact_time = _timestamp(parsedate_to_datetime(parsed.date))
            items.append(TimelineItem(artifact_time, "artifact", "Email Date header",
                                      "Date observed in the submitted artifact.", "Date", "artifact"))
        except (TypeError, ValueError, OverflowError):
            pass
    for hop in parsed.hops:
        timestamp = None
        if hop.timestamp:
            try: timestamp = _timestamp(parsedate_to_datetime(hop.timestamp))
            except (TypeError, ValueError, OverflowError): pass
        items.append(TimelineItem(timestamp, "mail_hop", f"Received hop {hop.hop_number}",
                                  f"Observed {hop.from_host or 'unknown'} → {hop.by_host or 'unknown'} ({hop.ip_address or 'no IP'}).",
                                  "Received", "artifact"))
    for auth in parsed.auth_results:
        items.append(TimelineItem(artifact_time, "authentication", f"{auth.protocol.upper()} result observed",
                                  f"{auth.protocol.upper()} authentication was reported as {auth.result.upper()}.",
                                  "Authentication-Results", "artifact"))
    now = completed_at or datetime.now(timezone.utc)
    for result in results:
        items.append(TimelineItem(now, "analysis", f"{result.stage.replace('_', ' ').title()} completed",
                                  f"{len(result.evidence)} evidence item(s) and {len(result.findings)} finding(s) produced.",
                                  result.stage, "analysis"))
    items.append(TimelineItem(now, "analysis", "Deterministic analysis completed",
                              "All available deterministic stages completed; individual warnings are retained.", "orchestrator", "analysis"))
    return sorted(items, key=lambda item: item.timestamp or datetime.min.replace(tzinfo=timezone.utc))
