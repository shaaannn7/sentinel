"""Synthetic coverage for the evidence-first deterministic analysis engine."""

from email.message import EmailMessage

from app.services.email_parser import parse_email
from app.services.analysis.orchestrator import run
from app.services.analysis.evidence import unique_evidence
from app.services.analysis.models import EvidenceItem
from app.services.analyzers.ips.analyzer import classify_ip, is_safe_for_external_lookup
from app.services.analyzers.urls.analyzer import normalize
from app.services.threat_intel import ThreatIntelProvider
import app.services.analysis.orchestrator as orchestrator


def make_email(body: str, *, from_addr="billing@paypal.com", reply_to=None, auth=None, attachment=None) -> bytes:
    message = EmailMessage()
    message["From"] = from_addr
    message["To"] = "analyst@example.net"
    message["Subject"] = "Notice"
    if reply_to:
        message["Reply-To"] = reply_to
    if auth:
        message["Authentication-Results"] = auth
    message["Date"] = "Tue, 01 Jan 2024 00:00:00 +0000"
    message.set_content(body)
    if attachment:
        filename, data, maintype, subtype = attachment
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return message.as_bytes()


def test_benign_email_is_low_and_findings_are_evidence_backed():
    result = run(parse_email(make_email("Hello team, the meeting is at 10:00.", auth="mx; spf=pass dkim=pass dmarc=pass")))
    assert result["score"].verdict == "BENIGN"
    assert result["score"].score < 25
    assert all(f.evidence for f in result["findings"])


def test_phishing_like_signals_combine_conservatively():
    parsed = parse_email(make_email(
        "URGENT: verify your password immediately. Your account will be suspended within 24 hours. "
        "Visit https://paypa1-example.test/login",
        from_addr="notice@paypa1-example.test", reply_to="help@other.test",
        auth="mx; spf=fail dkim=fail dmarc=fail",
    ))
    result = run(parsed)
    titles = {finding.title for finding in result["findings"]}
    assert "Potential lookalike domain" in titles
    assert "SPF authentication failed" in titles
    assert result["score"].verdict in {"PHISHING", "MALICIOUS"}
    assert result["score"].breakdown["AUTHENTICATION"] == 25


def test_attachment_double_extension_is_static_only():
    parsed = parse_email(make_email("See invoice.", attachment=("invoice.pdf.exe", b"MZ\x90", "application", "octet-stream")))
    result = run(parsed)
    assert any(f.category == "ATTACHMENT" for f in result["findings"])
    assert any(item.type == "ATTACHMENT" and item.metadata.get("sha256") for item in result["evidence"])


def test_ip_safety_covers_private_loopback_ipv6_and_invalid():
    assert classify_ip("10.0.0.1") == "PRIVATE"
    assert classify_ip("127.0.0.1") == "LOOPBACK"
    assert classify_ip("::1") == "LOOPBACK"
    assert classify_ip("not-an-ip") == "INVALID"
    assert is_safe_for_external_lookup("198.51.100.10") is False  # reserved TEST-NET
    assert is_safe_for_external_lookup("8.8.8.8") is True


def test_url_normalization_preserves_components_without_fetching():
    item = normalize("HTTPS://Example.test:8443/path?q=1#frag")
    assert item["hostname"] == "example.test"
    assert item["port"] == 8443
    assert item["normalized_url"] == "https://example.test:8443/path?q=1#frag"


def test_threat_intel_boundary_does_not_query_non_global_ips():
    result = ThreatIntelProvider().lookup_ip("192.168.1.10")
    assert result.source == "safety-gate"
    assert result.verdict == "unknown"
    assert "not-queried" in result.tags


def test_orchestrator_continues_when_one_stage_fails(monkeypatch):
    def broken(_parsed):
        raise RuntimeError("synthetic URL failure")
    monkeypatch.setattr(orchestrator, "url_analyze", broken)
    result = orchestrator.run(parse_email(make_email("Hello.", auth="mx; spf=pass")))
    assert any(not stage.success for stage in result["results"])
    assert result["score"].verdict in {"BENIGN", "INCONCLUSIVE"}
    assert "synthetic URL failure" in result["errors"]


def test_evidence_ids_are_scoped_per_investigation():
    first = unique_evidence(
        [EvidenceItem(type="HEADER", source="Subject", value="Notice", description="Observed subject")],
        namespace="investigation-a",
    )[0]
    second = unique_evidence(
        [EvidenceItem(type="HEADER", source="Subject", value="Notice", description="Observed subject")],
        namespace="investigation-b",
    )[0]
    assert first.id != second.id
