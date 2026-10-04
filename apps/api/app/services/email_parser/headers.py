"""Email header parsing helpers."""

import re
from typing import Optional
from email.utils import parseaddr, getaddresses

from app.services.email_parser.models import EmailHeader, AuthenticationResult, ReceivedHop


# Patterns for Received hop parsing
_RE_FROM_RE = re.compile(r"from\s+([^\s]+)", re.IGNORECASE)
_RE_BY_RE = re.compile(r"by\s+([^\s]+)", re.IGNORECASE)
_RE_IP_RE = re.compile(r"\[([0-9a-fA-F\.:]+)\]")
_RE_DATE_RE = re.compile(r";\s*(.+)$", re.IGNORECASE)

# Authentication-Results parsing
_AUTH_RESULTS_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_AUTH_DETAIL_RE = re.compile(r"\b(d|header\.d|smtp\.mailfrom|smtp\.helo|client-ip|policy|p)\s*=\s*([^\s;]+)", re.IGNORECASE)

# Email address regex
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def extract_addresses(value: str) -> list[str]:
    """Extract and normalize email addresses from header value."""
    if not value:
        return []
    addresses = getaddresses([value])
    return [addr for name, addr in addresses if addr]


def first_address(value: str) -> Optional[str]:
    """Return the first email address from a header value or None."""
    addrs = extract_addresses(value)
    return addrs[0] if addrs else None


def parse_received_hops(headers: list[EmailHeader]) -> list[ReceivedHop]:
    """Parse Received headers into ReceivedHop objects (in reverse order)."""
    received = [h.value for h in headers if h.name.lower() == "received"]
    hops = []
    for idx, value in enumerate(received):
        from_match = _RE_FROM_RE.search(value)
        by_match = _RE_BY_RE.search(value)
        ip_match = _RE_IP_RE.search(value)
        date_match = _RE_DATE_RE.search(value)

        from_host = from_match.group(1) if from_match else None
        by_host = by_match.group(1) if by_match else None
        ip_address = ip_match.group(1) if ip_match else None
        timestamp = date_match.group(1).strip() if date_match else None

        # Strip angle brackets from hosts
        if from_host:
            from_host = from_host.strip("<>")
        if by_host:
            by_host = by_host.strip("<>")

        hops.append(ReceivedHop(
            hop_number=idx + 1,
            from_host=from_host,
            by_host=by_host,
            ip_address=ip_address,
            timestamp=timestamp,
        ))
    return hops


def parse_authentication_results(auth_header: str) -> list[AuthenticationResult]:
    """Parse Authentication-Results header value into structured results."""
    if not auth_header:
        return []
    results = []
    # Match common patterns: spf=pass, dkim=pass, dmarc=pass
    details = {key.lower(): value.strip("()") for key, value in _AUTH_DETAIL_RE.findall(auth_header)}
    for protocol, result in _AUTH_RESULTS_RE.findall(auth_header):
        protocol_upper = protocol.upper()
        if protocol_upper in ("SPF", "DKIM", "DMARC"):
            results.append(AuthenticationResult(
                protocol=protocol_upper,
                result=result.lower(),
                details=details.copy(),
            ))
    return results


def get_header(headers: list[EmailHeader], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for h in headers:
        if h.name.lower() == name_lower:
            return h.value
    return None
