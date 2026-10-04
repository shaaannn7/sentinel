"""URL extraction utilities for email body content."""

import re
from urllib.parse import urlparse

# Match http(s) URLs, with optional protocol-relative or no-scheme host patterns
_URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:
        (?:https?://)
        |
        (?:www\.)
    )
    [^\s<>"'`]+
    """,
)

# Match bare domains in text
_DOMAIN_RE = re.compile(
    r"(?xi)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"
)


def normalize_url(url: str) -> str:
    """Normalize URL: strip trailing punctuation, lowercase scheme/host."""
    url = url.strip().rstrip(".,;:!?)>]'\"")
    parsed = urlparse(url)
    if parsed.scheme:
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        return f"{scheme}://{netloc}{parsed.path}" + (f"?{parsed.query}" if parsed.query else "")
    # No scheme (e.g., www.example.com)
    return url.lower()


def is_private_ip(ip: str) -> bool:
    """Quick check for private/reserved IPs that should not be looked up externally."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        return False


def extract_urls(text: str) -> list[str]:
    """Extract and normalize URLs from text. Returns unique list, preserves order."""
    if not text:
        return []
    found = _URL_RE.findall(text)
    # Deduplicate while preserving order
    seen = set()
    out = []
    for u in found:
        norm = normalize_url(u)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out
