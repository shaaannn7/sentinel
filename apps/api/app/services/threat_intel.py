"""Threat intelligence service with comprehensive SSRF protection.

Provides a deterministic mock ThreatIntelProvider that returns the same
response for any given IP, Domain, or URL indicator. The response shape
mirrors a typical STIX/TAXII-style enrichment payload so callers can be
swapped to a real provider later without changing call sites.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlparse

IndicatorType = Literal["ip", "domain", "url"]

_PRIVATE_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".test",
    ".example",
    ".invalid",
    ".localhost",
    ".localdomain",
)


@dataclass
class ThreatIntelResult:
    """Normalized threat-intel lookup result."""

    indicator: str
    indicator_type: IndicatorType
    verdict: Literal["malicious", "suspicious", "benign", "unknown"]
    confidence: int  # 0-100
    source: str
    first_seen: str
    last_seen: str
    tags: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_safe_ip(ip: str) -> bool:
    """Return true only for globally routable, non-private, non-loopback IP addresses.

    Guards against:
    - 127.0.0.0/8 (loopback)
    - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (private RFC 1918)
    - 169.254.0.0/16 (link-local, cloud metadata service like AWS/GCP 169.254.169.254)
    - 0.0.0.0/8 (unspecified)
    - IPv6 loopback (::1), link-local (fe80::/10), unique local (fc00::/7)
    - IPv4-mapped IPv6 (::ffff:127.0.0.1)
    """
    clean_ip = ip.strip()
    try:
        address = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False

    # Check for IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    if address.is_private or address.is_loopback or address.is_reserved or address.is_link_local:
        return False
    if address.is_multicast or address.is_unspecified:
        return False

    # Explicit cloud metadata check (169.254.169.254, 100.100.100.200)
    str_addr = str(address)
    if str_addr in {"169.254.169.254", "100.100.100.200"}:
        return False

    return address.is_global


def is_safe_domain(domain: str) -> bool:
    """Return true only for safe, public domains that cannot trigger SSRF.

    Blocks:
    - localhost, loopback variations
    - private TLDs (.local, .internal, .lan, etc.)
    - numeric / decimal / hex IP representations disguised as domains
    """
    if not domain or not isinstance(domain, str):
        return False

    clean = domain.strip().lower().rstrip(".")
    if not clean:
        return False

    _BLOCKED_HOSTNAMES = {"localhost", "instance-data", "metadata", "metadata.google.internal"}
    if clean in _BLOCKED_HOSTNAMES or clean.startswith("localhost.") or clean.endswith(_PRIVATE_DOMAIN_SUFFIXES):
        return False

    # Disallow IP addresses passed as domain strings if they resolve to non-global
    try:
        # Check if it parses as an IP address directly
        ipaddress.ip_address(clean)
        return is_safe_ip(clean)
    except ValueError:
        pass

    # Check for decimal/hex/octal encoded IPv4 notations (e.g., 2130706433 or 0x7f000001)
    if re.match(r"^0x[0-9a-f]+$", clean) or (clean.isdigit() and len(clean) >= 7):
        try:
            val = int(clean, 0)
            return is_safe_ip(str(ipaddress.IPv4Address(val)))
        except (ValueError, OverflowError):
            return False

    # Ensure domain contains at least one dot and valid characters
    if "." not in clean:
        return False

    return True


def is_safe_url(url: str) -> bool:
    """Return true only for external HTTP/HTTPS URLs targeting globally routable endpoints.

    Rejects:
    - javascript:, data:, file:, gopher:, dict:, ftp: schemes
    - URLs containing credentials (e.g. http://user:pass@host/)
    - URLs pointing to private/internal domains or non-global IPs
    """
    if not url or not isinstance(url, str):
        return False

    clean_url = url.strip()
    try:
        parsed = urlparse(clean_url)
    except Exception:
        return False

    if parsed.scheme.lower() not in {"http", "https"}:
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Check if host is a raw IP or domain name
    try:
        ipaddress.ip_address(hostname)
        return is_safe_ip(hostname)
    except ValueError:
        return is_safe_domain(hostname)


# Backwards compatibility alias
is_safe_for_external_lookup = is_safe_ip


class ThreatIntelProvider:
    """Deterministic mock threat-intel provider with strict SSRF defense."""

    SOURCE_NAME = "mock-threat-intel"
    _KNOWN_CATEGORIES = (
        "malware",
        "phishing",
        "c2",
        "ransomware",
        "scanner",
        "bruteforce",
        "spam",
        "tor-exit",
    )

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        if not is_safe_ip(ip):
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ip",
                verdict="unknown",
                confidence=0,
                source="safety-gate",
                first_seen="",
                last_seen="",
                tags=["private-or-reserved", "not-queried"],
            )
        return self._lookup(ip, "ip")

    def lookup_domain(self, domain: str) -> ThreatIntelResult:
        if not is_safe_domain(domain):
            return ThreatIntelResult(
                indicator=domain,
                indicator_type="domain",
                verdict="unknown",
                confidence=0,
                source="safety-gate",
                first_seen="",
                last_seen="",
                tags=["internal-or-reserved", "not-queried"],
            )
        return self._lookup(domain, "domain")

    def lookup_url(self, url: str) -> ThreatIntelResult:
        if not is_safe_url(url):
            return ThreatIntelResult(
                indicator=url,
                indicator_type="url",
                verdict="unknown",
                confidence=0,
                source="safety-gate",
                first_seen="",
                last_seen="",
                tags=["unsafe-or-private-target", "not-queried"],
            )
        return self._lookup(url, "url")

    def lookup(self, indicator: str, indicator_type: IndicatorType) -> ThreatIntelResult:
        """Lookup a generic indicator by explicit type."""
        if indicator_type == "ip":
            return self.lookup_ip(indicator)
        if indicator_type == "domain":
            return self.lookup_domain(indicator)
        if indicator_type == "url":
            return self.lookup_url(indicator)
        return self._lookup(indicator, indicator_type)

    def _lookup(self, indicator: str, indicator_type: IndicatorType) -> ThreatIntelResult:
        if not indicator:
            raise ValueError("indicator must be a non-empty string")

        normalized = self._normalize(indicator, indicator_type)
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        verdict_bucket = int(digest[:2], 16)
        if verdict_bucket < 32:
            verdict: Literal["malicious", "suspicious", "benign", "unknown"] = "malicious"
        elif verdict_bucket < 96:
            verdict = "suspicious"
        elif verdict_bucket < 224:
            verdict = "benign"
        else:
            verdict = "unknown"

        confidence = (int(digest[2:4], 16) % 71) + 20  # 20-90

        cat_count = (int(digest[4:6], 16) % 3) + 1
        categories = [
            self._KNOWN_CATEGORIES[(int(digest[i * 2 : i * 2 + 2], 16)) % len(self._KNOWN_CATEGORIES)]
            for i in range(cat_count)
        ]

        first_seen = self._timestamp_from_digest(digest[6:14], base_year=2018)
        last_seen = self._timestamp_from_digest(digest[14:22], base_year=2023)

        tags = ["mock", verdict, indicator_type] + categories

        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            confidence=confidence,
            source=self.SOURCE_NAME,
            first_seen=first_seen,
            last_seen=last_seen,
            tags=sorted(set(tags)),
            categories=sorted(set(categories)),
            references=[
                f"https://threat-intel.local/{indicator_type}/{digest[:12]}",
            ],
            raw={
                "sha256": digest,
                "queried_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    @staticmethod
    def _normalize(indicator: str, indicator_type: IndicatorType) -> str:
        value = indicator.strip().lower()
        if indicator_type == "url":
            return value
        if indicator_type == "domain":
            return value.rstrip(".")
        return value

    @staticmethod
    def _timestamp_from_digest(hex_slice: str, base_year: int) -> str:
        """Turn an 8-hex-char slice into a stable ISO-8601 UTC timestamp."""
        days_offset = int(hex_slice, 16) % 3650
        seconds_offset = int(hashlib.md5(hex_slice.encode("utf-8")).hexdigest()[:8], 16) % 86_400
        ts = datetime(base_year, 1, 1, tzinfo=timezone.utc).timestamp() + (
            days_offset * 86_400 + seconds_offset
        )
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


__all__ = [
    "ThreatIntelProvider",
    "ThreatIntelResult",
    "is_safe_ip",
    "is_safe_domain",
    "is_safe_url",
    "is_safe_for_external_lookup",
]
