"""Threat intelligence service.

Provides a deterministic mock ThreatIntelProvider that returns the same
response for any given IP, Domain, or URL indicator. The response shape
mirrors a typical STIX/TAXII-style enrichment payload so callers can be
swapped to a real provider later without changing call sites.
"""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

IndicatorType = Literal["ip", "domain", "url"]


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


class ThreatIntelProvider:
    """Deterministic mock threat-intel provider.

    Given the same indicator, the provider always returns the same result,
    derived from a stable hash of the input. This makes the service safe to
    use in tests and local development where a real provider is unavailable.
    """

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
        if not is_safe_for_external_lookup(ip):
            return ThreatIntelResult(
                indicator=ip, indicator_type="ip", verdict="unknown", confidence=0,
                source="safety-gate", first_seen="", last_seen="",
                tags=["private-or-reserved", "not-queried"],
            )
        return self._lookup(ip, "ip")

    def lookup_domain(self, domain: str) -> ThreatIntelResult:
        return self._lookup(domain, "domain")

    def lookup_url(self, url: str) -> ThreatIntelResult:
        return self._lookup(url, "url")

    def lookup(self, indicator: str, indicator_type: IndicatorType) -> ThreatIntelResult:
        """Lookup a generic indicator by explicit type."""
        return self._lookup(indicator, indicator_type)

    def _lookup(self, indicator: str, indicator_type: IndicatorType) -> ThreatIntelResult:
        if not indicator:
            raise ValueError("indicator must be a non-empty string")

        normalized = self._normalize(indicator, indicator_type)
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        # Map the first byte of the digest onto a verdict bucket. This keeps
        # the output deterministic but spreads inputs across all buckets.
        verdict_bucket = int(digest[:2], 16)
        if verdict_bucket < 32:
            verdict: Literal["malicious", "suspicious", "benign", "unknown"] = "malicious"
        elif verdict_bucket < 96:
            verdict = "suspicious"
        elif verdict_bucket < 224:
            verdict = "benign"
        else:
            verdict = "unknown"

        # Confidence is derived from the next two bytes so it is stable per
        # indicator but independent of the verdict bucket.
        confidence = (int(digest[2:4], 16) % 71) + 20  # 20-90

        # Pick 1-3 categories deterministically.
        cat_count = (int(digest[4:6], 16) % 3) + 1
        categories = [
            self._KNOWN_CATEGORIES[(int(digest[i * 2 : i * 2 + 2], 16)) % len(self._KNOWN_CATEGORIES)]
            for i in range(cat_count)
        ]

        # Derive a stable timestamp from the hash so first/last_seen are
        # deterministic for a given indicator but vary across indicators.
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
        days_offset = int(hex_slice, 16) % 3650  # ~10 years
        seconds_offset = int(hashlib.md5(hex_slice.encode("utf-8")).hexdigest()[:8], 16) % 86_400
        ts = datetime(base_year, 1, 1, tzinfo=timezone.utc).timestamp() + (
            days_offset * 86_400 + seconds_offset
        )
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


__all__ = ["ThreatIntelProvider", "ThreatIntelResult", "is_safe_for_external_lookup"]


def is_safe_for_external_lookup(ip: str) -> bool:
    """Return true only for globally routable IPs.

    This guard is intentionally centralized here as the provider boundary:
    private, loopback, link-local, multicast, reserved, and invalid addresses
    must never be sent to an external enrichment service.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_global
