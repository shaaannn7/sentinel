"""
SENTINEL Brain — Threat Memory Store
=====================================
Lightweight persistent memory that:
  1. Records sender + domain fingerprints from past investigations
  2. Returns a recall boost when a new email matches a known-threat pattern
  3. Learns from user feedback (mark investigation as confirmed threat/benign)

Storage: JSON file (apps/api/app/brain/memory/threat_memory.json)
No external dependencies — stdlib only + numpy.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

MEMORY_PATH = Path(__file__).resolve().parent / "threat_memory.json"

_DEFAULT_MEMORY: Dict[str, Any] = {
    "version": 1,
    "created_at": "",
    "total_records": 0,
    "threat_senders": {},      # fingerprint -> {count, last_seen, verdict}
    "threat_domains": {},      # domain -> {count, last_seen, verdict}
    "threat_url_patterns": {}, # pattern hash -> {count, last_seen}
    "confirmed_safe": set(),   # investigation IDs confirmed benign by user
    "confirmed_threat": set(), # investigation IDs confirmed threat by user
}


class MemoryStore:
    """Persistent threat memory with recall and learning."""

    _instance: Optional["MemoryStore"] = None

    def __init__(self, path: Path = MEMORY_PATH) -> None:
        self._path = path
        self._data: Dict[str, Any] = {}
        self._load()

    @classmethod
    def get(cls) -> "MemoryStore":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path) as f:
                    raw = json.load(f)
                # sets are serialised as lists
                raw["confirmed_safe"]   = set(raw.get("confirmed_safe", []))
                raw["confirmed_threat"] = set(raw.get("confirmed_threat", []))
                self._data = raw
                logger.debug("memory.store: loaded %d threat records", raw.get("total_records", 0))
                return
            except Exception as exc:
                logger.warning("memory.store: load failed (%s) — starting fresh", exc)
        self._data = dict(_DEFAULT_MEMORY)
        self._data["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._data["confirmed_safe"]   = set()
        self._data["confirmed_threat"] = set()

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        serialisable = {k: (list(v) if isinstance(v, set) else v) for k, v in self._data.items()}
        with open(self._path, "w") as f:
            json.dump(serialisable, f, indent=2)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        parsed_email: Any,
        verdict: str,
        investigation_id: Optional[str] = None,
    ) -> None:
        """
        Persist sender + domain + URL fingerprints for this investigation.
        Called by brain.orchestrator after every analysis.
        """
        if verdict in ("BENIGN",):
            # Don't pollute threat memory with benign emails
            return

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Sender fingerprint
        from_raw = getattr(parsed_email, "from_addr", "") or ""
        m = re.search(r"<([^>]+)>", from_raw)
        addr = m.group(1).strip().lower() if m else from_raw.strip().lower()
        fp = _fingerprint(addr)
        entry = self._data["threat_senders"].get(fp, {"count": 0, "last_seen": "", "verdict": verdict, "addr": addr})
        entry["count"] += 1
        entry["last_seen"] = ts
        entry["verdict"] = verdict
        self._data["threat_senders"][fp] = entry

        # Domain
        parts = addr.rsplit("@", 1)
        if len(parts) == 2:
            domain = parts[1]
            d_entry = self._data["threat_domains"].get(domain, {"count": 0, "last_seen": "", "verdict": verdict})
            d_entry["count"] += 1
            d_entry["last_seen"] = ts
            d_entry["verdict"] = verdict
            self._data["threat_domains"][domain] = d_entry

        # URL patterns
        indicators = getattr(parsed_email, "indicators", []) or []
        for ind in indicators:
            if getattr(ind, "type", "") == "URL":
                raw_url = getattr(ind, "normalized_value", "") or getattr(ind, "raw_value", "") or ""
                # Store only the netloc+path prefix, not query tokens
                url_key = _url_pattern_key(raw_url)
                if url_key:
                    u_entry = self._data["threat_url_patterns"].get(url_key, {"count": 0, "last_seen": ""})
                    u_entry["count"] += 1
                    u_entry["last_seen"] = ts
                    self._data["threat_url_patterns"][url_key] = u_entry

        self._data["total_records"] = (
            len(self._data["threat_senders"]) +
            len(self._data["threat_domains"]) +
            len(self._data["threat_url_patterns"])
        )
        self.save()

    # ------------------------------------------------------------------
    # Recall
    # ------------------------------------------------------------------

    def threat_boost(self, parsed_email: Any) -> float:
        """
        Return a boost probability in [0, 1] based on pattern recall.
        0.0 = no memory hit, 1.0 = definite known threat pattern.
        """
        score = 0.0

        from_raw = getattr(parsed_email, "from_addr", "") or ""
        m = re.search(r"<([^>]+)>", from_raw)
        addr = m.group(1).strip().lower() if m else from_raw.strip().lower()
        fp = _fingerprint(addr)

        # Exact sender match
        if fp in self._data["threat_senders"]:
            count = self._data["threat_senders"][fp]["count"]
            score = min(1.0, 0.6 + count * 0.05)

        # Domain match (softer)
        if score < 0.6:
            parts = addr.rsplit("@", 1)
            if len(parts) == 2:
                domain = parts[1]
                if domain in self._data["threat_domains"]:
                    count = self._data["threat_domains"][domain]["count"]
                    score = max(score, min(0.8, 0.3 + count * 0.04))

        # URL pattern match
        indicators = getattr(parsed_email, "indicators", []) or []
        for ind in indicators:
            if getattr(ind, "type", "") == "URL":
                raw_url = getattr(ind, "normalized_value", "") or getattr(ind, "raw_value", "") or ""
                url_key = _url_pattern_key(raw_url)
                if url_key and url_key in self._data["threat_url_patterns"]:
                    count = self._data["threat_url_patterns"][url_key]["count"]
                    score = max(score, min(0.9, 0.5 + count * 0.04))

        return float(score)

    # ------------------------------------------------------------------
    # Feedback
    # ------------------------------------------------------------------

    def confirm_threat(self, investigation_id: str, parsed_email: Any, verdict: str = "PHISHING") -> None:
        """User confirms this investigation is a real threat — strengthen memory."""
        self._data["confirmed_threat"].add(investigation_id)
        self.record(parsed_email, verdict, investigation_id)

    def confirm_safe(self, investigation_id: str) -> None:
        """User confirms this investigation is benign — do not penalise future matches."""
        self._data["confirmed_safe"].add(investigation_id)
        self.save()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        return {
            "total_records":     self._data.get("total_records", 0),
            "threat_senders":    len(self._data.get("threat_senders", {})),
            "threat_domains":    len(self._data.get("threat_domains", {})),
            "threat_url_patterns": len(self._data.get("threat_url_patterns", {})),
            "confirmed_safe":    len(self._data.get("confirmed_safe", set())),
            "confirmed_threat":  len(self._data.get("confirmed_threat", set())),
            "created_at":        self._data.get("created_at", ""),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fingerprint(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:16]


def _url_pattern_key(url: str) -> str:
    """Extract netloc+first-path-segment as a stable pattern key."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = (p.hostname or "").lower()
        path_seg = p.path.split("/")[1] if p.path.startswith("/") else ""
        key = f"{host}/{path_seg}" if path_seg else host
        return _fingerprint(key) if key else ""
    except Exception:
        return ""
