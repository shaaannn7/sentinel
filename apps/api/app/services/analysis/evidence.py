"""Evidence identity and safe content helpers."""

import hashlib
import re
from .models import EvidenceItem


def safe_excerpt(text: str, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def evidence(item: EvidenceItem, namespace: str | None = None) -> EvidenceItem:
    raw = f"{namespace or ''}|{item.type}|{item.source}|{item.value}|{item.description}"
    item.id = f"EVD-{hashlib.sha256(raw.encode('utf-8', 'replace')).hexdigest()[:12].upper()}"
    return item


def unique_evidence(items: list[EvidenceItem], namespace: str | None = None) -> list[EvidenceItem]:
    out: list[EvidenceItem] = []
    seen: set[str] = set()
    for item in items:
        item = evidence(item, namespace=namespace)
        if item.id not in seen:
            seen.add(item.id)
            out.append(item)
    return out
