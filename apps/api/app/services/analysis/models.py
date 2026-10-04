"""Shared contracts for deterministic analyzers."""

from dataclasses import dataclass, field
from typing import Any
from datetime import datetime


@dataclass
class EvidenceItem:
    type: str
    source: str
    value: str
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""


@dataclass
class FindingDraft:
    severity: str
    category: str
    title: str
    description: str
    evidence: list[EvidenceItem]
    source: str
    points: int = 0
    confidence: str = "MEDIUM"


@dataclass
class AnalyzerResult:
    stage: str
    success: bool = True
    evidence: list[EvidenceItem] = field(default_factory=list)
    findings: list[FindingDraft] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreResult:
    score: float
    level: str
    verdict: str
    confidence: str
    completeness: float
    breakdown: dict[str, float]


@dataclass
class TimelineItem:
    timestamp: datetime | None
    event_type: str
    title: str
    description: str
    source: str
    time_kind: str = "analysis"
