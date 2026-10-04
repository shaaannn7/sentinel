"""Strict schemas for AI enrichment outputs."""

from pydantic import BaseModel, Field


class Finding(BaseModel):
    evidence_ids: list[str] = Field(default_factory=list)
    statement: str = Field(min_length=1, max_length=2000)
    severity: str = "informational"


class HeaderAnalysis(BaseModel):
    assessment: str
    findings: list[Finding] = Field(default_factory=list)
    confidence: int = Field(ge=0, le=100)


class URLAnalysis(BaseModel):
    assessment: str
    findings: list[Finding] = Field(default_factory=list)
    confidence: int = Field(ge=0, le=100)


class ContentAnalysis(BaseModel):
    assessment: str
    signals: list[Finding] = Field(default_factory=list)
    confidence: int = Field(ge=0, le=100)


class Relationship(BaseModel):
    source: str
    target: str
    rationale: str = Field(min_length=1, max_length=1000)


class CorrelationAnalysis(BaseModel):
    assessment: str
    relationships: list[Relationship] = Field(default_factory=list)
    confidence: int = Field(ge=0, le=100)


class ReportAnalysis(BaseModel):
    summary: str
    recommendations: list[str] = Field(default_factory=list)
    confidence: int = Field(ge=0, le=100)


AI_OUTPUT_MODELS = {
    "header": HeaderAnalysis,
    "url": URLAnalysis,
    "content": ContentAnalysis,
    "correlation": CorrelationAnalysis,
    "report": ReportAnalysis,
}
