"""Pydantic schemas for Investigation API endpoints."""

from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict


class IndicatorSchema(BaseModel):
    id: str
    type: str
    raw_value: str
    normalized_value: str
    threat_verdict: str
    reputation_score: float
    is_private: bool = False

    model_config = ConfigDict(from_attributes=True)


class AuthResultSchema(BaseModel):
    id: str
    protocol: str
    result: str
    details: Optional[dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class ReceivedHopSchema(BaseModel):
    id: str
    hop_number: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EmailHeaderSchema(BaseModel):
    id: str
    name: str
    value: str

    model_config = ConfigDict(from_attributes=True)


class AttachmentSchema(BaseModel):
    id: str
    filename: str
    mime_type: str
    size: int
    sha256: str
    extension: Optional[str] = None
    is_suspicious: bool = False
    magic_bytes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EvidenceSchema(BaseModel):
    id: str
    type: str
    source: str
    value: str
    description: str
    metadata_json: dict[str, Any] = {}
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class FindingSchema(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    description: str
    confidence: str
    evidence_refs: list[str] = []
    source: str
    points: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class TimelineEventSchema(BaseModel):
    id: str
    timestamp: Optional[datetime] = None
    event_type: str
    title: str
    description: str
    source: str
    time_kind: str
    model_config = ConfigDict(from_attributes=True)


class AnalysisStageSchema(BaseModel):
    stage: str
    status: str
    error: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class AIAuditSchema(BaseModel):
    id: str
    agent: str
    model: str
    prompt_version: str
    input_evidence_ids: list[str]
    output: Optional[dict[str, Any]] = None
    validation_status: str
    attempt_count: int
    error: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class EmailArtifactSchema(BaseModel):
    id: str
    filename: str
    file_size: int
    mime_type: str
    sha256: str
    plain_body: Optional[str] = None
    html_body: Optional[str] = None
    headers: list[EmailHeaderSchema] = []
    attachments: list[AttachmentSchema] = []

    model_config = ConfigDict(from_attributes=True)


class InvestigationResponse(BaseModel):
    id: str
    external_id: str
    status: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    verdict: str
    risk_score: float
    confidence: float
    confidence_level: str = "LOW"
    summary: Optional[str] = None
    score_breakdown: dict[str, float] = {}
    analysis_warnings: list[str] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InvestigationDetailResponse(InvestigationResponse):
    artifacts: list[EmailArtifactSchema] = []
    indicators: list[IndicatorSchema] = []
    auth_results: list[AuthResultSchema] = []
    hops: list[ReceivedHopSchema] = []
    evidence: list[EvidenceSchema] = []
    findings: list[FindingSchema] = []
    timeline: list[TimelineEventSchema] = []
    analysis_stages: list[AnalysisStageSchema] = []
    ai_audits: list[AIAuditSchema] = []


class InvestigationListResponse(BaseModel):
    total: int
    items: list[InvestigationResponse]
