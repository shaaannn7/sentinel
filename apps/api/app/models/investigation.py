"""SQLAlchemy model for Investigation."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Float, DateTime, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Investigation(Base):
    """Investigation ORM model."""

    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    external_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=True)
    sender: Mapped[str] = mapped_column(String(256), nullable=True, index=True)
    verdict: Mapped[str] = mapped_column(String(32), default="unknown", index=True, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_level: Mapped[str] = mapped_column(String(16), default="LOW", nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=True)
    score_breakdown: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    score_version: Mapped[str] = mapped_column(String(32), default="2026.10", nullable=False)
    analysis_warnings: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    artifacts: Mapped[list["EmailArtifact"]] = relationship(
        "EmailArtifact", back_populates="investigation", cascade="all, delete-orphan"
    )
    indicators: Mapped[list["Indicator"]] = relationship(
        "Indicator", cascade="all, delete-orphan"
    )
    auth_results: Mapped[list["AuthenticationResult"]] = relationship(
        "AuthenticationResult", cascade="all, delete-orphan"
    )
    hops: Mapped[list["ReceivedHop"]] = relationship(
        "ReceivedHop", cascade="all, delete-orphan"
    )
    ai_audits: Mapped[list["AIAudit"]] = relationship(
        "AIAudit", cascade="all, delete-orphan"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        "Evidence", cascade="all, delete-orphan", order_by="Evidence.created_at"
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", cascade="all, delete-orphan", order_by="Finding.created_at"
    )
    timeline: Mapped[list["TimelineEvent"]] = relationship(
        "TimelineEvent", cascade="all, delete-orphan", order_by="TimelineEvent.timestamp"
    )
    analysis_stages: Mapped[list["AnalysisStage"]] = relationship(
        "AnalysisStage", cascade="all, delete-orphan", order_by="AnalysisStage.started_at"
    )
