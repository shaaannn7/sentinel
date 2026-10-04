"""SQLAlchemy models for email artifacts and extracted security entities."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class EmailArtifact(Base):
    """Email artifact model representing stored .eml file and parsed bodies."""

    __tablename__ = "email_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), default="message/rfc822")
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    plain_body: Mapped[str] = mapped_column(Text, nullable=True)
    html_body: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="artifacts")
    headers: Mapped[list["EmailHeader"]] = relationship("EmailHeader", cascade="all, delete-orphan")
    attachments: Mapped[list["ArtifactAttachment"]] = relationship(
        "ArtifactAttachment", cascade="all, delete-orphan"
    )


class EmailHeader(Base):
    """Extracted raw email header key-value pair."""

    __tablename__ = "email_headers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("email_artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class Indicator(Base):
    """Extracted indicator of compromise or interest."""

    __tablename__ = "indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # IP, DOMAIN, URL, EMAIL, HASH, ATTACHMENT
    raw_value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_value: Mapped[str] = mapped_column(Text, index=True, nullable=False)
    threat_verdict: Mapped[str] = mapped_column(String(32), default="unknown")
    reputation_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_private: Mapped[bool] = mapped_column(default=False, nullable=False)


class AuthenticationResult(Base):
    """Email authentication result (SPF, DKIM, DMARC)."""

    __tablename__ = "authentication_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)  # SPF, DKIM, DMARC
    result: Mapped[str] = mapped_column(String(32), nullable=False)    # pass, fail, neutral, none, softfail
    details: Mapped[dict] = mapped_column(JSON, nullable=True)


class ReceivedHop(Base):
    """Single hop in email header delivery chain."""

    __tablename__ = "received_hops"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hop_number: Mapped[int] = mapped_column(Integer, nullable=False)
    from_host: Mapped[str] = mapped_column(String(256), nullable=True)
    by_host: Mapped[str] = mapped_column(String(256), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    timestamp: Mapped[str] = mapped_column(String(128), nullable=True)


class ArtifactAttachment(Base):
    """Persisted metadata for an email attachment; content is never executed."""

    __tablename__ = "artifact_attachments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("email_artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    extension: Mapped[str] = mapped_column(String(32), nullable=True)
    is_suspicious: Mapped[bool] = mapped_column(default=False, nullable=False)
    magic_bytes: Mapped[str] = mapped_column(String(32), nullable=True)
