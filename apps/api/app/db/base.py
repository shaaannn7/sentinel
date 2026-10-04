"""Import all models for Alembic auto-discovery."""

from app.db.session import Base  # noqa
from app.models.investigation import Investigation  # noqa
from app.models.email_artifact import (  # noqa
    ArtifactAttachment,
    AuthenticationResult,
    EmailArtifact,
    EmailHeader,
    Indicator,
    ReceivedHop,
)
from app.models.ai_audit import AIAudit  # noqa
from app.models.analysis import Evidence, Finding, TimelineEvent, AnalysisStage  # noqa
