"""Investigation API endpoints."""

import uuid
import os
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.config import settings
from app.models.investigation import Investigation
from app.models.ai_audit import AIAudit
from app.models.email_artifact import (
    EmailArtifact,
    EmailHeader as DBHeader,
    Indicator as DBIndicator,
    AuthenticationResult as DBAuthResult,
    ReceivedHop as DBHop,
    ArtifactAttachment as DBAttachment,
)
from app.schemas.investigation import (
    InvestigationResponse,
    InvestigationDetailResponse,
    InvestigationListResponse,
)
from app.services.email_parser import parse_email
from app.services.analysis.orchestrator import run as run_deterministic_analysis
from app.core.auth import require_api_key
from app.services.ai_investigation import run_investigation_ai
from app.services.threat_intel import ThreatIntelProvider

router = APIRouter(
    prefix="/api/v1/investigations",
    tags=["investigations"],
    dependencies=[Depends(require_api_key)],
)


def get_investigation_or_404(db: Session, investigation_id: str) -> Investigation:
    """Get investigation by id or external_id, raise 404 if not found."""
    inv = db.query(Investigation).filter(
        (Investigation.id == investigation_id) | (Investigation.external_id == investigation_id.upper())
    ).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv
@router.post("", response_model=InvestigationDetailResponse)
async def create_investigation(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload a .eml file, parse it deterministically, store the artifact, and persist the investigation."""
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    max_size = int(os.getenv("MAX_UPLOAD_SIZE", str(settings.MAX_UPLOAD_SIZE)))
    chunks: list[bytes] = []
    total_size = 0
    while chunk := await file.read(1024 * 1024):
        total_size += len(chunk)
        if total_size > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"File size exceeds max allowed {max_size} bytes",
            )
        chunks.append(chunk)
    contents = b"".join(chunks)
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    # 1. Safely store artifact and get SHA-256 + path
    try:
        # Resolve the application-level storage at request time so deployments/tests
        # can replace the configured backend without rebuilding the router.
        from app import main as app_main
        file_path, sha256, file_size = app_main.storage.store(file.filename, contents)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store artifact: {e}")

    # 2. Parse email deterministically
    try:
        parsed = parse_email(contents)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse email artifact: {e}")

    # 3. Create database records
    inv_id = str(uuid.uuid4())
    ext_id = f"INV-{sha256[:8].upper()}"

    investigation = Investigation(
        id=inv_id,
        external_id=ext_id,
        status="EXTRACTING",
        subject=parsed.subject,
        sender=parsed.from_addr,
        verdict="inconclusive",
        risk_score=0.0,
        confidence=0.0,
        summary="Deterministic analysis queued.",
    )
    db.add(investigation)

    artifact = EmailArtifact(
        investigation_id=inv_id,
        filename=file.filename,
        file_path=file_path,
        file_size=file_size,
        mime_type="message/rfc822",
        sha256=sha256,
        plain_body=parsed.plain_body,
        html_body=parsed.html_body,
    )
    db.add(artifact)
    db.flush()

    # Headers
    for h in parsed.headers[:100]:  # Cap headers to prevent bloating
        db.add(DBHeader(artifact_id=artifact.id, name=h.name, value=h.value))
    for attachment in parsed.attachments:
        db.add(DBAttachment(
            artifact_id=artifact.id, filename=attachment.filename, mime_type=attachment.mime_type,
            size=attachment.size, sha256=attachment.sha256, extension=attachment.extension,
            is_suspicious=attachment.is_suspicious, magic_bytes=attachment.magic_bytes,
        ))

    # Indicators
    for ind in parsed.indicators:
        db.add(DBIndicator(
            investigation_id=inv_id,
            type=ind.type,
            raw_value=ind.raw_value,
            normalized_value=ind.normalized_value,
            threat_verdict="unknown",
            reputation_score=0.0,
            is_private=ind.is_private,
        ))

    # Auth results
    for auth in parsed.auth_results:
        db.add(DBAuthResult(
            investigation_id=inv_id,
            protocol=auth.protocol,
            result=auth.result,
            details=auth.details,
        ))

    # Hops
    for hop in parsed.hops:
        db.add(DBHop(
            investigation_id=inv_id,
            hop_number=hop.hop_number,
            from_host=hop.from_host,
            by_host=hop.by_host,
            ip_address=hop.ip_address,
            timestamp=hop.timestamp,
        ))

    # Phase 2 is deterministic and bounded. It reuses this parsed representation;
    # no analyzer reparses the raw artifact and the AI layer is not invoked.
    run_deterministic_analysis(parsed, investigation_id=inv_id, db=db)
    _enrich_investigation_indicators(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


@router.post("/{investigation_id}/analyze", response_model=InvestigationDetailResponse)
async def analyze_investigation(investigation_id: str, db: Session = Depends(get_db)):
    """Run (or rerun) deterministic analysis against the stored parsed artifact."""
    investigation = get_investigation_or_404(db, investigation_id)
    if not investigation.artifacts:
        raise HTTPException(status_code=409, detail="No email artifact available")
    artifact = investigation.artifacts[0]
    try:
        with open(artifact.file_path, "rb") as handle:
            parsed = parse_email(handle.read())
        run_deterministic_analysis(parsed, investigation_id=investigation.id, db=db)
        _enrich_investigation_indicators(investigation)
        db.commit()
        db.refresh(investigation)
        return investigation
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Artifact unavailable: {exc}")


@router.post("/{investigation_id}/ai-analysis", response_model=InvestigationDetailResponse)
async def analyze_investigation_with_ai(investigation_id: str, db: Session = Depends(get_db)):
    """Run optional bounded AI enrichment; deterministic results remain authoritative."""
    investigation = get_investigation_or_404(db, investigation_id)
    run_investigation_ai(db, investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


@router.get("/{investigation_id}/ai-reports")
async def get_ai_reports(investigation_id: str, db: Session = Depends(get_db)):
    """Return validated AI audit outputs without exposing raw model text."""
    investigation = get_investigation_or_404(db, investigation_id)
    audits = db.query(AIAudit).filter(
        AIAudit.investigation_id == investigation.id,
        AIAudit.output.is_not(None),
    ).order_by(AIAudit.created_at.asc()).all()
    return {"investigation_id": investigation.id, "reports": audits}


@router.post("/{investigation_id}/enrich")
async def enrich_indicators(investigation_id: str, db: Session = Depends(get_db)):
    """Enrich globally routable indicators using the configured provider boundary."""
    investigation = get_investigation_or_404(db, investigation_id)
    results = _enrich_investigation_indicators(investigation)
    db.commit()
    return {"investigation_id": investigation.id, "results": results}


def _enrich_investigation_indicators(investigation: Investigation) -> list[dict]:
    """Apply the same normalized threat-intel contract to API and CLI flows."""
    provider = ThreatIntelProvider()
    results = []
    for indicator in investigation.indicators:
        if indicator.type == "IP":
            result = provider.lookup_ip(indicator.normalized_value)
        elif indicator.type == "DOMAIN":
            result = provider.lookup_domain(indicator.normalized_value)
        elif indicator.type == "URL":
            result = provider.lookup_url(indicator.normalized_value)
        else:
            continue
        indicator.threat_verdict = result.verdict
        # Persist reputation as a 0..1 value; the GUI renders it as a percentage.
        indicator.reputation_score = result.confidence / 100.0
        results.append(result.to_dict())
    return results


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    skip: int = 0,
    limit: int = 50,
    verdict: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    """List all investigations ordered by creation time descending."""
    query = db.query(Investigation)
    if verdict:
        query = query.filter(Investigation.verdict == verdict.lower())
    if status:
        query = query.filter(Investigation.status == status.lower())
    total = query.count()
    items = query.order_by(Investigation.created_at.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": items}


@router.get("/{investigation_id}", response_model=InvestigationDetailResponse)
async def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """Get full details of an investigation including artifacts, indicators, auth results, and hops."""
    return get_investigation_or_404(db, investigation_id)
