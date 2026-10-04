"""Investigation API endpoints with RBAC, rate limiting, bounded pagination, and secure reporting."""

from __future__ import annotations

import html
import logging
import os
import uuid
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.auth import AuthUser, require_analyst, require_viewer
from app.core.config import settings
from app.core.limiter import limiter
from app.db.session import get_db
from app.models.ai_audit import AIAudit
from app.models.email_artifact import (
    ArtifactAttachment as DBAttachment,
    AuthenticationResult as DBAuthResult,
    EmailArtifact,
    EmailHeader as DBHeader,
    Indicator as DBIndicator,
    ReceivedHop as DBHop,
)
from app.models.investigation import Investigation
from app.schemas.investigation import (
    InvestigationDetailResponse,
    InvestigationListResponse,
)
from app.services.ai_investigation import run_investigation_ai
from app.services.analysis.orchestrator import run as run_deterministic_analysis
from app.services.email_parser import parse_email
from app.services.threat_intel import ThreatIntelProvider

router = APIRouter(
    prefix="/api/v1/investigations",
    tags=["investigations"],
)
logger = logging.getLogger(__name__)


def get_investigation_or_404(db: Session, investigation_id: str) -> Investigation:
    """Get investigation by id or external_id, raise 404 if not found."""
    inv = db.query(Investigation).filter(
        (Investigation.id == investigation_id) | (Investigation.external_id == investigation_id.upper())
    ).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@router.post("", response_model=InvestigationDetailResponse)
@limiter.limit(settings.RATE_LIMIT_UPLOAD)
async def create_investigation(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_analyst),
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
        from app import main as app_main
        file_path, sha256, file_size = app_main.storage.store(file.filename, contents)
    except HTTPException:
        raise
    except Exception:
        logger.exception("artifact_storage_failed request_id=%s", request.state.request_id)
        raise HTTPException(
            status_code=500,
            detail="Unable to store the email artifact",
            headers={"X-Request-ID": request.state.request_id},
        )

    # 2. Parse email deterministically with bounds
    try:
        parsed = parse_email(contents, max_mime_depth=settings.MAX_MIME_DEPTH)
    except Exception:
        logger.exception("email_parse_failed request_id=%s", request.state.request_id)
        raise HTTPException(
            status_code=400,
            detail="Unable to parse the email artifact",
            headers={"X-Request-ID": request.state.request_id},
        )

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
        score_version=settings.SCORE_VERSION,
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

    # Bounded headers (cap at MAX_HEADER_COUNT)
    for h in parsed.headers[:settings.MAX_HEADER_COUNT]:
        db.add(DBHeader(artifact_id=artifact.id, name=h.name[:200], value=h.value[:2000]))

    # Bounded attachments (cap at MAX_ATTACHMENTS)
    for attachment in parsed.attachments[:settings.MAX_ATTACHMENTS]:
        db.add(DBAttachment(
            artifact_id=artifact.id,
            filename=attachment.filename[:200],
            mime_type=attachment.mime_type[:100],
            size=attachment.size,
            sha256=attachment.sha256,
            extension=attachment.extension,
            is_suspicious=attachment.is_suspicious,
            magic_bytes=attachment.magic_bytes,
        ))

    # Bounded indicators (cap at MAX_INDICATORS)
    for ind in parsed.indicators[:settings.MAX_INDICATORS]:
        db.add(DBIndicator(
            investigation_id=inv_id,
            type=ind.type,
            raw_value=ind.raw_value[:500],
            normalized_value=ind.normalized_value[:500],
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

    # Hops (cap at 50)
    for hop in parsed.hops[:50]:
        db.add(DBHop(
            investigation_id=inv_id,
            hop_number=hop.hop_number,
            from_host=hop.from_host,
            by_host=hop.by_host,
            ip_address=hop.ip_address,
            timestamp=hop.timestamp,
        ))

    run_deterministic_analysis(parsed, investigation_id=inv_id, db=db)
    _enrich_investigation_indicators(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


@router.post("/{investigation_id}/analyze", response_model=InvestigationDetailResponse)
@limiter.limit(settings.RATE_LIMIT_EXPENSIVE)
async def analyze_investigation(
    request: Request,
    investigation_id: str,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_analyst),
):
    """Run (or rerun) deterministic analysis against the stored parsed artifact."""
    investigation = get_investigation_or_404(db, investigation_id)
    if not investigation.artifacts:
        raise HTTPException(status_code=409, detail="No email artifact available")
    artifact = investigation.artifacts[0]
    try:
        with open(artifact.file_path, "rb") as handle:
            parsed = parse_email(handle.read(), max_mime_depth=settings.MAX_MIME_DEPTH)
        run_deterministic_analysis(parsed, investigation_id=investigation.id, db=db)
        _enrich_investigation_indicators(investigation)
        db.commit()
        db.refresh(investigation)
        return investigation
    except OSError:
        logger.exception("artifact_unavailable investigation_id=%s request_id=%s", investigation_id, request.state.request_id)
        raise HTTPException(
            status_code=503,
            detail="The stored email artifact is unavailable",
            headers={"X-Request-ID": request.state.request_id},
        )


@router.post("/{investigation_id}/ai-analysis", response_model=InvestigationDetailResponse)
@limiter.limit(settings.RATE_LIMIT_EXPENSIVE)
async def analyze_investigation_with_ai(
    request: Request,
    investigation_id: str,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_analyst),
):
    """Run optional bounded AI enrichment; deterministic results remain authoritative."""
    investigation = get_investigation_or_404(db, investigation_id)
    run_investigation_ai(db, investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


@router.get("/{investigation_id}/ai-reports")
async def get_ai_reports(
    investigation_id: str,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_viewer),
):
    """Return validated AI audit outputs without exposing raw model text."""
    investigation = get_investigation_or_404(db, investigation_id)
    audits = db.query(AIAudit).filter(
        AIAudit.investigation_id == investigation.id,
        AIAudit.output.is_not(None),
    ).order_by(AIAudit.created_at.asc()).all()
    return {"investigation_id": investigation.id, "reports": audits}


@router.post("/{investigation_id}/enrich")
@limiter.limit(settings.RATE_LIMIT_EXPENSIVE)
async def enrich_indicators(
    request: Request,
    investigation_id: str,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_analyst),
):
    """Enrich globally routable indicators using the configured provider boundary."""
    investigation = get_investigation_or_404(db, investigation_id)
    results = _enrich_investigation_indicators(investigation)
    db.commit()
    return {"investigation_id": investigation.id, "results": results}


def _enrich_investigation_indicators(investigation: Investigation) -> list[dict]:
    """Apply the normalized threat-intel contract with SSRF gating."""
    provider = ThreatIntelProvider()
    results = []
    # Cap indicators to enrich at once
    for indicator in investigation.indicators[:settings.MAX_INDICATORS]:
        if indicator.type == "IP":
            result = provider.lookup_ip(indicator.normalized_value)
        elif indicator.type == "DOMAIN":
            result = provider.lookup_domain(indicator.normalized_value)
        elif indicator.type == "URL":
            result = provider.lookup_url(indicator.normalized_value)
        else:
            continue
        indicator.threat_verdict = result.verdict
        indicator.reputation_score = result.confidence / 100.0
        results.append(result.to_dict())
    return results


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    skip: int = Query(default=0, ge=0, description="Offset for pagination"),
    limit: int = Query(default=25, ge=1, le=100, description="Page size (max 100)"),
    verdict: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_viewer),
):
    """List investigations with bounded pagination and filtering."""
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
    user: AuthUser = Depends(require_viewer),
):
    """Get full details of an investigation including artifacts, indicators, auth results, and hops."""
    return get_investigation_or_404(db, investigation_id)


@router.get("/{investigation_id}/report")
async def generate_investigation_report(
    investigation_id: str,
    format: str = Query(default="json", pattern="^(json|html)$"),
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_viewer),
):
    """Generate a clean, sanitized forensic report in JSON or isolated HTML."""
    inv = get_investigation_or_404(db, investigation_id)

    report_data = {
        "id": inv.id,
        "external_id": inv.external_id,
        "status": inv.status,
        "subject": inv.subject,
        "sender": inv.sender,
        "verdict": inv.verdict,
        "risk_score": inv.risk_score,
        "confidence": inv.confidence,
        "confidence_level": inv.confidence_level,
        "score_version": getattr(inv, "score_version", "2026.10"),
        "score_breakdown": inv.score_breakdown,
        "summary": inv.summary,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "points": f.points,
            }
            for f in inv.findings
        ],
        "indicators": [
            {
                "type": i.type,
                "value": i.normalized_value,
                "threat_verdict": i.threat_verdict,
                "reputation_score": i.reputation_score,
                "is_private": i.is_private,
            }
            for i in inv.indicators
        ],
        "authentication": [
            {"protocol": a.protocol, "result": a.result}
            for a in inv.auth_results
        ],
    }

    if format == "json":
        return JSONResponse(content=report_data)

    # Isolated HTML Report with Strict Sanitization and No-Script CSP
    safe_subj = html.escape(inv.subject or "(No Subject)")
    safe_sender = html.escape(inv.sender or "(Unknown Sender)")
    safe_verdict = html.escape(inv.verdict.upper())
    safe_id = html.escape(inv.external_id)
    safe_score = f"{inv.risk_score:.1f}"

    findings_html = "".join(
        f"<tr><td>{html.escape(f['severity'])}</td><td>{html.escape(f['category'])}</td>"
        f"<td>{html.escape(f['title'])}</td><td>{html.escape(f['description'])}</td></tr>"
        for f in report_data["findings"]
    ) or "<tr><td colspan='4'>No findings detected.</td></tr>"

    indicators_html = "".join(
        f"<tr><td>{html.escape(i['type'])}</td><td><code>{html.escape(i['value'])}</code></td>"
        f"<td>{html.escape(i['threat_verdict'])}</td></tr>"
        for i in report_data["indicators"][:50]
    ) or "<tr><td colspan='3'>No indicators found.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SENTINEL Forensic Report - {safe_id}</title>
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; sandbox;">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #0b0f19; color: #f1f5f9; }}
    h1, h2 {{ color: #57d8ff; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: bold; background: #1e293b; color: #f87171; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; margin-bottom: 2rem; }}
    th, td {{ border: 1px solid #334155; padding: 0.5rem; text-align: left; }}
    th {{ background: #1e293b; color: #94a3b8; }}
    code {{ color: #38bdf8; font-family: monospace; }}
  </style>
</head>
<body>
  <h1>SENTINEL Forensic Investigation Report</h1>
  <p><strong>ID:</strong> {safe_id} | <strong>Verdict:</strong> <span class="badge">{safe_verdict}</span> | <strong>Score:</strong> {safe_score}/100</p>
  <p><strong>Subject:</strong> {safe_subj}</p>
  <p><strong>Sender:</strong> {safe_sender}</p>
  <h2>Key Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th></tr></thead>
    <tbody>{findings_html}</tbody>
  </table>
  <h2>Indicators of Compromise</h2>
  <table>
    <thead><tr><th>Type</th><th>Value</th><th>Verdict</th></tr></thead>
    <tbody>{indicators_html}</tbody>
  </table>
</body>
</html>"""

    return HTMLResponse(
        content=html_content,
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox;",
            "X-Content-Type-Options": "nosniff",
        },
    )
