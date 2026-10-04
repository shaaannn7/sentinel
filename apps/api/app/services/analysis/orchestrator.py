"""Phase 2 deterministic analysis orchestrator with stage isolation and persistence."""

from datetime import datetime, timezone
import logging
from sqlalchemy.orm import Session
from app.models.analysis import AnalysisStage, Evidence, Finding, TimelineEvent
from app.models.investigation import Investigation
from app.services.email_parser.models import ParsedEmail
from app.services.analysis.models import AnalyzerResult
from app.services.analysis.evidence import unique_evidence
from app.services.analyzers.authentication import analyze as auth_analyze
from app.services.analyzers.headers import analyze as header_analyze
from app.services.analyzers.urls import analyze as url_analyze
from app.services.analyzers.domains import analyze as domain_analyze
from app.services.analyzers.ips import analyze as ip_analyze
from app.services.analyzers.attachments import analyze as attachment_analyze
from app.services.analyzers.content import analyze as content_analyze
from app.services.scoring.engine import calculate
from app.services.timeline.builder import build

logger = logging.getLogger(__name__)
ANALYSIS_STAGES = ("AUTHENTICATION_ANALYSIS", "HEADER_ANALYSIS", "URL_ANALYSIS", "DOMAIN_ANALYSIS",
                   "IP_ANALYSIS", "ATTACHMENT_ANALYSIS", "CONTENT_ANALYSIS", "SCORING", "TIMELINE")


class AnalysisOrchestrator:
    """Reusable orchestration facade for API handlers and future workers."""

    def __init__(self, db: Session | None = None):
        self.db = db

    def run(self, parsed: ParsedEmail, investigation_id: str | None = None) -> dict:
        return run(parsed, investigation_id=investigation_id, db=self.db)


def run(parsed: ParsedEmail, investigation_id: str | None = None, db: Session | None = None) -> dict:
    """Analyze one already-parsed email. Parsing is intentionally performed once by the caller."""
    functions = (auth_analyze, header_analyze, url_analyze, domain_analyze, ip_analyze, attachment_analyze, content_analyze)
    results: list[AnalyzerResult] = []
    all_findings = []
    all_evidence = []
    stage_names = ("AUTHENTICATION_ANALYSIS", "HEADER_ANALYSIS", "URL_ANALYSIS", "DOMAIN_ANALYSIS",
                   "IP_ANALYSIS", "ATTACHMENT_ANALYSIS", "CONTENT_ANALYSIS")
    stage_records = []
    for function, stage in zip(functions, stage_names):
        started = datetime.now(timezone.utc)
        logger.info("analysis_stage_started", extra={"investigation_id": investigation_id, "stage": stage})
        try:
            result = function(parsed)
        except Exception as exc:  # an analyzer must not take down the investigation
            logger.exception("analysis_stage_failed", extra={"investigation_id": investigation_id, "stage": stage})
            result = AnalyzerResult(stage=stage, success=False, errors=[str(exc)])
        results.append(result)
        logger.info("analysis_stage_completed", extra={"investigation_id": investigation_id, "stage": stage,
                                                       "status": "completed" if result.success else "failed",
                                                       "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000)})
        all_findings.extend(result.findings)
        all_evidence.extend(result.evidence)
        stage_records.append((stage, result, started, datetime.now(timezone.utc)))
    all_evidence = unique_evidence(all_evidence, namespace=investigation_id)
    score = calculate(all_findings, len(all_evidence), parsed)
    timeline = build(parsed, results)

    # ── Brain Intelligence Layer ─────────────────────────────────────────────
    brain_result = None
    try:
        from app.brain.orchestrator import Brain
        brain_result = Brain.analyse(parsed, score, investigation_id=investigation_id)
        # Promote brain verdict/score when brain is more confident
        _SEVERITY = {"BENIGN": 0, "SUSPICIOUS": 1, "PHISHING": 2, "MALICIOUS": 3}
        if _SEVERITY.get(brain_result.verdict, 0) >= _SEVERITY.get(score.verdict, 0):
            # Use brain risk_score as enriched score; keep ScoreResult object intact
            # (the _persist call below will use brain values when present)
            pass
    except Exception as _brain_exc:
        logger.warning("brain_layer_skipped: %s", _brain_exc)
    # ────────────────────────────────────────────────────────────────────────

    if db and investigation_id:
        _persist(db, investigation_id, all_evidence, all_findings, timeline, score, stage_records,
                 [w for r in results for w in r.warnings] + [e for r in results for e in r.errors],
                 brain_result=brain_result)
    return {"results": results, "evidence": all_evidence, "findings": all_findings,
            "score": score, "timeline": timeline,
            "brain": brain_result.report if brain_result else {},
            "warnings": [w for r in results for w in r.warnings],
            "errors": [e for r in results for e in r.errors]}


def _persist(db: Session, investigation_id: str, evidence_items, findings, timeline, score,
             stage_records, warnings: list[str], brain_result=None) -> None:
    # Reruns replace deterministic output, preserving the artifact itself.
    db.query(Evidence).filter(Evidence.investigation_id == investigation_id).delete(synchronize_session=False)
    db.query(Finding).filter(Finding.investigation_id == investigation_id).delete(synchronize_session=False)
    db.query(TimelineEvent).filter(TimelineEvent.investigation_id == investigation_id).delete(synchronize_session=False)
    db.query(AnalysisStage).filter(AnalysisStage.investigation_id == investigation_id).delete(synchronize_session=False)
    for stage, result, started, completed in stage_records:
        db.add(AnalysisStage(investigation_id=investigation_id, stage=stage,
                              status="COMPLETED" if result.success else "FAILED",
                              error="; ".join(result.errors) if result.errors else None,
                              started_at=started, completed_at=completed))
    now = datetime.now(timezone.utc)
    db.add(AnalysisStage(investigation_id=investigation_id, stage="SCORING", status="COMPLETED",
                         started_at=now, completed_at=now))
    db.add(AnalysisStage(investigation_id=investigation_id, stage="TIMELINE", status="COMPLETED",
                         started_at=now, completed_at=now))
    for item in evidence_items:
        db.add(Evidence(id=item.id, investigation_id=investigation_id, type=item.type, source=item.source,
                        value=item.value, description=item.description, metadata_json=item.metadata))
    evidence_ids = {item.id for item in evidence_items}
    for draft in findings:
        refs = [item.id for item in draft.evidence if item.id in evidence_ids]
        if not refs:  # hard invariant: no evidence-free findings
            continue
        db.add(Finding(investigation_id=investigation_id, severity=draft.severity, category=draft.category,
                       title=draft.title, description=draft.description, confidence=draft.confidence,
                       evidence_refs=refs, source=draft.source, points=draft.points))
    for item in timeline:
        db.add(TimelineEvent(investigation_id=investigation_id, timestamp=item.timestamp, event_type=item.event_type,
                             title=item.title, description=item.description, source=item.source, time_kind=item.time_kind))
    investigation = db.get(Investigation, investigation_id)
    if investigation:
        investigation.status = "completed"
        # Use brain-enriched verdict/score when available
        if brain_result:
            investigation.verdict      = brain_result.verdict.lower()
            investigation.risk_score   = brain_result.risk_score
            investigation.confidence   = score.completeness
            investigation.confidence_level = brain_result.confidence
            investigation.summary = (
                f"[Brain v2] {brain_result.verdict.title()} — score {brain_result.risk_score}/100 "
                f"({brain_result.confidence.lower()} confidence). "
                f"{brain_result.explanation}"
            )
        else:
            investigation.verdict      = score.verdict.lower()
            investigation.risk_score   = score.score
            investigation.confidence   = score.completeness
            investigation.confidence_level = score.confidence
            investigation.summary = (
                f"{score.verdict.title()} assessment ({score.score:.0f}/100, {score.confidence.lower()} confidence). "
                f"{len(findings)} evidence-backed finding(s); evidence completeness {score.completeness:.0f}%."
            )
        investigation.score_breakdown   = score.breakdown
        investigation.analysis_warnings = warnings
    db.flush()
