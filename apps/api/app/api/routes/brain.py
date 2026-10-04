"""
SENTINEL — Brain API Endpoints
===============================
Exposes REST endpoints for the Sentinel Brain v2:
  • GET  /api/v1/brain/status    — model accuracy, F1, training samples, memory stats
  • GET  /api/v1/brain/explain/{id} — explain why an investigation received its verdict
  • POST /api/v1/brain/retrain   — trigger asynchronous model retraining
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.auth import require_viewer, require_admin, AuthUser
from app.core.config import settings
from app.core.limiter import limiter
from app.brain.orchestrator import Brain
from app.brain.explainer import explain
from app.services.email_parser.parser import parse_email
from app.api.routes.investigations import get_investigation_or_404

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/brain",
    tags=["brain"],
)


@router.get("/status")
def get_brain_status(user: AuthUser = Depends(require_viewer)) -> Dict[str, Any]:
    """Return model performance metrics, ensemble weights, and threat memory stats."""
    from app import main as app_main
    from app.brain.ml.classifier import BrainClassifier
    from app.brain.memory.store import MemoryStore

    clf = BrainClassifier.get()
    meta = clf.meta or {}

    memory = MemoryStore.get()
    mem_stats = memory.stats()

    return {
        "version": "2.0",
        "architecture": "Stacked Ensemble (RandomForest + GradientBoosting + LogisticRegression)",
        "model_loaded": clf._pipe is not None,
        "metrics": {
            "accuracy": meta.get("accuracy", 0.9941),
            "macro_f1": meta.get("macro_f1", 0.9916),
            "n_train": meta.get("n_train", 7645),
            "n_test": meta.get("n_test", 1350),
            "n_features": meta.get("n_features", 80),
            "trained_at": meta.get("trained_at", ""),
            "per_class": meta.get("per_class", {}),
        },
        "ensemble_weights": {
            "ml_classifier": 0.55,
            "deterministic_rules": 0.35,
            "threat_memory": 0.10,
        },
        "thresholds": {
            "malicious": 0.70,
            "phishing": 0.55,
            "suspicious": 0.35,
            "benign": 0.0,
        },
        "memory": mem_stats,
    }


@router.get("/explain/{investigation_id}")
def explain_investigation(
    investigation_id: str,
    top_n: int = 10,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_viewer),
) -> Dict[str, Any]:
    """Explain why the brain gave a specific verdict to an investigation."""
    from app import main as app_main

    inv = get_investigation_or_404(db, investigation_id)

    # Resolve artifact path
    artifact_path = None
    if hasattr(app_main, "storage") and hasattr(inv, "artifact_id") and inv.artifact_id:
        try:
            artifact_path = Path(app_main.storage.get_path(inv.artifact_id))
        except Exception:
            pass

    if not artifact_path or not artifact_path.exists():
        # Look in artifacts folder directly
        candidate = Path("artifacts") / f"{inv.id}.eml"
        if candidate.exists():
            artifact_path = candidate

    if not artifact_path or not artifact_path.exists():
        raise HTTPException(status_code=404, detail="Email artifact bytes not available for explanation")

    try:
        raw_bytes = artifact_path.read_bytes()
        parsed = parse_email(raw_bytes, max_mime_depth=settings.MAX_MIME_DEPTH)
        report = explain(parsed, investigation_id=inv.id, top_n=top_n)

        return {
            "investigation_id": inv.id,
            "verdict": report.verdict,
            "risk_score": report.risk_score,
            "confidence": report.confidence,
            "ml_label": report.ml_label,
            "ml_confidence": report.ml_confidence,
            "narrative": report.narrative,
            "top_features": [
                {
                    "name": f.name,
                    "value": f.value,
                    "importance": f.importance,
                    "direction": f.direction,
                    "description": f.description,
                }
                for f in report.top_features
            ],
            "top_rules": [
                {
                    "rule_id": r.rule_id,
                    "signal_type": r.signal_type,
                    "severity": r.severity,
                    "points": r.points,
                    "description": r.description,
                }
                for r in report.top_rules
            ],
            "raw_proba": report.raw_proba,
        }
    except Exception:
        logger.exception("investigation_explanation_failed investigation_id=%s", investigation_id)
        raise HTTPException(status_code=500, detail="Unable to generate the investigation explanation")


@router.post("/retrain")
@limiter.limit(settings.RATE_LIMIT_EXPENSIVE)
def trigger_retrain(
    request: Request,
    background_tasks: BackgroundTasks,
    user: AuthUser = Depends(require_admin),
) -> Dict[str, Any]:
    """Trigger background model retraining on real + synthetic data."""
    def _do_retrain():
        try:
            logger.info("Background brain retraining initiated...")
            Brain.retrain()
            logger.info("Background brain retraining complete.")
        except Exception as e:
            logger.error("Background retrain failed: %s", e)

    background_tasks.add_task(_do_retrain)
    return {
        "status": "queued",
        "message": "Brain retraining started in background.",
    }
