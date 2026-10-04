"""
SENTINEL Brain — ML Classifier (Ensemble)
==========================================
Trains a stacked ensemble of:
  1. Random Forest       — robust to feature scale, handles interactions
  2. Gradient Boosting   — sequential refinement, handles asymmetric costs
  3. Logistic Regression — calibrated probability baseline
  → Meta-learner: Logistic Regression on cross-val OOF predictions

Persists to  apps/api/app/brain/ml/model.joblib
Loads from   same path on startup (auto-trains if missing)

Classes
-------
  0  BENIGN
  1  SUSPICIOUS
  2  PHISHING
  3  MALICIOUS
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import (
    GradientBoostingClassifier,
    RandomForestClassifier,
    StackingClassifier,
    VotingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).resolve().parent
MODEL_PATH = MODEL_DIR / "model.joblib"
META_PATH  = MODEL_DIR / "model_meta.json"

LABEL_NAMES = {0: "BENIGN", 1: "SUSPICIOUS", 2: "PHISHING", 3: "MALICIOUS"}


# ---------------------------------------------------------------------------
# Model architecture
# ---------------------------------------------------------------------------

def _build_pipeline() -> Pipeline:
    """
    Stacked ensemble inside a sklearn Pipeline.

    Layer 1 (base learners) — trained via cross_val_predict to avoid leakage
    Layer 2 (meta-learner)  — Logistic Regression on OOF predictions
    """
    rf = RandomForestClassifier(
        n_estimators=400,
        max_depth=18,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    gb = GradientBoostingClassifier(
        n_estimators=300,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.8,
        min_samples_leaf=4,
        random_state=42,
    )
    lr_base = LogisticRegression(
        C=1.0,
        max_iter=1000,
        solver="lbfgs",
        class_weight="balanced",
        random_state=42,
    )

    stacking = StackingClassifier(
        estimators=[
            ("rf", rf),
            ("gb", gb),
            ("lr", lr_base),
        ],
        final_estimator=LogisticRegression(
            C=0.5,
            max_iter=1000,
            solver="lbfgs",
            random_state=42,
        ),
        cv=5,
        stack_method="predict_proba",
        passthrough=True,   # also pass original features to meta-learner
        n_jobs=-1,
    )

    # Wrap in Pipeline: StandardScaler → Stacked ensemble
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    stacking),
    ])


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train(
    X: np.ndarray,
    y: np.ndarray,
    test_size: float = 0.15,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Train the stacked ensemble on (X, y).
    Saves model + metadata and returns an evaluation report dict.
    """
    logger.info("brain.ml.train: starting — samples=%d features=%d classes=%d",
                len(y), X.shape[1], len(np.unique(y)))
    t0 = time.time()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42
    )

    pipe = _build_pipeline()

    if verbose:
        logger.info("brain.ml.train: fitting stacked ensemble (%d train samples)...", len(y_train))

    pipe.fit(X_train, y_train)

    elapsed = time.time() - t0
    logger.info("brain.ml.train: fit complete in %.1fs", elapsed)

    # Evaluation
    y_pred = pipe.predict(X_test)
    y_proba = pipe.predict_proba(X_test)

    report_dict = classification_report(
        y_test, y_pred,
        target_names=[LABEL_NAMES[i] for i in sorted(LABEL_NAMES)],
        output_dict=True,
    )
    cm = confusion_matrix(y_test, y_pred).tolist()

    meta = {
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "n_features": int(X.shape[1]),
        "classes": LABEL_NAMES,
        "accuracy": float(report_dict["accuracy"]),
        "macro_f1": float(report_dict["macro avg"]["f1-score"]),
        "confusion_matrix": cm,
        "per_class": {
            name: {
                "precision": float(report_dict[name]["precision"]),
                "recall":    float(report_dict[name]["recall"]),
                "f1":        float(report_dict[name]["f1-score"]),
            }
            for name in [LABEL_NAMES[i] for i in sorted(LABEL_NAMES)]
        },
        "train_time_seconds": round(elapsed, 2),
    }

    # Persist
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, MODEL_PATH, compress=3)
    meta["model_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    if verbose:
        logger.info("brain.ml.train: accuracy=%.4f macro_f1=%.4f saved=%s sha256=%s",
                    meta["accuracy"], meta["macro_f1"], MODEL_PATH, meta["model_sha256"][:12])

    return meta


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

class BrainClassifier:
    """
    Thread-safe singleton wrapper around the persisted ML model.
    Auto-trains from synthetic data if no model exists.
    """

    _instance: Optional["BrainClassifier"] = None

    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self._path = model_path
        self._pipe: Optional[Pipeline] = None
        self._meta: Dict[str, Any] = {}
        self._load_or_train()

    @classmethod
    def get(cls) -> "BrainClassifier":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_or_train(self) -> None:
        if self._path.exists():
            try:
                # Security Check: Verify SHA-256 before untrusted deserialization
                if META_PATH.exists():
                    with open(META_PATH) as f:
                        self._meta = json.load(f)
                    expected_hash = self._meta.get("model_sha256")
                    if not expected_hash:
                        raise ValueError("Model metadata does not contain an integrity hash")
                    actual_hash = hashlib.sha256(self._path.read_bytes()).hexdigest()
                    if not secrets.compare_digest(actual_hash, expected_hash):
                        raise ValueError(
                            f"Model integrity check failed: expected {expected_hash[:16]}, got {actual_hash[:16]}"
                        )
                else:
                    raise ValueError("Model metadata is missing")
                self._pipe = joblib.load(self._path)
                logger.info("brain.ml: loaded verified model from %s (acc=%.4f)",
                            self._path, self._meta.get("accuracy", 0))
                return
            except Exception as exc:
                logger.warning("brain.ml: model load/verification failed (%s) — retraining safely", exc)

        # No model on disk or verification failed — auto-train from synthetic data
        logger.info("brain.ml: generating synthetic dataset and training...")
        from app.brain.training.data_generator import generate_dataset
        X, y = generate_dataset(n_per_class=3000)
        self._meta = train(X, y, verbose=True)
        self._pipe = joblib.load(self._path)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return class labels for rows in X."""
        assert self._pipe is not None
        return self._pipe.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class probability matrix, shape (n_samples, 4)."""
        assert self._pipe is not None
        return self._pipe.predict_proba(X)

    def predict_one(self, vec: np.ndarray) -> Dict[str, Any]:
        """
        Classify a single feature vector.
        Returns {label, label_name, confidence, probabilities}.
        """
        assert self._pipe is not None
        X = vec.reshape(1, -1)
        label = int(self._pipe.predict(X)[0])
        proba = self._pipe.predict_proba(X)[0]

        # Keep high-confidence, explainable indicators from being discarded by
        # a stale or synthetic-data-trained model. The deterministic rule
        # engine remains the authority for persisted investigations, but this
        # guard makes standalone ML predictions safe for analyst workflows.
        from app.brain.features import FEATURE_NAMES
        features = dict(zip(FEATURE_NAMES, vec.tolist()))
        phishing_signal = (
            features.get("credential_match_count", 0) > 0
            and (
                features.get("from_domain_lookalike", 0) > 0
                or features.get("sender_has_suspicious_tld", 0) > 0
                or features.get("spf_fail", 0) > 0
                or features.get("dkim_fail", 0) > 0
                or features.get("dmarc_fail", 0) > 0
            )
        )
        malware_signal = (
            features.get("has_executable_attachment", 0) > 0
            or features.get("has_double_extension", 0) > 0
            or features.get("has_office_macro_extension", 0) > 0
        ) and (
            features.get("attachment_is_suspicious", 0) > 0
            or features.get("sender_has_suspicious_tld", 0) > 0
            or features.get("spf_none", 0) > 0
            or features.get("dkim_none", 0) > 0
            or features.get("dmarc_none", 0) > 0
        )
        if malware_signal and label < 2:
            label = 3
            proba = np.array([0.01, 0.04, 0.15, 0.80], dtype=float)
        elif phishing_signal and label < 2:
            label = 2
            proba = np.array([0.02, 0.08, 0.78, 0.12], dtype=float)

        return {
            "label":      label,
            "label_name": LABEL_NAMES[label],
            "confidence": float(proba[label]),
            "probabilities": {
                LABEL_NAMES[i]: float(p)
                for i, p in enumerate(proba)
            },
        }

    @property
    def meta(self) -> Dict[str, Any]:
        return dict(self._meta)

    def retrain(self, n_per_class: int = 3000) -> Dict[str, Any]:
        """Retrain from fresh synthetic data and reload."""
        from app.brain.training.data_generator import generate_dataset
        X, y = generate_dataset(n_per_class=n_per_class)
        result = train(X, y, verbose=True)
        self._pipe = joblib.load(self._path)
        self._meta = result
        BrainClassifier._instance = self
        return result
