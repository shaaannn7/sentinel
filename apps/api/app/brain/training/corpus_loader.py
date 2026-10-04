"""
SENTINEL Brain — Real Corpus Loader
=====================================
Loads real email corpora (SpamAssassin / Enron) and maps them to
SENTINEL's 4-class label scheme, then returns (X, y) arrays ready for
sklearn training.

Label mapping
-------------
  ham  → 0  BENIGN
  spam → 1  SUSPICIOUS   (spam ≠ phishing; it's a softer category)

Why not PHISHING/MALICIOUS from real corpus?
  Free public datasets mostly separate ham vs spam. True phishing labels
  come from PhishTank (URL-only) or APWG, which require registration.
  Our approach: use ham→BENIGN, spam→SUSPICIOUS as the real-world base,
  then keep synthetic PHISHING + MALICIOUS samples to give the model
  exposure to the most dangerous classes.

Usage
-----
  from app.brain.training.corpus_loader import build_real_dataset
  X, y, meta = build_real_dataset(max_per_class=5000)
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

logger = logging.getLogger(__name__)

LABEL_BENIGN     = 0
LABEL_SUSPICIOUS = 1
LABEL_PHISHING   = 2
LABEL_MALICIOUS  = 3


def build_real_dataset(
    max_per_class: int = 5000,
    synthetic_phishing: int = 2000,
    synthetic_malicious: int = 2000,
    seed: int = 42,
) -> Tuple[np.ndarray, np.ndarray, Dict]:
    """
    Build a mixed dataset:
      - Real ham emails   → label 0 (BENIGN)
      - Real spam emails  → label 1 (SUSPICIOUS)
      - Synthetic phishing → label 2 (PHISHING)   ← keeps coverage on rare class
      - Synthetic malicious→ label 3 (MALICIOUS)

    Returns
    -------
    X    : np.ndarray shape (N, 80)   float32
    y    : np.ndarray shape (N,)      int
    meta : dict with counts per class, source breakdown
    """
    from app.brain.training.download_corpus import iter_emails, corpus_size
    from app.brain.training.data_generator  import generate_dataset as gen_synthetic
    from app.brain.features import extract
    from app.services.email_parser.parser import parse_email

    rng = np.random.default_rng(seed)
    t0  = time.perf_counter()

    size = corpus_size()
    if size["total"] < 100:
        logger.warning(
            "corpus_loader: only %d real emails cached — run download_corpus first. "
            "Falling back to synthetic-only.", size["total"],
        )
        X_syn, y_syn = gen_synthetic(n_per_class=max_per_class, seed=seed)
        return X_syn, y_syn, {
            "source": "synthetic_only",
            "n_real": 0,
            "n_synthetic": len(y_syn),
            "warning": "real corpus unavailable; threat classes are synthetic",
        }

    rows_ham:  List[np.ndarray] = []
    rows_spam: List[np.ndarray] = []
    errors = 0

    def _load_class(label: str, target: List, limit: int) -> None:
        nonlocal errors
        for _, raw in iter_emails(label):
            if len(target) >= limit:
                break
            try:
                parsed = parse_email(raw)
                vec = extract(parsed)
                if not (np.isnan(vec).any() or np.isinf(vec).any()):
                    target.append(vec)
            except Exception:
                errors += 1

    logger.info("corpus_loader: loading real ham emails (max %d)…", max_per_class)
    _load_class("ham",  rows_ham,  max_per_class)
    logger.info("corpus_loader: loading real spam emails (max %d)…", max_per_class)
    _load_class("spam", rows_spam, max_per_class)

    # Synthetic PHISHING + MALICIOUS
    logger.info("corpus_loader: generating %d synthetic phishing + %d malicious samples…",
                synthetic_phishing, synthetic_malicious)
    X_syn, y_syn = gen_synthetic(
        n_per_class=max(synthetic_phishing, synthetic_malicious), seed=seed,
    )
    mask_ph  = y_syn == LABEL_PHISHING
    mask_mal = y_syn == LABEL_MALICIOUS
    X_ph  = X_syn[mask_ph][:synthetic_phishing]
    X_mal = X_syn[mask_mal][:synthetic_malicious]

    # Assemble final arrays
    X_ham  = np.array(rows_ham,  dtype=np.float32)  if rows_ham  else np.zeros((0, 80), np.float32)
    X_spam = np.array(rows_spam, dtype=np.float32)  if rows_spam else np.zeros((0, 80), np.float32)

    X = np.concatenate([X_ham, X_spam, X_ph, X_mal], axis=0)
    y = np.concatenate([
        np.zeros(len(X_ham),  dtype=int),
        np.ones (len(X_spam), dtype=int),
        np.full (len(X_ph),   LABEL_PHISHING,  dtype=int),
        np.full (len(X_mal),  LABEL_MALICIOUS, dtype=int),
    ])

    # Shuffle
    idx = rng.permutation(len(X))
    X, y = X[idx], y[idx]

    elapsed = time.perf_counter() - t0
    meta = {
        "source":            "mixed_real_synthetic",
        "n_real_ham":        len(X_ham),
        "n_real_spam":       len(X_spam),
        "n_synthetic_phish": len(X_ph),
        "n_synthetic_mal":   len(X_mal),
        "n_total":           len(X),
        "parse_errors":      errors,
        "elapsed_s":         round(elapsed, 1),
    }
    logger.info(
        "corpus_loader: built dataset — ham=%d spam=%d phish=%d mal=%d  total=%d  errors=%d  %.1fs",
        len(X_ham), len(X_spam), len(X_ph), len(X_mal), len(X), errors, elapsed,
    )
    return X, y, meta
