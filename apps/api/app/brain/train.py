"""
SENTINEL Brain — Training Script
==================================
Run this script directly to train (or retrain) the ML brain.

Usage
-----
  cd apps/api
  python -m app.brain.train [--samples N] [--evaluate] [--verbose]

Options
  --samples N    samples per class (default 3000)
  --real         mix cached real ham/spam corpora with synthetic threat classes
  --download     download the public SpamAssassin corpus before training
  --real-limit N maximum real ham/spam messages per class (default 5000)
  --evaluate     print full classification report
  --verbose      verbose progress output
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.brain.train")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Train SENTINEL Brain ML models")
    parser.add_argument("--samples", type=int, default=3000,
                        help="Synthetic samples per class (default: 3000 → 12 000 total)")
    parser.add_argument("--real", action="store_true",
                        help="Mix cached real ham/spam with synthetic phishing/malware samples")
    parser.add_argument("--download", action="store_true",
                        help="Download the public SpamAssassin corpus before real-data training")
    parser.add_argument("--real-limit", type=int, default=5000,
                        help="Maximum real ham/spam messages per class (default: 5000)")
    parser.add_argument("--evaluate", action="store_true",
                        help="Print full per-class metrics after training")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose progress output")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("SENTINEL Brain Training")
    logger.info("=" * 60)
    if args.real or args.download:
        logger.info(
            "Building mixed training set (up to %d real messages/class + %d synthetic threat samples/class)...",
            args.real_limit, args.samples,
        )
    else:
        logger.info("Generating %d synthetic training samples (%d per class)...",
                    args.samples * 4, args.samples)

    t0 = time.time()

    # Import here (triggers PYTHONPATH setup in the test environment)
    from app.brain.training.data_generator import generate_dataset, LABEL_NAMES
    from app.brain.ml.classifier import train, MODEL_PATH, META_PATH

    dataset_meta = {"source": "synthetic", "synthetic_per_class": args.samples}
    if args.real or args.download:
        if args.download:
            from app.brain.training.download_corpus import download_all
            logger.info("Downloading public training corpus (SpamAssassin quick set)…")
            download_all(quick=True, verbose=True)
        from app.brain.training.corpus_loader import build_real_dataset
        X, y, dataset_meta = build_real_dataset(
            max_per_class=args.real_limit,
            synthetic_phishing=args.samples,
            synthetic_malicious=args.samples,
        )
    else:
        X, y = generate_dataset(n_per_class=args.samples)
    logger.info("Dataset generated: X=%s y=%s (%.1fs)", X.shape, y.shape, time.time() - t0)

    # Class distribution
    for lbl, name in LABEL_NAMES.items():
        n = int((y == lbl).sum())
        logger.info("  Class %d (%s): %d samples", lbl, name, n)

    logger.info("Training stacked ensemble (RF + GB + LR → meta-LR)...")
    meta = train(X, y, verbose=args.verbose)
    meta["dataset"] = dataset_meta
    meta["training_config"] = {
        "seed": 42,
        "synthetic_per_class": args.samples,
        "real_limit_per_class": args.real_limit if (args.real or args.download) else 0,
        "feature_schema": "sentinel-80-v1",
    }
    meta["model_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    logger.info("")
    logger.info("=" * 60)
    logger.info("Training complete!")
    logger.info("  Model saved : %s", MODEL_PATH)
    logger.info("  Accuracy    : %.4f", meta["accuracy"])
    logger.info("  Macro F1    : %.4f", meta["macro_f1"])
    logger.info("  Train time  : %.1fs", meta["train_time_seconds"])
    logger.info("=" * 60)

    if args.evaluate:
        logger.info("")
        logger.info("Per-class metrics:")
        for class_name, scores in meta["per_class"].items():
            logger.info(
                "  %-12s  precision=%.4f  recall=%.4f  f1=%.4f",
                class_name, scores["precision"], scores["recall"], scores["f1"],
            )
        logger.info("")
        logger.info("Confusion matrix (rows=actual, cols=predicted):")
        for i, row in enumerate(meta["confusion_matrix"]):
            logger.info("  %-12s: %s", LABEL_NAMES[i], row)

    # Quick sanity check on a fixture email
    logger.info("")
    logger.info("Running smoke test on sample fixture emails...")
    _smoke_test()

    logger.info("Training and smoke test complete. Review validation metrics before production use. ✓")
    return 0


def _smoke_test():
    """Quick smoke check: run brain on all fixture .eml files."""
    import sys
    from pathlib import Path
    fixtures_dir = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
    if not fixtures_dir.exists():
        logger.warning("Fixtures dir not found at %s — skipping smoke test", fixtures_dir)
        return

    from app.services.email_parser.parser import parse_email
    from app.services.scoring.engine import calculate
    from app.brain.orchestrator import Brain

    for eml_path in sorted(fixtures_dir.glob("*.eml")):
        try:
            with open(eml_path, "rb") as f:
                raw = f.read()
            parsed = parse_email(raw)
            # Minimal fake findings/evidence for score calculation
            score = calculate([], 0, parsed)
            result = Brain.analyse(parsed, score, investigation_id=None, persist_memory=False)
            logger.info("  %-32s → %-12s (score=%3d, ml=%s)",
                        eml_path.name, result.verdict, result.risk_score,
                        result.ml_prediction.get("label", "?"))
        except Exception as exc:
            logger.warning("  %-32s → ERROR: %s", eml_path.name, exc)


if __name__ == "__main__":
    sys.exit(main())
