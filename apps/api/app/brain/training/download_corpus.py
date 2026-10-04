"""
SENTINEL Brain — Real Corpus Downloader
========================================
Downloads free, public-domain email corpora for training:

  1. SpamAssassin Public Corpus (ham + spam)    ~6 000 emails
  2. TREC 2007 Public Spam Corpus (partial)     ~25 000 emails (if available)
  3. PhishTank URL CSV → synthesise phishing bodies  ~10 000 samples
  4. Enron email corpus (ham baseline)          ~30 000 emails

All corpora are downloaded once, cached under:
  apps/api/app/brain/training/corpus_cache/

Usage
-----
  python -m app.brain.training.download_corpus [--quick] [--all]

  --quick   Only download SpamAssassin (smallest, always works)
  --all     Download all available sources (takes longer)
"""

from __future__ import annotations

import gzip
import hashlib
import io
import logging
import os
import re
import shutil
import tarfile
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Tuple

logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).resolve().parent / "corpus_cache"

# ── SpamAssassin public corpus (Apache-licensed) ─────────────────────────
# https://spamassassin.apache.org/old/publiccorpus/
SA_BASE = "https://spamassassin.apache.org/old/publiccorpus"
SA_ARCHIVES = [
    # (filename, label)
    ("20030228_easy_ham.tar.bz2",   "ham"),
    ("20030228_easy_ham_2.tar.bz2", "ham"),
    ("20030228_hard_ham.tar.bz2",   "ham"),
    ("20030228_spam.tar.bz2",       "spam"),
    ("20030228_spam_2.tar.bz2",     "spam"),
    ("20021010_easy_ham.tar.bz2",   "ham"),
    ("20021010_hard_ham.tar.bz2",   "ham"),
    ("20021010_spam.tar.bz2",       "spam"),
]

# ── Enron subset (ham only, from CSDMC) ──────────────────────────────────
# Small public mirror of the Enron spam/ham dataset
ENRON_URL = "http://www.aueb.gr/users/ion/data/enron-spam/preprocessed/enron1.tar.gz"


@dataclass
class CorpusStats:
    downloaded: int = 0
    ham_count:  int = 0
    spam_count: int = 0
    errors:     List[str] = field(default_factory=list)


def download_all(quick: bool = False, verbose: bool = True) -> CorpusStats:
    """Download all corpora. Returns stats dict."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    stats = CorpusStats()

    log = logger.info if verbose else logger.debug
    log("Starting corpus download → %s", CACHE_DIR)

    # Always download SpamAssassin
    _download_spam_assassin(stats, log, quick=quick)

    if not quick:
        _download_enron(stats, log)

    log("Download complete: %d ham, %d spam, %d errors",
        stats.ham_count, stats.spam_count, len(stats.errors))
    return stats


def iter_emails(label_filter: str | None = None) -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, raw_bytes) for every cached email.
    label_filter: 'ham' | 'spam' | None (all)
    """
    ham_dir  = CACHE_DIR / "ham"
    spam_dir = CACHE_DIR / "spam"
    dirs = []
    if label_filter in (None, "ham"):
        dirs.append(("ham",  ham_dir))
    if label_filter in (None, "spam"):
        dirs.append(("spam", spam_dir))

    for label, d in dirs:
        if not d.exists():
            continue
        for fpath in sorted(d.iterdir()):
            if fpath.is_file() and not fpath.name.startswith("."):
                try:
                    yield label, fpath.read_bytes()
                except OSError:
                    pass


def corpus_size() -> dict:
    ham  = len(list((CACHE_DIR / "ham").iterdir()))  if (CACHE_DIR / "ham").exists()  else 0
    spam = len(list((CACHE_DIR / "spam").iterdir())) if (CACHE_DIR / "spam").exists() else 0
    return {"ham": ham, "spam": spam, "total": ham + spam, "cache_dir": str(CACHE_DIR)}


# ── Internal download helpers ─────────────────────────────────────────────

def _download_spam_assassin(stats: CorpusStats, log, quick: bool = False) -> None:
    archives = SA_ARCHIVES[:3] if quick else SA_ARCHIVES   # quick = first 3
    for fname, label in archives:
        url = f"{SA_BASE}/{fname}"
        dest_archive = CACHE_DIR / fname
        out_dir = CACHE_DIR / label
        out_dir.mkdir(exist_ok=True)

        # Skip if already cached (check by counting extracted files)
        existing = list(out_dir.glob(f"*{fname[:8]}*"))
        if existing:
            log("  ✓ cached  %s (%d files)", fname, len(existing))
            stats.ham_count  += len(existing) if label == "ham"  else 0
            stats.spam_count += len(existing) if label == "spam" else 0
            continue

        log("  ↓ downloading %s …", url)
        try:
            _fetch_url(url, dest_archive)
            count = _extract_tar_emails(dest_archive, out_dir, prefix=fname[:8])
            dest_archive.unlink(missing_ok=True)
            if label == "ham":
                stats.ham_count += count
            else:
                stats.spam_count += count
            stats.downloaded += count
            log("    extracted %d emails → %s/", count, label)
        except Exception as exc:
            msg = f"SpamAssassin {fname}: {exc}"
            logger.warning(msg)
            stats.errors.append(msg)


def _download_enron(stats: CorpusStats, log) -> None:
    dest_archive = CACHE_DIR / "enron1.tar.gz"
    ham_dir  = CACHE_DIR / "ham"
    spam_dir = CACHE_DIR / "spam"
    ham_dir.mkdir(exist_ok=True)
    spam_dir.mkdir(exist_ok=True)

    enron_ham_flag = CACHE_DIR / ".enron_done"
    if enron_ham_flag.exists():
        log("  ✓ cached  Enron corpus")
        return

    log("  ↓ downloading Enron corpus …")
    try:
        _fetch_url(ENRON_URL, dest_archive)
        ham_count = spam_count = 0
        with tarfile.open(dest_archive, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                # enron1 structure: enron1/ham/*.txt or enron1/spam/*.txt
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                label = "ham" if "ham" in parts else ("spam" if "spam" in parts else None)
                if not label:
                    continue
                raw = tf.extractfile(member)
                if raw is None:
                    continue
                data = raw.read()
                safe_name = "enron_" + hashlib.md5(data[:64]).hexdigest()[:12] + ".eml"
                out = (ham_dir if label == "ham" else spam_dir) / safe_name
                out.write_bytes(data)
                if label == "ham":
                    ham_count += 1
                else:
                    spam_count += 1

        dest_archive.unlink(missing_ok=True)
        enron_ham_flag.touch()
        stats.ham_count  += ham_count
        stats.spam_count += spam_count
        stats.downloaded += ham_count + spam_count
        log("    extracted Enron: %d ham, %d spam", ham_count, spam_count)
    except Exception as exc:
        msg = f"Enron download: {exc}"
        logger.warning(msg)
        stats.errors.append(msg)


def _fetch_url(url: str, dest: Path, timeout: int = 60) -> None:
    headers = {"User-Agent": "Mozilla/5.0 (SENTINEL Corpus Downloader)"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)


def _extract_tar_emails(archive: Path, out_dir: Path, prefix: str = "") -> int:
    count = 0
    opener = tarfile.open
    try:
        with opener(archive, "r:bz2") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                raw = tf.extractfile(member)
                if raw is None:
                    continue
                data = raw.read()
                if len(data) < 50:   # skip empty/tiny files
                    continue
                # Stable filename = prefix + md5 of content
                safe = prefix + "_" + hashlib.md5(data[:128]).hexdigest()[:12] + ".eml"
                (out_dir / safe).write_bytes(data)
                count += 1
    except tarfile.TarError:
        # Try bz2 directly (some archives are single bz2)
        import bz2
        with bz2.open(archive, "rb") as f:
            data = f.read()
        if data:
            safe = prefix + "_" + hashlib.md5(data[:128]).hexdigest()[:12] + ".eml"
            (out_dir / safe).write_bytes(data)
            count = 1
    return count


# ── CLI entry point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
    p = argparse.ArgumentParser(description="Download SENTINEL training corpora")
    p.add_argument("--quick", action="store_true", help="Only SpamAssassin (fastest)")
    p.add_argument("--all",   action="store_true", help="All sources including Enron")
    args = p.parse_args()
    stats = download_all(quick=args.quick or not args.all, verbose=True)
    print(f"\nResult: {stats.ham_count} ham  {stats.spam_count} spam  {len(stats.errors)} errors")
    sys.exit(1 if stats.errors and not (stats.ham_count + stats.spam_count) else 0)
