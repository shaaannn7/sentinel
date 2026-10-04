#!/usr/bin/env python3
"""SENTINEL Pro Terminal Console & CLI
Cyber-Forensic Email Threat Detection, Geolocation & Intelligence Platform
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure apps/api is on the python path
API_ROOT = Path(__file__).resolve().parent
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

# Rich terminal libraries
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.tree import Tree
from rich.syntax import Syntax
from rich.columns import Columns
from rich.align import Align
from rich import box
from rich.style import Style

# Backend imports
from app.db.base import Base
from app.db.session import SessionLocal, engine, ensure_local_schema
from app.core.config import settings
from app.models.investigation import Investigation
from app.models.email_artifact import (
    EmailArtifact,
    EmailHeader as DBHeader,
    Indicator as DBIndicator,
    AuthenticationResult as DBAuthResult,
    ReceivedHop as DBHop,
    ArtifactAttachment as DBAttachment,
)
from app.models.ai_audit import AIAudit
from app.services.email_parser import parse_email
from app.services.analysis.orchestrator import run as run_deterministic_analysis
from app.services.artifact_storage import LocalArtifactStorage
from app.services.threat_intel import ThreatIntelProvider
from app.services.ai_investigation import run_investigation_ai

# Initialize database schema if not present
Base.metadata.create_all(bind=engine)
ensure_local_schema()
storage = LocalArtifactStorage()

# -----------------------------------------------------------------------------
# THEME & CONFIGURATION SYSTEM
# -----------------------------------------------------------------------------
CONFIG_PATH = Path.home() / ".sentinel_config.json"

THEMES: Dict[str, Dict[str, str]] = {
    "cyberpunk": {
        "name": "Cyberpunk Neon",
        "primary": "#00f0ff",      # Neon Cyan
        "secondary": "#ff007f",    # Hot Pink
        "accent": "#ffe600",       # Acid Yellow
        "success": "#00ff66",      # Matrix Green
        "warning": "#ff9900",      # Bright Amber
        "danger": "#ff003c",       # Laser Red
        "muted": "#708090",        # Slate
        "background": "#0a0e14",   # Deep Obsidian
        "card_bg": "#121820",      # Dark Blue Slate
        "text": "#e6edf3",         # Bright Ice
        "highlight": "#bd93f9",    # Neon Purple
    },
    "matrix": {
        "name": "Matrix Hacker",
        "primary": "#00ff66",      # Terminal Lime
        "secondary": "#39ff14",    # Phosphor Green
        "accent": "#73daca",       # Pale Mint
        "success": "#00ff66",      # Bright Green
        "warning": "#ccff00",      # Yellow Green
        "danger": "#ff3333",       # Red Alert
        "muted": "#2e5c38",        # Dim Matrix Green
        "background": "#040d06",   # Deep Matrix Black
        "card_bg": "#0a1f0f",      # Dark Green Slate
        "text": "#d4ffd6",         # Glowing Green White
        "highlight": "#00ffcc",    # Cyan Green
    },
    "dracula": {
        "name": "Dracula Gothic",
        "primary": "#bd93f9",      # Purple
        "secondary": "#ff79c6",    # Pink
        "accent": "#8be9fd",       # Cyan
        "success": "#50fa7b",      # Green
        "warning": "#ffb86c",      # Orange
        "danger": "#ff5555",       # Red
        "muted": "#6272a4",        # Comment Slate
        "background": "#282a36",   # Dark Background
        "card_bg": "#1e1f29",      # Darker Surface
        "text": "#f8f8f2",         # Foreground White
        "highlight": "#f1fa8c",    # Yellow
    },
    "nord": {
        "name": "Nordic Frost",
        "primary": "#88c0d0",      # Frost Cyan
        "secondary": "#81a1c1",    # Frost Blue
        "accent": "#ebcb8b",       # Aurora Yellow
        "success": "#a3be8c",      # Aurora Green
        "warning": "#d08770",      # Aurora Orange
        "danger": "#bf616a",       # Aurora Red
        "muted": "#4c566a",        # Polar Night Grey
        "background": "#2e3440",   # Polar Night
        "card_bg": "#3b4252",      # Polar Night Surface
        "text": "#eceff4",         # Snow Storm
        "highlight": "#b48ead",    # Aurora Purple
    },
    "crimson": {
        "name": "Crimson Red Alert",
        "primary": "#ff1744",      # Crimson Red
        "secondary": "#ff5252",    # Coral
        "accent": "#ffab00",       # Amber Glow
        "success": "#00e676",      # Bright Emerald
        "warning": "#ffd600",      # Electric Gold
        "danger": "#d50000",       # Dark Blood
        "muted": "#757575",        # Carbon
        "background": "#120507",   # Blood Obsidian
        "card_bg": "#21090d",      # Deep Crimson Box
        "text": "#ffffff",         # Pure White
        "highlight": "#ff4081",    # Rose Highlight
    },
    "tokyo-night": {
        "name": "Tokyo Night",
        "primary": "#7aa2f7",      # Electric Blue
        "secondary": "#bb9af7",    # Neon Violet
        "accent": "#7dcfff",       # Sky Cyan
        "success": "#73daca",      # Mint
        "warning": "#e0af68",      # Gold Ochre
        "danger": "#f7768e",       # Crimson Pink
        "muted": "#565f89",        # Blue Grey
        "background": "#1a1b26",   # Tokyo Night Base
        "card_bg": "#24283b",      # Surface
        "text": "#c0caf5",         # Soft Ice
        "highlight": "#2ac3de",    # Cyan Spark
    },
    "gold": {
        "name": "Monarch Gold & Luxury SOC",
        "primary": "#ffd700",      # Pure Gold
        "secondary": "#ffb300",    # Deep Amber
        "accent": "#00e5ff",       # Diamond Cyan
        "success": "#00c853",      # Emerald
        "warning": "#ff6d00",      # Bronze Orange
        "danger": "#ff1744",       # Ruby Red
        "muted": "#786c58",        # Antique Bronze
        "background": "#0f0d09",   # Obsidian Gold
        "card_bg": "#1c170e",      # Deep Amber Surface
        "text": "#fff8e7",         # Cream Silk
        "highlight": "#ffea00",    # Brilliant Yellow
    },
}

BOX_STYLES = {
    "rounded": box.ROUNDED,
    "double": box.DOUBLE,
    "heavy": box.HEAVY,
    "minimal": box.MINIMAL_DOUBLE_HEAD,
    "square": box.SQUARE,
    "ascii": box.ASCII,
}

DEFAULT_CONFIG = {
    "theme": "cyberpunk",
    "box_style": "rounded",
    "banner_style": "neon",
    "show_animations": True,
    "show_full_body": False,
}


def load_config() -> Dict[str, Any]:
    """Load configuration from disk with fallback to defaults."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {**DEFAULT_CONFIG, **data}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any]) -> None:
    """Save configuration to disk."""
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save config to {CONFIG_PATH}: {e}")


# Active runtime configuration
ACTIVE_CONFIG = load_config()
ACTIVE_CONFIG.setdefault("_no_banner", False)


def get_theme() -> Dict[str, str]:
    theme_name = ACTIVE_CONFIG.get("theme", "cyberpunk").lower()
    return THEMES.get(theme_name, THEMES["cyberpunk"])


def get_box():
    b_name = ACTIVE_CONFIG.get("box_style", "rounded").lower()
    return BOX_STYLES.get(b_name, box.ROUNDED)


console = Console()
err_console = Console(stderr=True)  # For printing errors/warnings to stderr

# -----------------------------------------------------------------------------
# VISUAL RENDERING HELPERS
# -----------------------------------------------------------------------------

def get_banner() -> Panel:
    t = get_theme()
    banner_style = ACTIVE_CONFIG.get("banner_style", "neon")

    if banner_style == "ascii":
        raw = r"""
  ___ ___ _  _ _____ ___ _  _ ___ _    
 / __| __| \| |_   _|_ _| \| | __| |   
 \__ \ _|| .` | | |  | || .` | _|| |__ 
 |___/___|_|\_| |_| |___|_|\_|___|____|
 Email Threat Detection & Forensic Platform
        """
        text = Text(raw, style=f"bold {t['primary']}")
    elif banner_style == "compact":
        text = Text("🛡️  SENTINEL — Email Threat Detection, Geolocation & Forensic Platform", style=f"bold {t['primary']}")
    else:  # neon
        text = Text()
        text.append("╔══════════════════════════════════════════════════════════════════════════╗\n", style=f"bold {t['primary']}")
        text.append("║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗          ║\n", style=f"bold {t['primary']}")
        text.append("║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║          ║\n", style=f"bold {t['secondary']}")
        text.append("║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║          ║\n", style=f"bold {t['secondary']}")
        text.append("║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║          ║\n", style=f"bold {t['accent']}")
        text.append("║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗     ║\n", style=f"bold {t['accent']}")
        text.append("║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝     ║\n", style=f"bold {t['primary']}")
        text.append("║       ⚡ Email Threat Detection, Geolocation & Forensic Intelligence    ║\n", style=f"bold {t['text']}")
        text.append("╚══════════════════════════════════════════════════════════════════════════╝", style=f"bold {t['primary']}")

    panel = Panel(
        Align.center(text),
        box=get_box(),
        border_style=f"{t['primary']}",
        padding=(0, 1),
        subtitle=f"[{t['muted']}]Theme: [{t['accent']} bold]{t['name']}[/] | Engine: [{t['success']}]Online[/][/{t['muted']}]",
    )
    return panel


def verdict_badge(verdict: str) -> Text:
    t = get_theme()
    v = (verdict or "").upper()
    if v in ("MALICIOUS", "PHISHING"):
        return Text(f" 🚨 {v} ", style=f"bold #ffffff on {t['danger']}")
    elif v == "SUSPICIOUS":
        return Text(f" ⚠️  {v} ", style=f"bold #000000 on {t['warning']}")
    elif v == "BENIGN":
        return Text(f" ✅ {v} ", style=f"bold #000000 on {t['success']}")
    return Text(f" ❓ {v or 'UNKNOWN'} ", style=f"bold #ffffff on {t['muted']}")


def score_gauge(score: float, width: int = 24) -> Text:
    t = get_theme()
    filled = max(0, min(width, int((score / 100.0) * width)))
    unfilled = width - filled

    if score >= 75:
        color = t['danger']
        label = "CRITICAL RISK"
    elif score >= 50:
        color = t['warning']
        label = "HIGH RISK"
    elif score >= 25:
        color = t['accent']
        label = "MODERATE"
    else:
        color = t['success']
        label = "BENIGN / LOW"

    bar = f"{'█' * filled}{'░' * unfilled}"
    txt = Text()
    txt.append(f"[{label}] ", style=f"bold {color}")
    txt.append(bar, style=f"bold {color}")
    txt.append(f" {score:.0f}/100", style=f"bold {t['text']}")
    return txt


def _terminal_width() -> int:
    return max(72, min(console.width, 132))


def show_status_dashboard(animate: bool = False) -> None:
    """Render a compact SOC-style command dashboard."""
    t = get_theme()
    db = SessionLocal()
    try:
        if animate and console.is_terminal and ACTIVE_CONFIG.get("show_animations", True):
            with Progress(
                SpinnerColumn(style=t["primary"]),
                TextColumn(f"[{t['text']}]{{task.description}}"),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task("Waking forensic command center…", total=None)
                time.sleep(0.18)
                progress.update(task, description="Reading investigation index…")
                time.sleep(0.18)
                progress.update(task, description="Loading threat telemetry…")
                time.sleep(0.18)

        rows = db.query(Investigation).all()
        counts = {"MALICIOUS": 0, "PHISHING": 0, "SUSPICIOUS": 0, "BENIGN": 0, "OTHER": 0}
        for row in rows:
            key = (row.verdict or "OTHER").upper()
            counts[key if key in counts else "OTHER"] += 1

        total = len(rows)
        at_risk = counts["MALICIOUS"] + counts["PHISHING"] + counts["SUSPICIOUS"]
        latest = max(rows, key=lambda row: row.created_at or datetime.min.replace(tzinfo=timezone.utc)) if rows else None

        console.print()
        if not ACTIVE_CONFIG.get("_no_banner"):
            console.print(get_banner())
        summary = Table.grid(expand=True, padding=(0, 2))
        summary.add_column(justify="center")
        summary.add_column(justify="center")
        summary.add_column(justify="center")
        summary.add_column(justify="center")
        summary.add_row(
            f"[bold {t['primary']}] {total} [/]\n[{t['muted']}]INVESTIGATIONS[/]",
            f"[bold {t['danger']}] {at_risk} [/]\n[{t['muted']}]ACTIVE RISK[/]",
            f"[bold {t['success']}] {counts['BENIGN']} [/]\n[{t['muted']}]BENIGN[/]",
            f"[bold {t['accent']}] {len(THEMES)} [/]\n[{t['muted']}]VISUAL THEMES[/]",
        )
        console.print(Panel(summary, title=f"[{t['primary']} bold]SENTINEL COMMAND CENTER[/]", border_style=t["primary"], box=get_box()))

        verdicts = Table(box=get_box(), expand=True, title=f"[{t['secondary']} bold]THREAT POSTURE[/]")
        verdicts.add_column("Verdict")
        verdicts.add_column("Count", justify="right")
        verdicts.add_column("Signal", justify="left")
        for verdict, color, signal in (
            ("MALICIOUS", t["danger"], "Immediate containment"),
            ("PHISHING", t["danger"], "Credential or brand lure"),
            ("SUSPICIOUS", t["warning"], "Analyst review"),
            ("BENIGN", t["success"], "No significant signal"),
        ):
            verdicts.add_row(verdict_badge(verdict), f"[bold {color}]{counts[verdict]}[/]", f"[{t['muted']}]{signal}[/]")
        console.print(verdicts)

        latest_text = "No investigations yet — drop an .eml file to begin."
        if latest:
            latest_text = (
                f"[bold {t['accent']}]{latest.external_id}[/]  "
                f"{verdict_badge(latest.verdict)}  "
                f"{latest.subject or '(no subject)'}"
            )
        quick = (
            f"[bold {t['primary']}]Quick actions[/]\n"
            f"  [{t['accent']}]analyze[/] <file.eml>   [{t['muted']}]inspect a message[/]\n"
            f"  [{t['accent']}]list[/]                [{t['muted']}]browse investigations[/]\n"
            f"  [{t['accent']}]watch[/] <folder>      [{t['muted']}]monitor a drop folder[/]\n"
            f"  [{t['accent']}]interactive[/]         [{t['muted']}]open command center shell[/]\n\n"
            f"[bold {t['primary']}]Latest signal[/]\n  {latest_text}"
        )
        console.print(Panel(quick, border_style=t["secondary"], box=get_box(), width=_terminal_width()))
        console.print(f"[{t['muted']}]Theme: {ACTIVE_CONFIG.get('theme', 'cyberpunk')}  •  Database: {settings.DATABASE_URL.split('://', 1)[0]}  •  Press 'interactive' for guided mode[/]\n")
    finally:
        db.close()


# -----------------------------------------------------------------------------
# CORE INVESTIGATION ENGINE WITH LIVE PROGRESS
# -----------------------------------------------------------------------------

def analyze_file(file_path: str, run_ai: bool = False, verbose: bool = False) -> Investigation:
    """Analyze a single .eml file and store the investigation in the database."""
    t = get_theme()
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(path, "rb") as f:
        contents = f.read()

    if not contents:
        raise ValueError("File is empty")

    show_anim = ACTIVE_CONFIG.get("show_animations", True)

    if show_anim:
        with Progress(
            SpinnerColumn(spinner_name="dots12", style=f"bold {t['primary']}"),
            TextColumn("[bold {task.fields[color]}]{task.description}"),
            BarColumn(bar_width=30, style=f"{t['muted']}", complete_style=f"bold {t['primary']}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            t1 = progress.add_task("Storing artifact securely...", total=100, color=t['primary'])
            stored_path, sha256, file_size = storage.store(path.name, contents)
            progress.update(t1, completed=30, description="Extracting MIME structure & RFC822 headers...")
            time.sleep(0.08)

            parsed = parse_email(contents)
            progress.update(t1, completed=60, description="Executing deterministic heuristic pipelines...")
            time.sleep(0.08)

            inv_id = str(uuid.uuid4())
            ext_id = f"INV-{inv_id[:8].upper()}"

            db = SessionLocal()
            try:
                investigation = Investigation(
                    id=inv_id,
                    external_id=ext_id,
                    status="EXTRACTING",
                    subject=parsed.subject or "(no subject)",
                    sender=parsed.from_addr or "(unknown)",
                    verdict="inconclusive",
                    risk_score=0.0,
                    confidence=0.0,
                    summary="Deterministic analysis queued.",
                )
                db.add(investigation)

                artifact = EmailArtifact(
                    investigation_id=inv_id,
                    filename=path.name,
                    file_path=stored_path,
                    file_size=file_size,
                    mime_type="message/rfc822",
                    sha256=sha256,
                    plain_body=parsed.plain_body,
                    html_body=parsed.html_body,
                )
                db.add(artifact)
                db.flush()

                for h in parsed.headers[:100]:
                    db.add(DBHeader(artifact_id=artifact.id, name=h.name, value=h.value))

                for attachment in parsed.attachments:
                    db.add(DBAttachment(
                        artifact_id=artifact.id, filename=attachment.filename, mime_type=attachment.mime_type,
                        size=attachment.size, sha256=attachment.sha256, extension=attachment.extension,
                        is_suspicious=attachment.is_suspicious, magic_bytes=attachment.magic_bytes,
                    ))

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

                for auth in parsed.auth_results:
                    db.add(DBAuthResult(
                        investigation_id=inv_id,
                        protocol=auth.protocol,
                        result=auth.result,
                        details=auth.details,
                    ))

                for hop in parsed.hops:
                    db.add(DBHop(
                        investigation_id=inv_id,
                        hop_number=hop.hop_number,
                        from_host=hop.from_host,
                        by_host=hop.by_host,
                        ip_address=hop.ip_address,
                        timestamp=hop.timestamp,
                    ))

                # Phase 2 analysis
                run_deterministic_analysis(parsed, investigation_id=inv_id, db=db)

                progress.update(t1, completed=80, description="Querying threat intelligence database...")
                time.sleep(0.06)

                provider = ThreatIntelProvider()
                for indicator in investigation.indicators:
                    if indicator.type == "IP":
                        res = provider.lookup_ip(indicator.normalized_value)
                    elif indicator.type == "DOMAIN":
                        res = provider.lookup_domain(indicator.normalized_value)
                    elif indicator.type == "URL":
                        res = provider.lookup_url(indicator.normalized_value)
                    else:
                        continue
                    indicator.threat_verdict = res.verdict
                    indicator.reputation_score = res.confidence / 100.0

                if run_ai:
                    progress.update(t1, completed=90, description="Running AI multi-agent enrichment...")
                    run_investigation_ai(db, investigation)

                db.commit()
                db.refresh(investigation)
                progress.update(t1, completed=100, description="Analysis completed successfully!")
                time.sleep(0.05)
                return investigation
            finally:
                db.close()
    else:
        # Non-animated direct run
        stored_path, sha256, file_size = storage.store(path.name, contents)
        parsed = parse_email(contents)
        inv_id = str(uuid.uuid4())
        ext_id = f"INV-{inv_id[:8].upper()}"

        db = SessionLocal()
        try:
            investigation = Investigation(
                id=inv_id,
                external_id=ext_id,
                status="EXTRACTING",
                subject=parsed.subject or "(no subject)",
                sender=parsed.from_addr or "(unknown)",
                verdict="inconclusive",
                risk_score=0.0,
                confidence=0.0,
                summary="Deterministic analysis queued.",
            )
            db.add(investigation)

            artifact = EmailArtifact(
                investigation_id=inv_id,
                filename=path.name,
                file_path=stored_path,
                file_size=file_size,
                mime_type="message/rfc822",
                sha256=sha256,
                plain_body=parsed.plain_body,
                html_body=parsed.html_body,
            )
            db.add(artifact)
            db.flush()

            for h in parsed.headers[:100]:
                db.add(DBHeader(artifact_id=artifact.id, name=h.name, value=h.value))
            for attachment in parsed.attachments:
                db.add(DBAttachment(
                    artifact_id=artifact.id, filename=attachment.filename, mime_type=attachment.mime_type,
                    size=attachment.size, sha256=attachment.sha256, extension=attachment.extension,
                    is_suspicious=attachment.is_suspicious, magic_bytes=attachment.magic_bytes,
                ))
            for ind in parsed.indicators:
                db.add(DBIndicator(
                    investigation_id=inv_id, type=ind.type, raw_value=ind.raw_value,
                    normalized_value=ind.normalized_value, threat_verdict="unknown",
                    reputation_score=0.0, is_private=ind.is_private,
                ))
            for auth in parsed.auth_results:
                db.add(DBAuthResult(
                    investigation_id=inv_id, protocol=auth.protocol, result=auth.result, details=auth.details,
                ))
            for hop in parsed.hops:
                db.add(DBHop(
                    investigation_id=inv_id, hop_number=hop.hop_number, from_host=hop.from_host,
                    by_host=hop.by_host, ip_address=hop.ip_address, timestamp=hop.timestamp,
                ))

            run_deterministic_analysis(parsed, investigation_id=inv_id, db=db)

            provider = ThreatIntelProvider()
            for indicator in investigation.indicators:
                if indicator.type == "IP":
                    res = provider.lookup_ip(indicator.normalized_value)
                elif indicator.type == "DOMAIN":
                    res = provider.lookup_domain(indicator.normalized_value)
                elif indicator.type == "URL":
                    res = provider.lookup_url(indicator.normalized_value)
                else:
                    continue
                indicator.threat_verdict = res.verdict
                indicator.reputation_score = res.confidence / 100.0

            if run_ai:
                run_investigation_ai(db, investigation)

            db.commit()
            db.refresh(investigation)
            return investigation
        finally:
            db.close()


# -----------------------------------------------------------------------------
# DETAILED INVESTIGATION REPORT RENDERER
# -----------------------------------------------------------------------------

def print_investigation_report(inv_id_or_ext: str, json_output: bool = False, export_path: str | None = None):
    """Render high-resolution, rich terminal dashboard for an investigation."""
    t = get_theme()
    b = get_box()
    db = SessionLocal()
    try:
        inv = db.query(Investigation).filter(
            (Investigation.id == inv_id_or_ext) | (Investigation.external_id == inv_id_or_ext.upper())
        ).first()

        if not inv:
            console.print(f"[{t['danger']} bold]Error:[/] Investigation not found: {inv_id_or_ext}")
            return

        if json_output:
            data = {
                "id": inv.id,
                "external_id": inv.external_id,
                "status": inv.status,
                "subject": inv.subject,
                "sender": inv.sender,
                "verdict": inv.verdict,
                "risk_score": inv.risk_score,
                "confidence": inv.confidence,
                "confidence_level": inv.confidence_level,
                "summary": inv.summary,
                "score_breakdown": inv.score_breakdown,
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
                "findings": [{"severity": f.severity, "category": f.category, "title": f.title, "description": f.description, "points": f.points} for f in inv.findings],
                "indicators": [{"type": i.type, "value": i.normalized_value, "threat_verdict": i.threat_verdict, "reputation_score": i.reputation_score} for i in inv.indicators],
                "auth_results": [{"protocol": a.protocol, "result": a.result, "details": a.details} for a in inv.auth_results],
                "hops": [{"hop": h.hop_number, "from": h.from_host, "by": h.by_host, "ip": h.ip_address, "timestamp": h.timestamp} for h in inv.hops],
            }
            console.print_json(data=data)
            return

        # 1. Header & Overview Card
        overview_table = Table.grid(padding=(0, 2))
        overview_table.add_column(style=f"bold {t['muted']}", justify="right", width=14)
        overview_table.add_column(style=f"bold {t['text']}")

        overview_table.add_row("Subject:", f"[{t['text']} bold]{inv.subject}[/]")
        overview_table.add_row("Sender:", f"[{t['primary']}]{inv.sender}[/]")
        overview_table.add_row("Verdict:", verdict_badge(inv.verdict))
        overview_table.add_row("Risk Score:", score_gauge(inv.risk_score))
        overview_table.add_row("Confidence:", f"[{t['accent']} bold]{inv.confidence:.1f}%[/] ({inv.confidence_level})")
        overview_table.add_row("Status:", f"[{t['success'] if inv.status == 'completed' else t['warning']} bold]{inv.status.upper()}[/]")
        created_str = inv.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if inv.created_at else "N/A"
        overview_table.add_row("Timestamp:", f"[{t['muted']}]{created_str}[/]")
        overview_table.add_row("Summary:", f"[{t['text']} italic]{inv.summary}[/]")

        overview_panel = Panel(
            overview_table,
            title=f"[{t['primary']} bold]🛡️  INVESTIGATION {inv.external_id}[/]",
            subtitle=f"[{t['muted']}]UUID: {inv.id}[/]",
            box=b,
            border_style=f"{t['primary']}",
            padding=(1, 2),
        )
        console.print()
        console.print(overview_panel)

        # 2. Risk Breakdown & Authentication in 2 columns
        # Column 1: Risk Breakdown
        score_table = Table(box=b, border_style=f"{t['muted']}", expand=True)
        score_table.add_column("Category", style=f"bold {t['text']}")
        score_table.add_column("Points", justify="right", style=f"bold {t['accent']}")
        score_table.add_column("Weight", justify="left")

        for cat, pts in sorted(inv.score_breakdown.items(), key=lambda x: -x[1]):
            b_len = int(pts)
            bar_color = t['danger'] if pts >= 10 else t['warning'] if pts >= 5 else t['success']
            score_table.add_row(cat, f"{pts} pts", f"[{bar_color}]{'■' * b_len}[/]")

        breakdown_panel = Panel(
            score_table,
            title=f"[{t['secondary']} bold]📊 Score Breakdown[/]",
            box=b,
            border_style=f"{t['secondary']}",
        )

        # Column 2: Authentication
        auth_table = Table(box=b, border_style=f"{t['muted']}", expand=True)
        auth_table.add_column("Protocol", style=f"bold {t['primary']}")
        auth_table.add_column("Result", justify="center")
        auth_table.add_column("Details", style=f"{t['muted']}")

        for auth in inv.auth_results:
            st = auth.result.lower()
            badge = Text(f" {st.upper()} ", style=f"bold #000 on {t['success']}" if st == "pass" else f"bold #fff on {t['danger']}" if st == "fail" else f"bold #000 on {t['warning']}")
            details_str = ", ".join(f"{k}={v}" for k, v in (auth.details or {}).items() if k in ("smtp.mailfrom", "header.d", "client-ip")) or "-"
            auth_table.add_row(auth.protocol, badge, details_str[:30])

        if not inv.auth_results:
            auth_table.add_row("[dim]None[/]", "[dim]N/A[/]", "[dim]No Authentication-Results header[/]")

        auth_panel = Panel(
            auth_table,
            title=f"[{t['accent']} bold]🔐 Email Authentication (SPF/DKIM/DMARC)[/]",
            box=b,
            border_style=f"{t['accent']}",
        )

        console.print(Columns([breakdown_panel, auth_panel]))

        # 3. Evidence-Backed Findings Table
        if inv.findings:
            fnd_table = Table(box=b, border_style=f"{t['danger']}", expand=True)
            fnd_table.add_column("#", justify="center", width=4, style=f"bold {t['muted']}")
            fnd_table.add_column("Severity", justify="center", width=12)
            fnd_table.add_column("Finding Title", style=f"bold {t['text']}", width=34)
            fnd_table.add_column("Points", justify="right", width=8, style=f"bold {t['accent']}")
            fnd_table.add_column("Description & Evidence Ref", style=f"{t['muted']}")

            for idx, f in enumerate(inv.findings, 1):
                sev = f.severity.upper()
                sev_badge = Text(f" {sev} ", style=f"bold #fff on {t['danger']}" if sev in ("HIGH", "CRITICAL") else f"bold #000 on {t['warning']}" if sev == "MEDIUM" else f"bold #fff on {t['primary']}")
                desc = f.description
                if f.evidence_refs:
                    desc += f"\n[dim {t['accent']}]Refs: {', '.join(f.evidence_refs)}[/]"
                fnd_table.add_row(str(idx), sev_badge, f.title, f"+{f.points}", desc)

            fnd_panel = Panel(
                fnd_table,
                title=f"[{t['danger']} bold]🚨 Evidence-Backed Findings ({len(inv.findings)})[/]",
                box=b,
                border_style=f"{t['danger']}",
            )
            console.print(fnd_panel)

        # 4. Indicators of Compromise (IOCs) Table
        if inv.indicators:
            ioc_table = Table(box=b, border_style=f"{t['primary']}", expand=True)
            ioc_table.add_column("Type", width=8, style=f"bold {t['secondary']}")
            ioc_table.add_column("Threat Verdict", justify="center", width=14)
            ioc_table.add_column("Reputation", justify="center", width=12)
            ioc_table.add_column("Indicator Value", style=f"bold {t['text']}")

            for ind in inv.indicators[:30]:
                tv = ind.threat_verdict.lower()
                badge = Text(f" {tv.upper()} ", style=f"bold #fff on {t['danger']}" if tv == "malicious" else f"bold #000 on {t['warning']}" if tv == "suspicious" else f"bold #000 on {t['success']}" if tv == "benign" else f"bold #fff on {t['muted']}")
                rep_pct = f"{ind.reputation_score * 100:.0f}%" if ind.reputation_score else "-"
                ioc_table.add_row(ind.type, badge, rep_pct, ind.normalized_value)

            ioc_panel = Panel(
                ioc_table,
                title=f"[{t['primary']} bold]🌐 Extracted Indicators of Compromise ({len(inv.indicators)})[/]",
                box=b,
                border_style=f"{t['primary']}",
            )
            console.print(ioc_panel)

        # 5. Email Delivery Path (Hops Tree)
        if inv.hops:
            tree = Tree(f"[{t['accent']} bold]📧 Email Delivery Path ({len(inv.hops)} hops)[/]")
            for hop in inv.hops:
                node = tree.add(
                    f"[{t['primary']} bold]Hop #{hop.hop_number}:[/] [{t['text']}]{hop.from_host or 'unknown'}[/] → [{t['secondary']} bold]{hop.by_host or 'unknown'}[/] [{t['accent']}][{hop.ip_address or 'no IP'}][/{t['accent']}]"
                )
                if hop.timestamp:
                    node.add(f"[{t['muted']}]Timestamp: {hop.timestamp}[/]")

            hop_panel = Panel(tree, box=b, border_style=f"{t['accent']}")
            console.print(hop_panel)

        # 6. Attachments
        for art in inv.artifacts:
            if art.attachments:
                att_table = Table(box=b, border_style=f"{t['secondary']}", expand=True)
                att_table.add_column("Filename", style=f"bold {t['text']}")
                att_table.add_column("Size", justify="right", width=10, style=f"{t['muted']}")
                att_table.add_column("MIME Type", width=22, style=f"{t['primary']}")
                att_table.add_column("Status", justify="center", width=14)
                att_table.add_column("SHA-256 Checksum", style=f"{t['muted']} font-mono")

                for att in art.attachments:
                    st_badge = Text(" SUSPICIOUS ", style=f"bold #fff on {t['danger']}") if att.is_suspicious else Text(" SAFE ", style=f"bold #000 on {t['success']}")
                    size_kb = f"{att.size / 1024.0:.1f} KB"
                    att_table.add_row(att.filename, size_kb, att.mime_type, st_badge, att.sha256[:32] + "...")

                att_panel = Panel(
                    att_table,
                    title=f"[{t['secondary']} bold]📦 Attachment Security Analysis ({len(art.attachments)})[/]",
                    box=b,
                    border_style=f"{t['secondary']}",
                )
                console.print(att_panel)

        # 7. AI Enrichment Audits
        if inv.ai_audits:
            ai_tree = Tree(f"[{t['highlight']} bold]🤖 AI Multi-Agent Enrichment Audits ({len(inv.ai_audits)})[/]")
            for audit in inv.ai_audits:
                status_color = t['success'] if audit.validation_status == "validated" else t['warning']
                agent_node = ai_tree.add(
                    f"[{t['primary']} bold]Agent: {audit.agent.upper()}[/] | Model: [{t['muted']}]{audit.model}[/] | Status: [{status_color} bold]{audit.validation_status}[/]"
                )
                if audit.output:
                    out_text = json.dumps(audit.output, indent=2)
                    agent_node.add(Syntax(out_text, "json", theme="monokai", word_wrap=True))

            ai_panel = Panel(ai_tree, box=b, border_style=f"{t['highlight']}")
            console.print(ai_panel)

        console.print()

        # HTML Export option
        if export_path:
            html_content = console.export_html(inline_styles=True)
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            console.print(f"[{t['success']} bold]Report exported to {export_path}[/]")

    finally:
        db.close()


# -----------------------------------------------------------------------------
# INVESTIGATION LISTING
# -----------------------------------------------------------------------------

def list_investigations(limit: int = 20, verdict: str | None = None, status: str | None = None):
    """List investigations in a formatted rich table."""
    t = get_theme()
    b = get_box()
    db = SessionLocal()
    try:
        query = db.query(Investigation)
        if verdict:
            query = query.filter(Investigation.verdict == verdict.lower())
        if status:
            query = query.filter(Investigation.status == status.lower())

        total = query.count()
        items = query.order_by(Investigation.created_at.desc()).limit(limit).all()

        console.print()
        if not items:
            console.print(Panel(
                f"[{t['muted']}]No investigations found.\nAnalyze an email using: [bold {t['primary']}]sentinel analyze <file.eml>[/][/]",
                box=b,
                title=f"[{t['primary']} bold]Investigations Database[/]",
                border_style=f"{t['muted']}",
            ))
            return

        table = Table(
            box=b,
            border_style=f"{t['primary']}",
            title=f"[{t['primary']} bold]SENTINEL INVESTIGATIONS DATABASE[/] [{t['muted']}]({total} total records)[/]",
            expand=True,
        )
        table.add_column("ID", style=f"bold {t['primary']}", width=14)
        table.add_column("Date", style=f"{t['muted']}", width=18)
        table.add_column("Verdict", justify="center", width=14)
        table.add_column("Risk Score", justify="center", width=16)
        table.add_column("Confidence", justify="center", width=12, style=f"{t['accent']}")
        table.add_column("Subject", style=f"bold {t['text']}")
        table.add_column("Sender", style=f"{t['muted']}")

        for inv in items:
            date_str = inv.created_at.strftime("%Y-%m-%d %H:%M") if inv.created_at else "-"
            subj = (inv.subject or "(no subject)")[:35]
            sender = (inv.sender or "-")[:25]
            score_txt = f"{inv.risk_score:.0f}/100"
            conf_txt = f"{inv.confidence:.0f}%"

            table.add_row(
                inv.external_id,
                date_str,
                verdict_badge(inv.verdict),
                score_txt,
                conf_txt,
                subj,
                sender,
            )

        console.print(table)
        console.print()
    finally:
        db.close()


# -----------------------------------------------------------------------------
# THEME SHOWCASE & CONFIGURATION MANAGEMENT
# -----------------------------------------------------------------------------

def show_themes_showcase():
    """Visual theme gallery in terminal."""
    b = get_box()
    console.print()
    console.print(Panel(
        "[bold #ffffff]🎨 SENTINEL THEME GALLERY & PALETTES[/]\n"
        "[dim]Switch themes dynamically with: [bold #00f0ff]./sentinel config set theme <name>[/][/]",
        box=b,
        border_style="bold #00f0ff",
    ))

    cards = []
    for key, theme_data in THEMES.items():
        is_active = (key == ACTIVE_CONFIG.get("theme", "cyberpunk"))
        active_badge = "[bold #00ff66] (ACTIVE)[/]" if is_active else ""

        content = Table.grid(padding=(0, 1))
        content.add_column(width=10, style="dim")
        content.add_column()

        content.add_row("Primary", f"[{theme_data['primary']} bold]██████ {theme_data['primary']}[/]")
        content.add_row("Secondary", f"[{theme_data['secondary']} bold]██████ {theme_data['secondary']}[/]")
        content.add_row("Accent", f"[{theme_data['accent']} bold]██████ {theme_data['accent']}[/]")
        content.add_row("Success", f"[{theme_data['success']} bold]██████ {theme_data['success']}[/]")
        content.add_row("Danger", f"[{theme_data['danger']} bold]██████ {theme_data['danger']}[/]")
        content.add_row("Verdict", Text(" MALICIOUS ", style=f"bold #ffffff on {theme_data['danger']}"))

        card = Panel(
            content,
            title=f"[{theme_data['primary']} bold]{key}[/]{active_badge}",
            subtitle=f"[{theme_data['muted']}]{theme_data['name']}[/]",
            box=b,
            border_style=f"{theme_data['primary']}",
            width=36,
        )
        cards.append(card)

    console.print(Columns(cards, equal=True))
    console.print()


def handle_config_command(args):
    """Handle configuration inspection and mutation."""
    t = get_theme()
    b = get_box()

    if not args.action or args.action in ("list", "show"):
        cfg_table = Table(box=b, border_style=f"{t['primary']}", title=f"[{t['primary']} bold]Current Sentinel Configuration[/]")
        cfg_table.add_column("Setting", style=f"bold {t['secondary']}")
        cfg_table.add_column("Value", style=f"bold {t['text']}")
        cfg_table.add_column("Available Choices", style=f"{t['muted']}")

        cfg_table.add_row("theme", f"[{t['accent']}]{ACTIVE_CONFIG.get('theme')}[/]", ", ".join(THEMES.keys()))
        cfg_table.add_row("box_style", f"[{t['accent']}]{ACTIVE_CONFIG.get('box_style')}[/]", ", ".join(BOX_STYLES.keys()))
        cfg_table.add_row("banner_style", f"[{t['accent']}]{ACTIVE_CONFIG.get('banner_style')}[/]", "neon, ascii, compact, none")
        cfg_table.add_row("show_animations", f"[{t['accent']}]{ACTIVE_CONFIG.get('show_animations')}[/]", "true, false")
        cfg_table.add_row("show_full_body", f"[{t['accent']}]{ACTIVE_CONFIG.get('show_full_body')}[/]", "true, false")

        console.print()
        console.print(cfg_table)
        console.print(f"[{t['muted']}]Config file: {CONFIG_PATH}[/]\n")

    elif args.action == "set":
        key = args.key
        value = args.value
        if not key or value is None:
            console.print(f"[{t['danger']} bold]Usage:[/] ./sentinel config set <key> <value>")
            return

        key = key.lower()
        if key == "theme":
            if value.lower() not in THEMES:
                console.print(f"[{t['danger']} bold]Error:[/] Invalid theme '{value}'. Choose from: {', '.join(THEMES.keys())}")
                return
            ACTIVE_CONFIG["theme"] = value.lower()
        elif key == "box_style":
            if value.lower() not in BOX_STYLES:
                console.print(f"[{t['danger']} bold]Error:[/] Invalid box_style '{value}'. Choose from: {', '.join(BOX_STYLES.keys())}")
                return
            ACTIVE_CONFIG["box_style"] = value.lower()
        elif key == "banner_style":
            if value.lower() not in ("neon", "ascii", "compact", "none"):
                console.print(f"[{t['danger']} bold]Error:[/] Invalid banner_style '{value}'. Choose from: neon, ascii, compact, none")
                return
            ACTIVE_CONFIG["banner_style"] = value.lower()
        elif key in ("show_animations", "show_full_body"):
            ACTIVE_CONFIG[key] = value.lower() in ("true", "1", "yes", "on")
        else:
            console.print(f"[{t['danger']} bold]Error:[/] Unknown setting '{key}'")
            return

        save_config(ACTIVE_CONFIG)
        console.print(f"[{t['success']} bold]✓ Setting updated:[/] {key} = [bold {t['accent']}]{value}[/]")


# -----------------------------------------------------------------------------
# BRAIN INTELLIGENCE LAYER CLI
# -----------------------------------------------------------------------------

def handle_brain_command(action: str = "status") -> None:
    """Show brain ML status, memory stats, or retrain the model."""
    t = get_theme()
    bx = get_box()
    action = (action or "status").lower()

    if action == "status":
        # ML model metadata
        from pathlib import Path
        import json as _json

        meta_path = Path(__file__).resolve().parent / "app" / "brain" / "ml" / "model_meta.json"
        if not meta_path.exists():
            console.print(Panel(
                f"[{t['warning']} bold]⚠  Brain model not trained yet.[/]\n"
                f"Run: [{t['accent']}]./sentinel brain train[/]  to train the ML model.",
                title=f"[{t['primary']} bold]🧠 SENTINEL Brain[/]",
                border_style=t["primary"], box=bx,
            ))
            return

        try:
            meta = _json.loads(meta_path.read_text())
        except Exception as e:
            console.print(f"[{t['danger']}]Could not read model meta: {e}[/]")
            return

        # Memory stats
        mem_stats = {}
        try:
            from app.brain.memory.store import MemoryStore
            mem_stats = MemoryStore.get().stats()
        except Exception:
            pass

        # Build display
        tbl = Table(box=bx, border_style=t["primary"], show_header=False, padding=(0, 1))
        tbl.add_column("Key",   style=f"bold {t['accent']}", width=26)
        tbl.add_column("Value", style=t["text"])

        tbl.add_section()
        tbl.add_row("🧠 Brain Version",   "2.0 — Ensemble ML + Rules + Memory")
        tbl.add_row("📅 Trained At",      meta.get("trained_at", "?"))
        tbl.add_row("🎯 Accuracy",        f"{meta.get('accuracy', 0):.4f}  ({meta.get('accuracy', 0)*100:.2f}%)")
        tbl.add_row("📊 Macro F1",        f"{meta.get('macro_f1', 0):.4f}")
        tbl.add_row("📦 Train Samples",   str(meta.get("n_train", "?")))
        tbl.add_row("🔬 Test Samples",    str(meta.get("n_test", "?")))
        tbl.add_row("🔢 Features",        str(meta.get("n_features", 80)))
        tbl.add_row("⏱  Train Time",      f"{meta.get('train_time_seconds', '?')}s")

        tbl.add_section()
        per_class = meta.get("per_class", {})
        for cls, scores in per_class.items():
            colour = {"BENIGN": t["success"], "SUSPICIOUS": t["warning"],
                      "PHISHING": t["danger"], "MALICIOUS": t["danger"]}.get(cls, t["text"])
            tbl.add_row(
                f"[{colour}]{cls}[/]",
                f"P={scores.get('precision', 0):.3f}  R={scores.get('recall', 0):.3f}  F1={scores.get('f1', 0):.3f}",
            )

        tbl.add_section()
        tbl.add_row("💾 Threat Senders",  str(mem_stats.get("threat_senders", 0)))
        tbl.add_row("🌐 Threat Domains",  str(mem_stats.get("threat_domains", 0)))
        tbl.add_row("🔗 Threat URLs",     str(mem_stats.get("threat_url_patterns", 0)))
        tbl.add_row("✅ Confirmed Safe",  str(mem_stats.get("confirmed_safe", 0)))
        tbl.add_row("☣  Confirmed Threat",str(mem_stats.get("confirmed_threat", 0)))

        console.print(Panel(tbl, title=f"[{t['primary']} bold]🧠 SENTINEL Brain Status[/]",
                            border_style=t["primary"], box=bx))

    elif action in ("train", "retrain"):
        console.print(f"[{t['primary']} bold]🧠 Training SENTINEL Brain...[/]")
        console.print(f"[{t['muted']}]Generating 12 000 synthetic email samples (4 classes × 3 000)...[/]")

        with Progress(
            SpinnerColumn(style=t["primary"]),
            TextColumn(f"[{t['text']}]{{task.description}}"),
            TimeElapsedColumn(),
            console=console, transient=False,
        ) as progress:
            task = progress.add_task("Training stacked ensemble (RF + GB + LR → meta-LR)...", total=None)
            try:
                from app.brain.orchestrator import Brain
                meta = Brain.retrain(n_per_class=3000)
                progress.update(task, description="[bold green]Training complete![/]")
            except Exception as e:
                progress.stop()
                err_console.print(f"[{t['danger']} bold]Training failed:[/] {e}")
                return

        console.print(f"\n[{t['success']} bold]✓ Brain trained successfully![/]")
        console.print(f"  Accuracy: [{t['accent']}]{meta.get('accuracy', 0):.4f}[/]   "
                      f"Macro F1: [{t['accent']}]{meta.get('macro_f1', 0):.4f}[/]   "
                      f"Time: [{t['muted']}]{meta.get('train_time_seconds', '?')}s[/]")
        per_class = meta.get("per_class", {})
        tbl = Table(box=bx, border_style=t["primary"])
        tbl.add_column("Class",     style=f"bold {t['accent']}")
        tbl.add_column("Precision", style=t["text"])
        tbl.add_column("Recall",    style=t["text"])
        tbl.add_column("F1",        style=t["text"])
        for cls, sc in per_class.items():
            tbl.add_row(cls, f"{sc['precision']:.4f}", f"{sc['recall']:.4f}", f"{sc['f1']:.4f}")
        console.print(tbl)

    else:
        console.print(f"[{t['danger']}]Unknown brain action '{action}'. Use: status | train[/]")


# -----------------------------------------------------------------------------
# IMAP INBOX INTEGRATION
# -----------------------------------------------------------------------------

import imaplib
import email as _email_module
import getpass
import ssl
import tempfile

# Well-known IMAP server presets
IMAP_PRESETS: Dict[str, Dict[str, Any]] = {
    "gmail":   {"host": "imap.gmail.com",          "port": 993, "label": "Gmail"},
    "outlook": {"host": "imap-mail.outlook.com",    "port": 993, "label": "Outlook / Hotmail"},
    "yahoo":   {"host": "imap.mail.yahoo.com",      "port": 993, "label": "Yahoo Mail"},
    "apple":   {"host": "imap.mail.me.com",         "port": 993, "label": "Apple iCloud Mail"},
    "zoho":    {"host": "imap.zoho.com",            "port": 993, "label": "Zoho Mail"},
    "custom":  {"host": "",                          "port": 993, "label": "Custom Server"},
}

# Saved account in config under key "imap_accounts" (list of dicts, no password stored)
IMAP_CONFIG_KEY = "imap_accounts"


def _imap_connect(host: str, port: int, username: str, password: str) -> imaplib.IMAP4_SSL:
    """Open a TLS-secured IMAP4 connection and login."""
    ctx = ssl.create_default_context()
    conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
    conn.login(username, password)
    return conn


def _decode_header_value(raw: str) -> str:
    """Safely decode an RFC2047-encoded email header into a plain string."""
    parts = _email_module.header.decode_header(raw or "")
    decoded = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            decoded.append(chunk.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(str(chunk))
    return "".join(decoded)


def run_inbox_command(args) -> None:
    """
    Main handler for `./sentinel inbox [--provider] [--host] [--port] [--user] [--folder] [--limit]`.
    Guides the user through provider selection → credentials → inbox listing → analysis.
    """
    t = get_theme()
    bx = get_box()

    # ── 1. Pick provider ────────────────────────────────────────────────────
    provider = getattr(args, "provider", None) or ""
    host     = getattr(args, "host",     None) or ""
    port     = getattr(args, "port",     None) or 993
    username = getattr(args, "user",     None) or ""
    folder   = getattr(args, "folder",   None) or "INBOX"
    limit    = getattr(args, "limit",    None) or 20

    if not provider and not host:
        # Interactive provider picker
        console.print()
        console.print(Panel(
            f"[bold {t['primary']}]📬 SENTINEL INBOX CONNECT[/]\n"
            f"[{t['text']}]Connect to your email account via secure IMAP (SSL/TLS).[/]\n"
            f"[{t['muted']}]Your password is never stored to disk.[/]",
            box=bx, border_style=t['primary'],
        ))

        tbl = Table(box=bx, border_style=t['accent'], title=f"[{t['accent']} bold]Supported Providers[/]")
        tbl.add_column("#",        style=f"bold {t['accent']}", width=4)
        tbl.add_column("Provider", style=f"bold {t['primary']}")
        tbl.add_column("IMAP Host", style=t['muted'])
        for i, (key, val) in enumerate(IMAP_PRESETS.items(), 1):
            tbl.add_row(str(i), val["label"], val["host"] or "(enter manually)")
        console.print(tbl)

        choice = console.input(f"[bold {t['primary']}]Select provider number (or press Enter for Gmail):[/] ").strip()
        keys = list(IMAP_PRESETS.keys())
        try:
            idx = int(choice) - 1 if choice else 0
            provider = keys[idx] if 0 <= idx < len(keys) else "gmail"
        except ValueError:
            provider = choice.lower() if choice.lower() in IMAP_PRESETS else "gmail"

    preset = IMAP_PRESETS.get(provider, IMAP_PRESETS["custom"])

    if not host:
        if preset["host"]:
            host = preset["host"]
            port = preset["port"]
        else:
            host = console.input(f"[bold {t['primary']}]IMAP Host (e.g. imap.example.com):[/] ").strip()
            port_str = console.input(f"[bold {t['primary']}]Port [{t['muted']}](default 993)[/]: ").strip()
            port = int(port_str) if port_str.isdigit() else 993

    if not username:
        username = console.input(f"[bold {t['primary']}]Email address:[/] ").strip()

    password = getpass.getpass(f"Password for {username} (not stored): ")

    # ── 2. Connect ───────────────────────────────────────────────────────────
    console.print(f"\n[{t['muted']}]Connecting to {host}:{port} ...[/]")
    try:
        with Progress(
            SpinnerColumn(spinner_name="dots", style=f"bold {t['primary']}"),
            TextColumn(f"[{t['text']}]{{task.description}}"),
            console=console, transient=True,
        ) as prog:
            task = prog.add_task("Establishing TLS connection...", total=None)
            conn = _imap_connect(host, port, username, password)
            prog.update(task, description="Selecting folder...")
            conn.select(folder)

        console.print(f"[{t['success']} bold]✓ Connected as {username}[/]\n")
    except imaplib.IMAP4.error as e:
        err_console.print(f"[{t['danger']} bold]Login failed:[/] {e}")
        err_console.print(
            f"[{t['muted']}]Gmail tip: use an App Password (myaccount.google.com → Security → App Passwords).[/]"
        )
        return
    except Exception as e:
        err_console.print(f"[{t['danger']} bold]Connection error:[/] {e}")
        return

    # ── 3. List inbox ─────────────────────────────────────────────────────────
    _show_inbox_and_prompt(conn, folder, limit, t, bx, username)
    try:
        conn.logout()
    except Exception:
        pass


def _show_inbox_and_prompt(
    conn: imaplib.IMAP4_SSL,
    folder: str,
    limit: int,
    t: Dict[str, str],
    bx,
    username: str,
) -> None:
    """Fetch message list, print a table, then let user pick one to analyze."""
    # Search for all messages; most recent first
    status, data = conn.search(None, "ALL")
    if status != "OK" or not data or not data[0]:
        console.print(f"[{t['warning']}]No messages found in {folder}.[/]")
        return

    msg_ids = data[0].split()
    msg_ids = list(reversed(msg_ids))[:limit]   # newest first

    # Fetch headers only for performance
    tbl = Table(
        box=bx, border_style=t['primary'],
        title=f"[{t['primary']} bold]📬 {folder} — {username} ({len(msg_ids)} shown)[/]",
        show_lines=False,
    )
    tbl.add_column("#",      style=f"bold {t['accent']}", width=5, justify="right")
    tbl.add_column("From",   style=f"{t['text']}", max_width=30)
    tbl.add_column("Subject", style=f"bold {t['primary']}", max_width=42)
    tbl.add_column("Date",   style=t['muted'], width=20)
    tbl.add_column("Size",   style=t['muted'], width=8, justify="right")

    uid_map: Dict[int, bytes] = {}   # display-number → raw IMAP uid

    for display_num, uid in enumerate(msg_ids, 1):
        uid_map[display_num] = uid
        try:
            _, hdr_data = conn.fetch(uid, "(RFC822.SIZE BODY[HEADER.FIELDS (FROM SUBJECT DATE)])")
            if not hdr_data or not hdr_data[0]:
                continue
            raw_header = hdr_data[0][1] if isinstance(hdr_data[0], tuple) else b""
            size_str   = hdr_data[1].decode() if len(hdr_data) > 1 and isinstance(hdr_data[1], bytes) else "?"
            msg = _email_module.message_from_bytes(raw_header)

            from_val    = _decode_header_value(msg.get("From", "(unknown)"))[:30]
            subject_val = _decode_header_value(msg.get("Subject", "(no subject)"))[:42]
            date_val    = (msg.get("Date", ""))[:20]
            size_kb     = f"{int(size_str)//1024}KB" if size_str.strip().isdigit() else "-"
        except Exception:
            from_val, subject_val, date_val, size_kb = "(error)", "(error)", "", "-"

        tbl.add_row(str(display_num), from_val, subject_val, date_val, size_kb)

    console.print(tbl)
    console.print(
        f"[{t['muted']}]Enter a message number to analyze it, "
        f"[bold {t['accent']}]r[/] to refresh, or [bold {t['accent']}]q[/] to quit.[/]\n"
    )

    while True:
        t = get_theme()
        try:
            choice = console.input(f"[bold {t['primary']}]inbox[/][bold {t['secondary']}] ❯ [/]").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print(f"\n[{t['muted']}]Returning to main console.[/]")
            break

        if choice in ("q", "quit", "exit"):
            break
        elif choice == "r":
            _show_inbox_and_prompt(conn, folder, 20, t, bx, "")
            break
        elif choice.isdigit():
            num = int(choice)
            if num not in uid_map:
                console.print(f"[{t['danger']}]Invalid number. Enter 1–{len(uid_map)}.[/]")
                continue
            uid = uid_map[num]
            _fetch_and_analyze(conn, uid, t)
        else:
            console.print(f"[{t['muted']}]Type a number, [bold]r[/] to refresh, or [bold]q[/] to quit.[/]")


def _fetch_and_analyze(conn: imaplib.IMAP4_SSL, uid: bytes, t: Dict[str, str]) -> None:
    """Download the full RFC822 message, save to a temp .eml file, then analyze."""
    console.print(f"[{t['muted']}]Downloading full message...[/]")
    try:
        _, msg_data = conn.fetch(uid, "(RFC822)")
        if not msg_data or not msg_data[0]:
            console.print(f"[{t['danger']}]Could not fetch message body.[/]")
            return
        raw_eml: bytes = msg_data[0][1]
    except Exception as e:
        console.print(f"[{t['danger']} bold]Fetch error:[/] {e}")
        return

    # Parse subject for a meaningful filename
    try:
        parsed_hdr = _email_module.message_from_bytes(raw_eml[:4096])
        subject = _decode_header_value(parsed_hdr.get("Subject", "email"))
        safe_name = "".join(c if c.isalnum() or c in " -_" else "_" for c in subject)[:40].strip()
    except Exception:
        safe_name = "fetched_email"

    with tempfile.NamedTemporaryFile(
        suffix=".eml", prefix=f"sentinel_{safe_name}_", delete=False
    ) as tmp:
        tmp.write(raw_eml)
        tmp_path = tmp.name

    console.print(f"[{t['muted']}]Saved to temp file: {tmp_path}[/]")
    console.print(f"[{t['primary']} bold]Running Sentinel analysis...[/]\n")

    try:
        inv = analyze_file(tmp_path)
        print_investigation_report(inv.id)
    except Exception as e:
        console.print(f"[{t['danger']} bold]Analysis failed:[/] {e}")
    finally:
        try:
            Path(tmp_path).unlink()
        except Exception:
            pass


# -----------------------------------------------------------------------------
# INTERACTIVE TERMINAL SHELL
# -----------------------------------------------------------------------------

def run_interactive_mode():
    """High-tech interactive terminal shell."""
    console.clear()
    if not ACTIVE_CONFIG.get("_no_banner"):
        console.print(get_banner())

    t = get_theme()
    console.print(f"[{t['text']} bold]Type [{t['primary']}]help[/] for command reference or [{t['primary']}]samples[/] to analyze test emails.[/{t['text']} bold]\n")

    while True:
        t = get_theme()
        try:
            prompt = console.input(f"[bold {t['primary']}]sentinel[/][bold {t['secondary']}] ❯ [/]")
        except (KeyboardInterrupt, EOFError):
            console.print(f"\n[{t['accent']}]Exiting Sentinel Console. System Secured.[/{t['accent']}]")
            break

        prompt = prompt.strip()
        if not prompt:
            continue

        parts = prompt.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit", "quit", "q"):
            console.print(f"[{t['accent']}]Exiting Sentinel Console. System Secured.[/{t['accent']}]")
            break
        elif cmd in ("help", "?"):
            t_help = Table(box=get_box(), border_style=f"{t['primary']}", title=f"[{t['primary']} bold]Console Commands[/]")
            t_help.add_column("Command", style=f"bold {t['accent']}")
            t_help.add_column("Description", style=f"{t['text']}")
            t_help.add_row("analyze <file.eml> [--ai]", "Analyze an .eml email artifact with real-time pipeline")
            t_help.add_row("inbox [provider]",           "Connect to live inbox (gmail/outlook/yahoo…) and analyze emails")
            t_help.add_row("brain [status|train]",       "🧠 AI Brain: show ML status / accuracy / retrain model")
            t_help.add_row("list [limit] [verdict]",     "List historical investigations in formatted database table")
            t_help.add_row("status [--animate]",         "Open the SOC command dashboard")
            t_help.add_row("view <id_or_ext>",           "Open full forensic dashboard for an investigation")
            t_help.add_row("themes",                     "Show visual theme gallery with color palettes")
            t_help.add_row("theme <name>",               "Quick-switch active theme (e.g. theme matrix, theme dracula)")
            t_help.add_row("border <style>",             "Quick-switch border box style (rounded, double, heavy, minimal)")
            t_help.add_row("config [set key val]",       "View or edit persistent configurations")
            t_help.add_row("samples",                    "List sample .eml fixtures available for testing")
            t_help.add_row("clear",                      "Clear terminal screen and redraw banner")
            t_help.add_row("exit",                       "Quit interactive console")
            console.print(t_help)
        elif cmd == "clear":
            console.clear()
            if not ACTIVE_CONFIG.get("_no_banner"):
                console.print(get_banner())
        elif cmd == "themes":
            show_themes_showcase()
        elif cmd == "theme":
            if not args:
                show_themes_showcase()
            else:
                target = args[0].lower()
                if target in THEMES:
                    ACTIVE_CONFIG["theme"] = target
                    save_config(ACTIVE_CONFIG)
                    console.print(f"[{THEMES[target]['success']} bold]✓ Theme switched to [{THEMES[target]['accent']} bold]{THEMES[target]['name']}[/]")
                else:
                    console.print(f"[{t['danger']} bold]Error:[/] Unknown theme '{target}'. Choose from: {', '.join(THEMES.keys())}")
        elif cmd == "border":
            if not args:
                console.print(f"[{t['muted']}]Available borders: {', '.join(BOX_STYLES.keys())}[/]")
            else:
                target = args[0].lower()
                if target in BOX_STYLES:
                    ACTIVE_CONFIG["box_style"] = target
                    save_config(ACTIVE_CONFIG)
                    console.print(f"[{t['success']} bold]✓ Border style set to [{t['accent']} bold]{target}[/]")
                else:
                    console.print(f"[{t['danger']} bold]Error:[/] Invalid border style. Choose from: {', '.join(BOX_STYLES.keys())}")
        elif cmd == "config":
            class DummyArgs:
                action = args[0] if args else "list"
                key = args[1] if len(args) > 1 else None
                value = args[2] if len(args) > 2 else None
            handle_config_command(DummyArgs())
        elif cmd == "samples":
            fixtures_dir = API_ROOT / "app" / "tests" / "fixtures"
            if fixtures_dir.exists():
                t_samp = Table(box=get_box(), border_style=f"{t['accent']}", title=f"[{t['accent']} bold]Sample Email Fixtures[/]")
                t_samp.add_column("File Name", style=f"bold {t['primary']}")
                t_samp.add_column("Path", style=f"{t['muted']}")
                for file in sorted(fixtures_dir.glob("*.eml")):
                    t_samp.add_row(file.name, str(file.resolve()))
                console.print(t_samp)
                console.print(f"[{t['text']}]Try: [bold {t['primary']}]analyze {fixtures_dir / 'phishing-like.eml'}[/][/]\n")
            else:
                console.print(f"[{t['warning']}]No fixtures directory found.[/{t['warning']}]")
        elif cmd == "analyze":
            if not args:
                console.print(f"[{t['danger']} bold]Error:[/] Specify a path to an .eml file.")
                continue
            run_ai = "--ai" in args
            filepath = [a for a in args if not a.startswith("--")][0]
            try:
                inv = analyze_file(filepath, run_ai=run_ai)
                print_investigation_report(inv.id)
            except Exception as e:
                console.print(f"[{t['danger']} bold]Analysis Error:[/] {e}")
        elif cmd == "list":
            limit = int(args[0]) if args and args[0].isdigit() else 20
            verdict = args[1] if len(args) > 1 else None
            list_investigations(limit=limit, verdict=verdict)
        elif cmd in ("status", "dashboard"):
            show_status_dashboard(animate="--animate" in args)
        elif cmd == "view":
            if not args:
                console.print(f"[{t['danger']} bold]Error:[/] Please specify an investigation ID (e.g. view INV-38907AE8)")
                continue
            print_investigation_report(args[0])
        elif cmd == "inbox":
            # Build a minimal args-like object for run_inbox_command
            class _InboxArgs:
                provider = args[0] if args else None
                host     = None
                port     = 993
                user     = None
                folder   = "INBOX"
                limit    = 20
            run_inbox_command(_InboxArgs())
        elif cmd == "brain":
            action = args[0] if args else "status"
            if action == "download":
                _run_brain_download()
            else:
                handle_brain_command(action)
        elif cmd in ("explain",):
            class _ExplainArgs:
                file = args[0] if args else None
                inv  = None
                top  = 10
            if _ExplainArgs.file:
                _run_explain_command(_ExplainArgs())
            else:
                console.print(f"[{t['warning']}]Usage: explain <file.eml>[/]")
        elif cmd == "watch":
            class _WatchArgs:
                folder     = args[0] if args else "."
                alert_only = args[1] if len(args) > 1 else None
                recursive  = False
                sound      = False
            _run_watch_command(_WatchArgs())
        else:
            console.print(f"[{t['danger']}]Unknown command: '{cmd}'. Type [{t['primary']}]help[/{t['primary']}] for available commands.[/{t['danger']}]")


# -----------------------------------------------------------------------------
# MAIN CLI ENTRYPOINT
# -----------------------------------------------------------------------------



# -----------------------------------------------------------------------------
# BRAIN DOWNLOAD HANDLER
# -----------------------------------------------------------------------------

def _run_brain_download() -> None:
    """Download real phishing/ham corpora for brain training."""
    t = get_theme(); bx = get_box()
    console.print(Panel(
        f"[{t['primary']} bold]🧠 Brain — Real Corpus Download[/]\n\n"
        f"Downloading public email corpora:\n"
        f"  • SpamAssassin Public Corpus (ham + spam, ~6 000 emails)\n"
        f"  • Enron Ham Corpus (~30 000 emails)\n\n"
        f"[{t['muted']}]Files cached to apps/api/app/brain/training/corpus_cache/[/]",
        title=f"[{t['primary']} bold]Corpus Downloader[/]",
        border_style=t["primary"], box=bx,
    ))

    from app.brain.training.download_corpus import download_all, corpus_size

    with Progress(
        SpinnerColumn(style=t["primary"]),
        TextColumn(f"[{t['text']}]{{task.description}}"),
        TimeElapsedColumn(),
        console=console, transient=False,
    ) as prog:
        task = prog.add_task("Downloading SpamAssassin + Enron corpora…", total=None)
        try:
            stats = download_all(quick=False, verbose=False)
            prog.update(task, description="[bold green]Download complete![/]")
        except Exception as e:
            prog.stop()
            err_console.print(f"[{t['danger']} bold]Download failed:[/] {e}")
            return

    size = corpus_size()
    console.print(f"\n[{t['success']} bold]✓ Corpus ready![/]")
    console.print(f"  Ham emails : [{t['accent']}]{size['ham']}[/]")
    console.print(f"  Spam emails: [{t['accent']}]{size['spam']}[/]")
    console.print(f"  Errors     : [{t['warning']}]{len(stats.errors)}[/]")
    if stats.errors:
        for err in stats.errors[:3]:
            console.print(f"    [{t['muted']}]- {err}[/]")
    console.print(f"\n[{t['muted']}]Now run: ./sentinel brain train  to retrain with real data.[/]")


# -----------------------------------------------------------------------------
# EXPLAIN COMMAND HANDLER
# -----------------------------------------------------------------------------

def _run_explain_command(args) -> None:
    """Explain WHY the brain gave a verdict — feature importances + rule signals."""
    t = get_theme(); bx = get_box()
    from app.brain.explainer import explain
    from app.services.email_parser.parser import parse_email

    # Resolve source
    if getattr(args, "file", None):
        eml_path = Path(args.file).expanduser().resolve()
        if not eml_path.exists():
            err_console.print(f"[{t['danger']}]File not found: {eml_path}[/]")
            return
        console.print(f"[{t['primary']} bold]🔍 Explaining:[/] {eml_path.name}")
        with open(eml_path, "rb") as f:
            raw = f.read()
        parsed = parse_email(raw)
        inv_id = None
    else:
        # Load from DB artifact
        inv_id = args.inv
        console.print(f"[{t['primary']} bold]🔍 Explaining investigation:[/] {inv_id}")
        db = SessionLocal()
        try:
            from app.api.routes.investigations import get_investigation_or_404
            inv = get_investigation_or_404(db, inv_id)
            artifact_path = Path(storage.get_path(inv.artifact_id)) if hasattr(inv, "artifact_id") else None
            if artifact_path and artifact_path.exists():
                raw = artifact_path.read_bytes()
                parsed = parse_email(raw)
            else:
                err_console.print(f"[{t['danger']}]Artifact not found for {inv_id}[/]")
                return
        finally:
            db.close()

    with Progress(SpinnerColumn(style=t["primary"]),
                  TextColumn(f"[{t['text']}]Running explainer…"),
                  console=console, transient=True) as prog:
        prog.add_task("", total=None)
        report = explain(parsed, investigation_id=inv_id, top_n=getattr(args, "top", 10))

    # ── Verdict banner ───────────────────────────────────────────────────
    verdict_colour = {"MALICIOUS": t["danger"], "PHISHING": t["danger"],
                      "SUSPICIOUS": t["warning"], "BENIGN": t["success"]}.get(report.verdict, t["text"])
    console.print(Panel(
        f"[bold]Verdict:[/]    [{verdict_colour} bold]{report.verdict}[/]  "
        f"(score {report.risk_score}/100, {report.confidence} confidence)\n"
        f"[bold]ML Model:[/]   {report.ml_label} @ {report.ml_confidence:.0%}\n"
        f"[bold]Narrative:[/]  [{t['muted']}]{report.narrative}[/]",
        title=f"[{t['primary']} bold]🧠 Brain Explanation Report[/]",
        border_style=verdict_colour, box=bx,
    ))

    # ── Top features table ───────────────────────────────────────────────
    feat_tbl = Table(box=bx, border_style=t["primary"], title=f"[{t['accent']}]Top Feature Importances[/]")
    feat_tbl.add_column("Rank", style=f"bold {t['muted']}", width=5)
    feat_tbl.add_column("Feature",     style=f"bold {t['accent']}", width=30)
    feat_tbl.add_column("Value",       style=t["text"],    width=8)
    feat_tbl.add_column("Importance",  style=t["text"],    width=12)
    feat_tbl.add_column("Direction",   style=t["text"],    width=14)
    feat_tbl.add_column("Description", style=t["muted"])
    for i, f in enumerate(report.top_features, 1):
        dir_colour = {"increases_risk": t["danger"], "decreases_risk": t["success"],
                      "neutral": t["muted"]}.get(f.direction, t["muted"])
        dir_icon   = {"increases_risk": "▲ risk", "decreases_risk": "▼ safe", "neutral": "— n/a"}.get(f.direction)
        feat_tbl.add_row(
            str(i),
            f.name,
            f"{f.value:.3f}",
            f"{f.importance:.5f}",
            f"[{dir_colour}]{dir_icon}[/]",
            f.description,
        )
    console.print(feat_tbl)

    # ── ML probabilities ─────────────────────────────────────────────────
    prob_tbl = Table(box=bx, border_style=t["primary"], title=f"[{t['accent']}]ML Class Probabilities[/]",
                     show_header=False)
    prob_tbl.add_column("Class", style=f"bold {t['accent']}", width=14)
    prob_tbl.add_column("Bar",   style=t["text"], width=40)
    prob_tbl.add_column("Prob",  style=t["text"])
    for cls, prob in sorted(report.raw_proba.items(), key=lambda x: -x[1]):
        bar_len = int(prob * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        cls_colour = {"MALICIOUS": t["danger"], "PHISHING": t["danger"],
                      "SUSPICIOUS": t["warning"], "BENIGN": t["success"]}.get(cls, t["text"])
        prob_tbl.add_row(f"[{cls_colour}]{cls}[/]", bar, f"{prob:.4f}")
    console.print(prob_tbl)

    # ── Rule engine signals ──────────────────────────────────────────────
    if report.top_rules:
        rule_tbl = Table(box=bx, border_style=t["primary"],
                         title=f"[{t['accent']}]Top Rule Engine Signals[/]")
        rule_tbl.add_column("Rule ID",   style=f"bold {t['accent']}", width=10)
        rule_tbl.add_column("Severity",  style=t["text"],             width=10)
        rule_tbl.add_column("Points",    style=t["text"],             width=8)
        rule_tbl.add_column("Type",      style=t["muted"],            width=14)
        rule_tbl.add_column("Description", style=t["muted"])
        for r in report.top_rules:
            sev_colour = {"CRITICAL": t["danger"], "HIGH": t["danger"],
                          "MEDIUM": t["warning"], "LOW": t["muted"]}.get(r.severity, t["text"])
            rule_tbl.add_row(r.rule_id, f"[{sev_colour}]{r.severity}[/]",
                             f"+{r.points}", r.signal_type, r.description[:80])
        console.print(rule_tbl)


# -----------------------------------------------------------------------------
# WATCH COMMAND HANDLER
# -----------------------------------------------------------------------------

def _run_watch_command(args) -> None:
    """Start real-time folder watching."""
    t = get_theme()
    alert_only = None
    if getattr(args, "alert_only", None):
        alert_only = {v.strip().upper() for v in args.alert_only.split(",")}

    from app.watch import run_watch
    run_watch(
        folder     = args.folder,
        alert_only = alert_only,
        theme      = t,
        sound      = getattr(args, "sound", False),
        recursive  = getattr(args, "recursive", False),
    )


def main():
    # Shared theme/border args added to every subcommand that renders UI
    def _add_ui_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--theme", choices=list(THEMES.keys()), help="Override UI theme for this run")
        p.add_argument("--border", choices=list(BOX_STYLES.keys()), help="Override border style for this run")

    parser = argparse.ArgumentParser(
        description="SENTINEL - Email Threat Detection, Geolocation & Forensic Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_ui_args(parser)
    parser.add_argument("--no-banner", action="store_true", help="Suppress the startup banner")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze an .eml email file")
    analyze_parser.add_argument("file", help="Path to the .eml file to analyze")
    analyze_parser.add_argument("--ai", action="store_true", help="Run AI multi-agent enrichment")
    analyze_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    analyze_parser.add_argument("--export", help="Export full visual report to HTML file path")
    _add_ui_args(analyze_parser)

    # list command
    list_parser = subparsers.add_parser("list", help="List stored investigations")
    list_parser.add_argument("-n", "--limit", type=int, default=20, help="Number of records to show")
    list_parser.add_argument("-v", "--verdict", help="Filter by verdict (malicious, suspicious, benign)")
    list_parser.add_argument("-s", "--status", help="Filter by status (completed, pending)")
    _add_ui_args(list_parser)

    # status command
    status_parser = subparsers.add_parser("status", aliases=["dashboard"], help="Open the terminal SOC command dashboard")
    status_parser.add_argument("--animate", action="store_true", help="Play the startup telemetry animation")
    _add_ui_args(status_parser)

    # view command
    view_parser = subparsers.add_parser("view", help="View full forensic details of an investigation")
    view_parser.add_argument("id", help="Investigation ID or External ID (e.g. INV-38907AE8)")
    view_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    view_parser.add_argument("--export", help="Export full visual report to HTML file path")
    _add_ui_args(view_parser)

    # themes command
    subparsers.add_parser("themes", help="Showcase all visual color themes")

    # config command
    config_parser = subparsers.add_parser("config", help="Manage Sentinel configuration")
    config_parser.add_argument("action", nargs="?", default="list", choices=["list", "show", "set"], help="Action to perform")
    config_parser.add_argument("key", nargs="?", help="Configuration key to set")
    config_parser.add_argument("value", nargs="?", help="Configuration value")

    # interactive command
    subparsers.add_parser("interactive", help="Start interactive terminal shell")

    # server command
    server_parser = subparsers.add_parser("serve", help="Start FastAPI backend server")
    server_parser.add_argument("--host", default="0.0.0.0", help="Host address to bind")
    server_parser.add_argument("--port", type=int, default=8000, help="Port to listen on")

    # inbox command
    inbox_parser = subparsers.add_parser("inbox", help="Connect to your email inbox and analyze live emails")
    inbox_parser.add_argument(
        "--provider", choices=list(IMAP_PRESETS.keys()),
        help="Email provider shortcut (gmail, outlook, yahoo, apple, zoho, custom)",
    )
    inbox_parser.add_argument("--host",    help="Custom IMAP hostname (overrides --provider)")
    inbox_parser.add_argument("--port",    type=int, default=993, help="IMAP port (default 993 SSL)")
    inbox_parser.add_argument("--user",    help="Email address / IMAP username")
    inbox_parser.add_argument("--folder",  default="INBOX", help="Mailbox folder to open (default INBOX)")
    inbox_parser.add_argument("-n", "--limit", type=int, default=20, help="Number of recent emails to show")
    _add_ui_args(inbox_parser)

    # brain command — extend to include download action
    brain_parser = subparsers.add_parser("brain", help="AI Brain: ML status, training, threat memory, explain")
    brain_parser.add_argument("action", nargs="?", default="status",
                              choices=["status", "train", "retrain", "download"],
                              help="Action: status | train | retrain | download (fetch real training data)")
    brain_parser.add_argument("--inv", dest="inv_id", default=None,
                              help="Investigation ID for 'explain' action")
    _add_ui_args(brain_parser)

    # explain command
    explain_parser = subparsers.add_parser("explain", help="Explain WHY the brain flagged an email or investigation")
    explain_grp = explain_parser.add_mutually_exclusive_group(required=True)
    explain_grp.add_argument("--file", "-f", help="Path to .eml file to explain")
    explain_grp.add_argument("--inv",  "-i", help="Investigation ID (e.g. INV-38907AE8) to explain")
    explain_parser.add_argument("--top", type=int, default=10, help="Number of top features to show (default 10)")
    _add_ui_args(explain_parser)

    # watch command
    watch_parser = subparsers.add_parser("watch", help="Watch a folder and auto-analyze any .eml dropped in it")
    watch_parser.add_argument("folder", help="Folder path to watch")
    watch_parser.add_argument("--alert-only", dest="alert_only", default=None,
                              help="Only show alerts for these verdicts (e.g. PHISHING,MALICIOUS)")
    watch_parser.add_argument("--recursive", "-r", action="store_true",
                              help="Also watch subdirectories")
    watch_parser.add_argument("--sound",     "-s", action="store_true",
                              help="Ring terminal bell on threat detection")
    _add_ui_args(watch_parser)

    args = parser.parse_args()

    # Apply runtime CLI overrides
    if args.theme:
        ACTIVE_CONFIG["theme"] = args.theme
    if args.border:
        ACTIVE_CONFIG["box_style"] = args.border
    if args.no_banner:
        ACTIVE_CONFIG["_no_banner"] = True

    if not args.command or args.command == "interactive":
        run_interactive_mode()
    elif args.command == "themes":
        show_themes_showcase()
    elif args.command == "config":
        handle_config_command(args)
    elif args.command == "brain":
        action = getattr(args, "action", "status")
        if action == "download":
            _run_brain_download()
        else:
            handle_brain_command(action)
    elif args.command == "explain":
        _run_explain_command(args)
    elif args.command == "watch":
        _run_watch_command(args)
    elif args.command == "analyze":
        try:
            inv = analyze_file(args.file, run_ai=args.ai)
            print_investigation_report(inv.id, json_output=args.json, export_path=args.export)
        except Exception as e:
            t = get_theme()
            err_console.print(f"[{t['danger']} bold]Analysis failed:[/] {e}")
            sys.exit(1)
    elif args.command == "list":
        list_investigations(limit=args.limit, verdict=args.verdict, status=args.status)
    elif args.command in ("status", "dashboard"):
        show_status_dashboard(animate=args.animate)
    elif args.command == "view":
        print_investigation_report(args.id, json_output=args.json, export_path=args.export)
    elif args.command == "inbox":
        run_inbox_command(args)
    elif args.command == "serve":
        import uvicorn
        t = get_theme()
        console.print(f"[{t['primary']} bold]Starting Sentinel API on http://{args.host}:{args.port}...[/]")
        uvicorn.run("app.main:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
