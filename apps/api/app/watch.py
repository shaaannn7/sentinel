"""
SENTINEL — Watch Mode
======================
Monitors a folder for new .eml files and automatically analyzes them.

Usage
-----
  ./sentinel watch ~/Downloads/emails/
  ./sentinel watch /var/mail/suspicious/ --alert-only PHISHING,MALICIOUS
  ./sentinel watch . --theme cyberpunk --sound

Features
--------
  • Real-time folder monitoring via watchdog inotify
  • Instant Rich notification panel on new file detection
  • Full brain + deterministic analysis pipeline
  • Alert filtering (only show PHISHING or MALICIOUS if --alert-only)
  • Live statistics panel (total analyzed, threats found, safe count)
  • Optional sound bell on threat detection
  • Graceful Ctrl+C exit with summary
"""

from __future__ import annotations

import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Set, Optional

# ── Rich imports ─────────────────────────────────────────────────────────────
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()
err_console = Console(stderr=True)


class WatchStats:
    def __init__(self):
        self.total     = 0
        self.threats   = 0
        self.safe      = 0
        self.suspicious = 0
        self.lock       = threading.Lock()

    def record(self, verdict: str):
        with self.lock:
            self.total += 1
            if verdict in ("PHISHING", "MALICIOUS"):
                self.threats += 1
            elif verdict == "SUSPICIOUS":
                self.suspicious += 1
            else:
                self.safe += 1


def run_watch(
    folder:     str | Path,
    alert_only: Set[str] | None = None,
    theme:      dict | None     = None,
    sound:      bool            = False,
    recursive:  bool            = False,
):
    """
    Start watching a folder. Blocks until Ctrl+C.

    Parameters
    ----------
    folder     : directory to watch
    alert_only : only print results for these verdicts (e.g. {"PHISHING","MALICIOUS"})
    theme      : Rich color theme dict (from get_theme())
    sound      : ring terminal bell on threat detection
    recursive  : watch subdirectories too
    """
    from watchdog.observers import Observer
    from watchdog.events    import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent

    watch_path = Path(folder).expanduser().resolve()
    if not watch_path.is_dir():
        err_console.print(f"[bold red]Error:[/] '{watch_path}' is not a directory.")
        sys.exit(1)

    t = theme or _default_theme()
    bx = box.ROUNDED
    stats = WatchStats()
    seen: Set[str] = set()   # avoid double-processing on some filesystems

    _print_watch_banner(watch_path, alert_only, t, bx)

    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if not isinstance(event, FileCreatedEvent):
                return
            _handle_new_file(Path(event.src_path), stats, seen, alert_only, t, bx, sound)

        def on_moved(self, event):
            if not isinstance(event, FileMovedEvent):
                return
            _handle_new_file(Path(event.dest_path), stats, seen, alert_only, t, bx, sound)

    observer = Observer()
    observer.schedule(Handler(), str(watch_path), recursive=recursive)
    observer.start()

    console.print(
        f"[{t['success']}]Watching[/] [{t['accent']}]{watch_path}[/] "
        f"[{t['muted']}](Press Ctrl+C to stop)[/]\n"
    )

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        _print_watch_summary(stats, t, bx)


def _handle_new_file(
    path:       Path,
    stats:      WatchStats,
    seen:       Set[str],
    alert_only: Set[str] | None,
    t:          dict,
    bx,
    sound:      bool,
):
    if path.suffix.lower() != ".eml":
        return
    key = str(path)
    if key in seen:
        return
    seen.add(key)

    # Small delay to let the file finish writing
    time.sleep(0.3)
    if not path.exists():
        return

    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")

    try:
        verdict, risk_score, confidence, explanation, elapsed = _analyse_file(path)
    except Exception as exc:
        console.print(
            f"[{t['muted']}][{ts}][/] [{t['danger']}]ERROR[/] {path.name}: {exc}"
        )
        return

    stats.record(verdict)

    # Filter if alert_only is set
    if alert_only and verdict not in alert_only:
        console.print(
            f"[{t['muted']}][{ts}] {path.name} → {verdict} (score {risk_score}) — suppressed[/]"
        )
        return

    # Colour the verdict
    verdict_colour = {
        "MALICIOUS":  t["danger"],
        "PHISHING":   t["danger"],
        "SUSPICIOUS": t["warning"],
        "BENIGN":     t["success"],
    }.get(verdict, t["text"])

    # Emoji badge
    badge = {
        "MALICIOUS":  "☣  MALICIOUS",
        "PHISHING":   "🎣 PHISHING",
        "SUSPICIOUS": "⚠  SUSPICIOUS",
        "BENIGN":     "✓  BENIGN",
    }.get(verdict, verdict)

    panel_content = (
        f"[bold]File:[/]    {path.name}\n"
        f"[bold]Verdict:[/] [{verdict_colour} bold]{badge}[/]\n"
        f"[bold]Score:[/]   {risk_score}/100  [{t['muted']}]({confidence} confidence)[/]\n"
        f"[bold]Brain:[/]   [{t['muted']}]{explanation[:120]}{'…' if len(explanation) > 120 else ''}[/]\n"
        f"[bold]Time:[/]    {elapsed}ms"
    )

    console.print(Panel(
        panel_content,
        title=f"[{t['primary']}][{ts}] New Email Detected[/]",
        border_style=verdict_colour if verdict in ("MALICIOUS", "PHISHING") else t["primary"],
        box=bx,
    ))

    # Sound bell on threat
    if sound and verdict in ("MALICIOUS", "PHISHING"):
        console.bell()

    # Live stats line
    console.print(
        f"  [{t['muted']}]Stats → Total: {stats.total}  "
        f"[{t['danger']}]Threats: {stats.threats}[/]  "
        f"[{t['warning']}]Suspicious: {stats.suspicious}[/]  "
        f"[{t['success']}]Safe: {stats.safe}[/][/]\n"
    )


def _analyse_file(path: Path):
    """Run the full brain pipeline on an .eml file. Returns (verdict, score, confidence, explanation, elapsed_ms)."""
    import time as _time
    from app.services.email_parser.parser import parse_email
    from app.services.scoring.engine      import calculate
    from app.brain.orchestrator           import Brain

    t0  = _time.perf_counter()
    raw = path.read_bytes()
    parsed  = parse_email(raw)
    score   = calculate([], 0, parsed)
    result  = Brain.analyse(parsed, score, persist_memory=True)
    elapsed = int((_time.perf_counter() - t0) * 1000)
    return result.verdict, result.risk_score, result.confidence, result.explanation, elapsed


def _print_watch_banner(path, alert_only, t, bx):
    title = f"[{t['primary']} bold]👁  SENTINEL Watch Mode[/]"
    body  = (
        f"[bold]Watching:[/]    [{t['accent']}]{path}[/]\n"
        f"[bold]Filter:[/]      "
        + (f"[{t['warning']}]{', '.join(sorted(alert_only))}[/]" if alert_only else f"[{t['success']}]All verdicts[/]")
        + f"\n[bold]Action:[/]      Analyze every new .eml file automatically\n"
        f"[{t['muted']}]Drop .eml files into the folder and Sentinel will analyze them in real-time.[/]"
    )
    console.print(Panel(body, title=title, border_style=t["primary"], box=bx))


def _print_watch_summary(stats, t, bx):
    console.print()
    tbl = Table(box=bx, border_style=t["primary"], show_header=False)
    tbl.add_column("", style=f"bold {t['accent']}", width=18)
    tbl.add_column("", style=t["text"])
    tbl.add_row("Total analyzed",  str(stats.total))
    tbl.add_row("☣  Threats",      f"[{t['danger']} bold]{stats.threats}[/]")
    tbl.add_row("⚠  Suspicious",   f"[{t['warning']}]{stats.suspicious}[/]")
    tbl.add_row("✓  Safe",         f"[{t['success']}]{stats.safe}[/]")
    console.print(Panel(tbl, title=f"[{t['primary']} bold]Watch Session Summary[/]",
                        border_style=t["primary"], box=bx))


def _default_theme() -> dict:
    """Minimal theme fallback if called outside CLI context."""
    return {
        "primary": "cyan",  "accent": "bright_cyan", "text": "white",
        "success": "green", "warning": "yellow",      "danger": "red",
        "muted":   "bright_black",
    }
