"""Attachment extraction with security checks."""

import os
import re
import hashlib
from email.message import Message

from app.services.email_parser.models import Attachment


# Magic byte signatures
_MAGIC = {
    b"\x4d\x5a": "PE",
    b"\x7f\x45\x4c\x46": "ELF",
    b"PK\x03\x04": "ZIP",
    b"PK\x05\x06": "ZIP_EMPTY",
    b"\x1f\x8b": "GZIP",
    b"%PDF": "PDF",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF87",
    b"GIF89a": "GIF89",
    b"\xff\xd8\xff": "JPEG",
    b"<?xml": "XML",
    b"<html": "HTML",
    b"#!/": "SCRIPT",
    b"<svg": "SVG",
    b"MZ": "DOS",
}


# Suspicious extensions / magic combos
_SUSPICIOUS_EXT = {
    "exe", "bat", "cmd", "com", "cpl", "dll", "msi", "msp", "scr", "vbs", "js",
    "jse", "wsf", "wsh", "ps1", "psm1", "jar", "hta", "scr", "lnk", "reg",
    "html", "htm", "svg", "iso", "img", "vhd",
}


def _safe_filename(name: str) -> str:
    """Strip path components and shell metacharacters."""
    if not name:
        return "attachment"
    base = os.path.basename(name)
    clean = re.sub(r"[^a-zA-Z0-9.\-_]", "_", base)
    if not clean or clean.startswith("."):
        clean = "attachment"
    return clean[:200]


def _detect_magic(data: bytes) -> str | None:
    """Detect file type from first bytes."""
    for sig, name in _MAGIC.items():
        if data.startswith(sig):
            return name
    return None


def _extension(name: str) -> str:
    """Return lowercased extension without dot."""
    _, ext = os.path.splitext(name)
    return ext.lstrip(".").lower()


def extract_attachments(msg: Message) -> list[Attachment]:
    """Walk the message and extract attachment metadata.

    Attachments are NEVER executed. We only compute metadata (size, hash, magic).
    """
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()
        # Treat as attachment if disposition explicitly says so OR filename is present and not text/*
        if "attachment" in disposition or (filename and part.get_content_maintype() != "text"):
            payload = part.get_payload(decode=True) or b""
            if not filename:
                filename = "part.bin"
            safe_name = _safe_filename(filename)
            ext = _extension(safe_name)
            sha256 = hashlib.sha256(payload).hexdigest()
            magic = _detect_magic(payload[:16]) if payload else None
            suspicious = ext in _SUSPICIOUS_EXT or magic in {"PE", "ELF", "DOS", "SCRIPT", "SVG", "HTML"}

            out.append(Attachment(
                filename=safe_name,
                mime_type=part.get_content_type(),
                size=len(payload),
                sha256=sha256,
                extension=ext or None,
                is_suspicious=suspicious,
                magic_bytes=magic,
            ))
    return out
