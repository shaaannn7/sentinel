"""Static attachment metadata checks. Attachments are never executed or unpacked."""

import os
from app.services.email_parser.models import ParsedEmail
from app.services.analysis.models import AnalyzerResult, EvidenceItem, FindingDraft
from app.services.analysis.evidence import evidence

EXECUTABLE = {"exe", "com", "bat", "cmd", "dll", "msi", "scr", "vbs", "js", "jse", "wsf", "ps1", "jar", "hta", "lnk"}
MIME_EXT = {"pdf": {"application/pdf"}, "png": {"image/png"}, "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"},
            "zip": {"application/zip", "application/x-zip-compressed"}, "exe": {"application/octet-stream", "application/x-msdownload"}}


def analyze(parsed: ParsedEmail) -> AnalyzerResult:
    result = AnalyzerResult(stage="ATTACHMENT_ANALYSIS")
    data = []
    for attachment in parsed.attachments:
        filename = attachment.filename.lower()
        ext = (attachment.extension or "").lower()
        ev = evidence(EvidenceItem("ATTACHMENT", "attachment metadata", attachment.filename,
                                   f"Observed attachment {attachment.filename} ({attachment.mime_type}, {attachment.size} bytes).",
                                   {"sha256": attachment.sha256, "mime_type": attachment.mime_type, "magic_bytes": attachment.magic_bytes}))
        hash_ev = evidence(EvidenceItem("ATTACHMENT", "SHA-256", attachment.sha256,
                                        f"SHA-256 for attachment {attachment.filename}."))
        result.evidence.extend([ev, hash_ev])
        if ext in EXECUTABLE:
            result.findings.append(FindingDraft("HIGH", "ATTACHMENT", "Executable extension detected in attachment filename.",
                f"The attachment filename ends with .{ext}; no execution was performed.", [ev], "attachments", 20, "HIGH"))
        if filename.count(".") >= 2 and ext in EXECUTABLE:
            result.findings.append(FindingDraft("MEDIUM", "ATTACHMENT", "Double extension observed in attachment filename.",
                "The attachment uses multiple extensions, a common deceptive naming pattern.", [ev], "attachments", 15))
        expected = MIME_EXT.get(ext)
        if expected and attachment.mime_type not in expected:
            result.findings.append(FindingDraft("MEDIUM", "ATTACHMENT", "Attachment extension and MIME type differ.",
                f"The .{ext} extension does not match observed MIME type {attachment.mime_type}.", [ev], "attachments", 8))
        if not ext:
            result.findings.append(FindingDraft("INFO", "ATTACHMENT", "Attachment has no file extension.",
                "An attachment without an extension was observed.", [ev], "attachments", 1))
        data.append({"filename": attachment.filename, "sha256": attachment.sha256, "mime_type": attachment.mime_type, "size": attachment.size})
    result.data = {"attachments": data}
    return result
