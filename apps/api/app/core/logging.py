"""Structured and sanitized logging for SENTINEL."""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

# Patterns matching sensitive keys or bearer credentials in text
_SENSITIVE_KEY_RE = re.compile(
    r'(?i)(api[_-]?key|secret|password|auth[_-]?token|authorization)["\']?\s*[:=]\s*["\']?([^"\'\s,;]+)',
)
_BEARER_RE = re.compile(
    r'(?i)\b(bearer)\s+([a-zA-Z0-9_\-\.]+)',
)


class SanitizingFilter(logging.Filter):
    """Redact passwords, API keys, and authorization tokens from all log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _SENSITIVE_KEY_RE.sub(r'\1: [REDACTED]', record.msg)
            record.msg = _BEARER_RE.sub(r'\1 [REDACTED]', record.msg)
        if record.args:
            if isinstance(record.args, dict):
                clean_args = {}
                for k, v in record.args.items():
                    if any(term in str(k).lower() for term in ("key", "secret", "password", "token", "auth")):
                        clean_args[k] = "[REDACTED]"
                    else:
                        clean_args[k] = v
                record.args = clean_args
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    "[REDACTED]" if any(term in str(arg).lower() for term in ("bearer ", "key=")) else arg
                    for arg in record.args
                )
        return True


class JSONFormatter(logging.Formatter):
    """Emit structured JSON log entries for log collectors."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "request_id"):
            log_obj["request_id"] = getattr(record, "request_id")
        if hasattr(record, "investigation_id"):
            log_obj["investigation_id"] = getattr(record, "investigation_id")
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def setup_logging(log_level: str = "INFO", json_format: bool = False) -> None:
    """Configure sanitized logging with optional JSON output."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicate log outputs
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(SanitizingFilter())

    if json_format:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )

    root_logger.addHandler(handler)


logger = logging.getLogger("sentinel")

__all__ = ["logger", "setup_logging", "SanitizingFilter", "JSONFormatter"]
