"""Centralized rate limiting for SENTINEL API using slowapi."""

from __future__ import annotations

import logging
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from app.core.config import settings

logger = logging.getLogger(__name__)


def rate_limit_key_func(request: Request) -> str:
    """Derive rate-limit key from authenticated token or remote IP address."""
    auth_header = request.headers.get("authorization") or request.headers.get("x-api-key")
    if auth_header:
        return f"auth:{auth_header[:32]}"
    return get_remote_address(request) or "127.0.0.1"


# Configure storage: Use Redis when available and not mock, fallback to in-memory
storage_uri = "memory://"
if settings.REDIS_URL and not settings.DEMO_MODE:
    try:
        storage_uri = settings.REDIS_URL
    except Exception as exc:
        logger.warning("Failed to configure Redis for rate limiting, falling back to memory: %s", exc)

limiter = Limiter(
    key_func=rate_limit_key_func,
    default_limits=[settings.RATE_LIMIT_DEFAULT] if settings.RATE_LIMIT_ENABLED else [],
    storage_uri=storage_uri,
    enabled=settings.RATE_LIMIT_ENABLED,
)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """Return compliant 429 Too Many Requests response with Retry-After header."""
    retry_after = "60"
    if hasattr(exc, "detail") and exc.detail:
        detail_msg = f"Rate limit exceeded: {exc.detail}"
    else:
        detail_msg = "Rate limit exceeded. Please retry later."

    return JSONResponse(
        status_code=429,
        content={
            "error": detail_msg,
            "code": "RATE_LIMIT_EXCEEDED",
            "request_id": getattr(request.state, "request_id", None),
        },
        headers={"Retry-After": retry_after},
    )


__all__ = ["limiter", "rate_limit_exceeded_handler"]
