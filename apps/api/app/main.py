"""FastAPI entry point for SENTINEL backend with defense-in-depth hardening."""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.api.routes import brain, health, investigations
from app.core.config import settings
from app.core.limiter import limiter, rate_limit_exceeded_handler
from app.core.logging import setup_logging
from app.db.base import Base
from app.db.session import engine
from app.services.artifact_storage import LocalArtifactStorage

setup_logging(log_level="INFO")
logger = logging.getLogger("sentinel.app")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Verify/create DB schema
    Base.metadata.create_all(bind=engine)
    logger.info("SENTINEL backend initialized successfully (score_version=%s)", settings.SCORE_VERSION)
    yield


app = FastAPI(
    title="SENTINEL API",
    version="0.1.0",
    description="Evidence-first email threat detection and forensic investigation platform",
    lifespan=lifespan,
)

# Attach state for slowapi
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

storage = LocalArtifactStorage()

# Restrictive CORS configuration
cors_origins = [
    origin.strip()
    for origin in settings.CORS_ORIGINS.split(",")
    if origin.strip() and origin.strip() != "*"
]
if not cors_origins and settings.DEMO_MODE:
    cors_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Request-ID"],
)


@app.middleware("http")
async def request_context_and_security_headers(request: Request, call_next):
    # 1. Attach or propagate unique request ID
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = req_id

    # 2. Process request
    response: Response = await call_next(request)

    # 3. Apply defensive security response headers
    response.headers["X-Request-ID"] = req_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
    )
    response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Sanitize unexpected server exceptions to prevent internal information leakage."""
    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.exception("unhandled_server_error request_id=%s path=%s exc=%s", req_id, request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "An internal server error occurred while processing the request",
            "code": "INTERNAL_SERVER_ERROR",
            "request_id": req_id,
        },
    )


app.include_router(health.router)
app.include_router(investigations.router)
app.include_router(brain.router)

__all__ = ["app", "storage"]