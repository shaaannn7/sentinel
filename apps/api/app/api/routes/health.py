from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.db.session import engine
from app.core.config import settings

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """Liveness probe — confirms the API process is up."""
    return {"status": "ok"}


@router.get("/ready")
async def readiness_check(response: Response):
    """Readiness probe — verifies required dependencies are reachable."""
    result = {"status": "ok", "db": "unknown", "redis": "unknown"}

    # Database check
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        result["db"] = "ok"
    except Exception:
        result["db"] = "unavailable"

    # Redis check (best-effort — with strict 2-second timeout to prevent probe hangs)
    try:
        import redis  # type: ignore
        client = redis.from_url(
            settings.REDIS_URL,
            socket_timeout=2.0,
            socket_connect_timeout=2.0,
        )
        client.ping()
        result["redis"] = "ok"
    except Exception:
        result["redis"] = "unavailable"

    if result["db"] != "ok":
        result["status"] = "degraded"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result
