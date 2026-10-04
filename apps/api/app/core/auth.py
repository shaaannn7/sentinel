import secrets
from fastapi import Header, HTTPException, status

from app.core.config import settings


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Require the configured API key when authentication is enabled."""
    if settings.API_AUTH_KEY and not secrets.compare_digest(x_api_key or "", settings.API_AUTH_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
