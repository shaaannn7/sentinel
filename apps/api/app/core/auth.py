"""Centralized authentication and role-based authorization for SENTINEL."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Literal, Optional

from fastapi import Depends, Header, HTTPException, status
from app.core.config import settings

UserRole = Literal["viewer", "analyst", "admin"]
ROLE_LEVELS: dict[UserRole, int] = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
}


@dataclass(frozen=True)
class AuthUser:
    """Authenticated user/service principal identity."""
    role: UserRole
    key_name: str
    is_authenticated: bool

    def has_role(self, required_role: UserRole) -> bool:
        """Check if current user's role satisfies or exceeds required_role."""
        return ROLE_LEVELS.get(self.role, 0) >= ROLE_LEVELS.get(required_role, 0)


def _extract_token(
    x_api_key: Optional[str] = None,
    authorization: Optional[str] = None,
) -> Optional[str]:
    """Extract API key from X-API-Key or Authorization Bearer header."""
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()
    if authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        if len(parts) == 1:
            return parts[0].strip()
    return None


def get_current_user(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> AuthUser:
    """Authenticate incoming request and return the resolved AuthUser principal."""
    provided_key = _extract_token(x_api_key, authorization)

    # 1. Check against configured keys in order of privilege
    if provided_key:
        if settings.ADMIN_API_KEY and secrets.compare_digest(provided_key, settings.ADMIN_API_KEY):
            return AuthUser(role="admin", key_name="admin", is_authenticated=True)
        if settings.ANALYST_API_KEY and secrets.compare_digest(provided_key, settings.ANALYST_API_KEY):
            return AuthUser(role="analyst", key_name="analyst", is_authenticated=True)
        if settings.VIEWER_API_KEY and secrets.compare_digest(provided_key, settings.VIEWER_API_KEY):
            return AuthUser(role="viewer", key_name="viewer", is_authenticated=True)
        if settings.API_AUTH_KEY and secrets.compare_digest(provided_key, settings.API_AUTH_KEY):
            # Legacy generic key maps to analyst role
            return AuthUser(role="analyst", key_name="legacy", is_authenticated=True)

        # A key was explicitly provided but matched none of the configured keys
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key or bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Key was NOT provided
    # Determine if auth is strictly required
    has_any_configured_key = bool(
        settings.ADMIN_API_KEY or settings.ANALYST_API_KEY or
        settings.VIEWER_API_KEY or settings.API_AUTH_KEY
    )
    auth_mandatory = settings.AUTH_ENFORCE or (not settings.DEMO_MODE) or has_any_configured_key

    if auth_mandatory:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided. Provide X-API-Key or Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Demo mode with unconfigured auth defaults to analyst role
    return AuthUser(role="analyst", key_name="demo-unauthenticated", is_authenticated=False)


def require_role(min_role: UserRole):
    """FastAPI dependency factory enforcing a minimum user role."""
    def _dependency(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if not user.has_role(min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: requires at least {min_role} role",
            )
        return user
    return _dependency


def require_viewer(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> AuthUser:
    """Enforce minimum role: viewer (read-only investigations)."""
    user = get_current_user(x_api_key, authorization)
    if not user.has_role("viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: requires at least viewer role",
        )
    return user


def require_analyst(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> AuthUser:
    """Enforce minimum role: analyst (create, analyze, enrich, generate reports)."""
    user = get_current_user(x_api_key, authorization)
    if not user.has_role("analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: requires at least analyst role",
        )
    return user


def require_admin(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> AuthUser:
    """Enforce role: admin (retrain models, configuration, admin management)."""
    user = get_current_user(x_api_key, authorization)
    if not user.has_role("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: requires admin role",
        )
    return user


def require_api_key(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> AuthUser:
    """Backwards-compatible alias for standard authentication."""
    return get_current_user(x_api_key, authorization)


__all__ = [
    "AuthUser",
    "UserRole",
    "get_current_user",
    "require_viewer",
    "require_analyst",
    "require_admin",
    "require_api_key",
]
