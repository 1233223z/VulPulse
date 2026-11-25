"""Shared FastAPI dependencies."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

from fastapi import Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.config import get_settings
from vulpulse.db.session import get_database


async def get_session() -> AsyncIterator[AsyncSession]:
    database = get_database()
    async with database.session() as session:
        yield session


async def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """Protect admin endpoints with the configured API key."""
    settings = get_settings()
    if not settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API is disabled: set VULPULSE_API_KEY",
        )
    if x_api_key is None or not secrets.compare_digest(
        x_api_key.encode("utf-8"),
        settings.api_key.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
