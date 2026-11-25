"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.api.deps import get_session
from vulpulse.api.schemas import HealthStatus

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthStatus)
async def healthz(session: AsyncSession = Depends(get_session)) -> HealthStatus:
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - depends on infrastructure
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc
    return HealthStatus(status="ok", database="ok")
