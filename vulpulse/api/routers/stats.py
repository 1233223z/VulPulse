"""Aggregate statistics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.api.deps import get_session
from vulpulse.api.schemas import SeverityCounts, StatsOverview, TrendPoint
from vulpulse.db.repositories import VulnerabilityRepository

router = APIRouter(prefix="/stats", tags=["statistics"])


@router.get("/overview", response_model=StatsOverview)
async def overview(
    days: int = Query(default=30, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
) -> StatsOverview:
    repository = VulnerabilityRepository(session)
    counts = await repository.severity_counts()
    trend = await repository.published_trend(days)

    return StatsOverview(
        total=await repository.count(),
        severity=SeverityCounts(
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
            none=counts.get("none", 0),
            unknown=counts.get("unknown", 0),
        ),
        in_kev=await repository.count_in_kev(),
        exploit_available=await repository.count_with_exploit(),
        epss_scored=await repository.count_with_epss(),
        trend=[TrendPoint(date=day, count=count) for day, count in trend],
    )
