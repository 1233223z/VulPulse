"""Data source status endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.api.deps import get_session
from vulpulse.api.schemas import LastRunOut, SourceInfo
from vulpulse.db.repositories import SourceRepository

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("", response_model=list[SourceInfo])
async def list_sources(
    session: AsyncSession = Depends(get_session),
) -> list[SourceInfo]:
    repository = SourceRepository(session)
    sources = await repository.list_all()
    result: list[SourceInfo] = []

    for source in sources:
        last_run = await repository.latest_run(source.id)
        result.append(
            SourceInfo(
                id=source.id,
                name=source.name,
                kind=source.kind,
                base_url=source.base_url,
                enabled=source.enabled,
                last_success_at=source.last_success_at,
                records=await repository.count_records(source.id),
                last_run=(
                    LastRunOut(
                        status=last_run.status,
                        started_at=last_run.started_at,
                        finished_at=last_run.finished_at,
                        stats=last_run.stats,
                    )
                    if last_run is not None
                    else None
                ),
            )
        )

    return result
