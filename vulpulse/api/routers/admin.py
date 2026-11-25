"""Administrative endpoints."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from loguru import logger

from vulpulse.api.deps import require_api_key
from vulpulse.api.schemas import CrawlAccepted, CrawlRequest
from vulpulse.config import get_settings
from vulpulse.crawler import available_sources
from vulpulse.scheduler.jobs import run_crawl_job

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_api_key)],
)


@router.post(
    "/crawl",
    response_model=CrawlAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def trigger_crawl(
    payload: CrawlRequest,
    background: BackgroundTasks,
) -> CrawlAccepted:
    if payload.source not in available_sources():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown source: {payload.source}",
        )

    settings = get_settings()

    async def _run() -> None:
        try:
            stats = await run_crawl_job(
                payload.source,
                settings=settings,
                lookback_days=payload.since_days,
            )
            logger.info("Manual crawl finished for {}: {}", payload.source, stats)
        except Exception:
            logger.exception("Manual crawl failed for {}", payload.source)

    background.add_task(_run)
    return CrawlAccepted(
        status="accepted",
        source=payload.source,
        since_days=payload.since_days,
    )
