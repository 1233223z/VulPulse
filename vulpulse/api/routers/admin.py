"""Administrative endpoints."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.ai.service import SummaryService
from vulpulse.ai.summarizer import SummaryConfigurationError, SummaryError, SummaryRefused
from vulpulse.api.deps import get_session, require_api_key
from vulpulse.api.schemas import CrawlAccepted, CrawlRequest, SummaryOut
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


@router.post("/vulns/{identifier}/summary", response_model=SummaryOut)
async def generate_summary(
    identifier: str,
    refresh: bool = Query(default=False),
    session: AsyncSession = Depends(get_session),
) -> SummaryOut:
    """Generate and cache an AI summary for one vulnerability."""
    settings = get_settings()
    if not settings.llm_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI summaries are disabled",
        )
    if not settings.llm_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="VULPULSE_LLM_API_KEY is not configured",
        )

    service = SummaryService(session, settings=settings)
    try:
        outcome = await service.generate(identifier, refresh=refresh)
    except SummaryRefused as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The model declined to summarize this record",
        ) from exc
    except SummaryConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI summary provider is not configured correctly",
        ) from exc
    except SummaryError as exc:
        logger.warning("Summary generation failed for {}: {}", identifier, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Summary generation failed",
        ) from exc

    if outcome is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )

    return SummaryOut(
        text=outcome.text,
        model=outcome.model,
        generated_at=outcome.generated_at,
        cached=outcome.cached,
    )
