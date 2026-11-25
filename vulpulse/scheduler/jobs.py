"""Scheduled job definitions and their execution wrappers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from vulpulse.analyzer.scoring_service import RiskService, ScoreStats
from vulpulse.config import Settings
from vulpulse.crawler.base import BaseSource
from vulpulse.crawler.registry import create_source
from vulpulse.db.session import Database
from vulpulse.enrich.epss import EpssEnricher, EpssStats
from vulpulse.ingest import IngestService, IngestStats
from vulpulse.notifier.service import NotificationService, NotificationStats
from vulpulse.timeutils import utcnow


@dataclass(frozen=True)
class JobSchedule:
    job_id: str
    kind: Literal["crawl", "enrich", "notify", "score"]
    target: str
    interval_seconds: int
    lookback_days: int = 0
    run_on_start: bool = True


def default_schedules(settings: Settings) -> list[JobSchedule]:
    return [
        JobSchedule(
            job_id="crawl:nvd",
            kind="crawl",
            target="nvd",
            interval_seconds=settings.nvd_interval_minutes * 60,
            lookback_days=settings.nvd_lookback_days,
            run_on_start=settings.scheduler_run_on_start,
        ),
        JobSchedule(
            job_id="crawl:cisa_kev",
            kind="crawl",
            target="cisa_kev",
            interval_seconds=settings.kev_interval_hours * 3600,
            run_on_start=settings.scheduler_run_on_start,
        ),
        JobSchedule(
            job_id="crawl:exploitdb",
            kind="crawl",
            target="exploitdb",
            interval_seconds=settings.exploitdb_interval_hours * 3600,
            run_on_start=settings.scheduler_run_on_start,
        ),
        JobSchedule(
            job_id="enrich:epss",
            kind="enrich",
            target="epss",
            interval_seconds=settings.epss_interval_hours * 3600,
            run_on_start=settings.scheduler_run_on_start,
        ),
        JobSchedule(
            job_id="score:refresh",
            kind="score",
            target="risk",
            interval_seconds=settings.score_interval_hours * 3600,
            # Ingest and EPSS refresh scores immediately; this job handles decay.
            run_on_start=False,
        ),
        JobSchedule(
            job_id="notify:alerts",
            kind="notify",
            target="alerts",
            interval_seconds=settings.notify_interval_minutes * 60,
            # Do not send alerts on every worker restart.
            run_on_start=False,
        ),
    ]


async def run_crawl_job(
    source_name: str,
    *,
    settings: Settings,
    database: Database | None = None,
    lookback_days: int = 0,
    source_factory: Callable[[str, Settings], BaseSource] = create_source,
    service_factory: Callable[[Database | None], Any] = IngestService,
) -> IngestStats:
    """Run one source and persist the result.

    If a previous successful run left a checkpoint, it is used instead of the
    lookback window. Sources without a checkpoint (KEV, Exploit-DB) simply
    ignore the argument.
    """
    crawler = source_factory(source_name, settings)
    try:
        service = service_factory(database)
        checkpoint = await service.last_checkpoint(source_name)
        since = None
        if checkpoint is None and lookback_days > 0:
            since = utcnow() - timedelta(days=lookback_days)
        return await service.ingest(crawler, since=since, checkpoint=checkpoint)
    finally:
        await crawler.close()


async def run_epss_job(
    *,
    settings: Settings,
    database: Database | None = None,
    enricher_factory: Callable[..., EpssEnricher] = EpssEnricher,
) -> EpssStats:
    enricher = enricher_factory(database=database, settings=settings)
    try:
        return await enricher.enrich()
    finally:
        await enricher.close()


async def run_notify_job(
    *,
    settings: Settings,
    database: Database | None = None,
    service_factory: Callable[..., NotificationService] = NotificationService,
) -> NotificationStats:
    service = service_factory(database=database, settings=settings)
    return await service.run_cycle()


async def run_score_job(
    *,
    settings: Settings,
    database: Database | None = None,
    service_factory: Callable[..., RiskService] = RiskService,
) -> ScoreStats:
    service = service_factory(database=database, settings=settings)
    return await service.score_all()
