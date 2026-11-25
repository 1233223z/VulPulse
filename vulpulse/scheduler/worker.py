"""Standalone scheduler worker.

Run this in its own process (``vulpulse worker``). The API process never
schedules jobs, so scaling the API cannot trigger duplicate crawls.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from loguru import logger

from vulpulse.config import Settings, get_settings
from vulpulse.db.session import Database, get_database
from vulpulse.scheduler.jobs import (
    JobSchedule,
    default_schedules,
    run_crawl_job,
    run_epss_job,
)

JobCallable = Callable[[JobSchedule], Awaitable[Any]]


class SchedulerWorker:
    def __init__(
        self,
        *,
        settings: Settings | None = None,
        database: Database | None = None,
        schedules: list[JobSchedule] | None = None,
        crawl_job: JobCallable | None = None,
        enrich_job: JobCallable | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.database = database or get_database()
        self.schedules = schedules if schedules is not None else default_schedules(self.settings)
        self._crawl_job = crawl_job
        self._enrich_job = enrich_job
        self.scheduler = AsyncIOScheduler(timezone=timezone.utc)

    def register_jobs(self) -> None:
        """Attach every schedule to the APScheduler instance."""
        now = datetime.now(timezone.utc)
        for schedule in self.schedules:
            options: dict[str, Any] = {
                "trigger": IntervalTrigger(seconds=schedule.interval_seconds),
                "args": [schedule],
                "id": schedule.job_id,
                "name": schedule.job_id,
                "replace_existing": True,
                "max_instances": 1,
                "coalesce": True,
                "misfire_grace_time": 300,
            }
            if schedule.run_on_start:
                options["next_run_time"] = now
            self.scheduler.add_job(self._run, **options)

    def start(self) -> None:
        self.register_jobs()
        self.scheduler.start()
        logger.info("Scheduler started with {} jobs", len(self.schedules))

    def shutdown(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    async def run_forever(self) -> None:
        self.start()
        try:
            while True:
                await asyncio.sleep(3600)
        finally:
            self.shutdown()

    async def run_all_once(self) -> None:
        for schedule in self.schedules:
            await self._run(schedule)

    async def run_once(self, schedule: JobSchedule) -> None:
        await self._run(schedule)

    async def _run(self, schedule: JobSchedule) -> None:
        logger.info("Running scheduled job: {}", schedule.job_id)
        try:
            if schedule.kind == "crawl":
                result = (
                    await self._crawl_job(schedule)
                    if self._crawl_job is not None
                    else await run_crawl_job(
                        schedule.target,
                        settings=self.settings,
                        database=self.database,
                        lookback_days=schedule.lookback_days,
                    )
                )
            else:
                result = (
                    await self._enrich_job(schedule)
                    if self._enrich_job is not None
                    else await run_epss_job(
                        settings=self.settings,
                        database=self.database,
                    )
                )
            logger.info("Job {} finished: {}", schedule.job_id, result)
        except Exception:
            # A single failing source must not stop the scheduler.
            logger.exception("Job {} failed", schedule.job_id)
