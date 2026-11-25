from __future__ import annotations

import asyncio
from datetime import timedelta

from apscheduler.triggers.interval import IntervalTrigger
from loguru import logger

from vulpulse.config import Settings
from vulpulse.db.session import Database
from vulpulse.scheduler.jobs import JobSchedule, default_schedules
from vulpulse.scheduler.worker import SchedulerWorker


def test_default_schedules_follow_settings() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        nvd_interval_minutes=30,
        kev_interval_hours=3,
        exploitdb_interval_hours=12,
        epss_interval_hours=6,
        nvd_lookback_days=4,
        notify_interval_minutes=10,
        score_interval_hours=8,
        scheduler_run_on_start=False,
    )

    schedules = {schedule.job_id: schedule for schedule in default_schedules(settings)}

    assert set(schedules) == {
        "crawl:nvd",
        "crawl:cisa_kev",
        "crawl:exploitdb",
        "enrich:epss",
        "score:refresh",
        "notify:alerts",
    }
    assert schedules["crawl:nvd"].interval_seconds == 30 * 60
    assert schedules["crawl:nvd"].lookback_days == 4
    assert schedules["crawl:cisa_kev"].interval_seconds == 3 * 3600
    assert schedules["crawl:exploitdb"].interval_seconds == 12 * 3600
    assert schedules["enrich:epss"].interval_seconds == 6 * 3600
    assert schedules["score:refresh"].interval_seconds == 8 * 3600
    assert schedules["score:refresh"].run_on_start is False
    assert schedules["notify:alerts"].interval_seconds == 10 * 60
    assert schedules["notify:alerts"].run_on_start is False
    assert all(not schedule.run_on_start for schedule in schedules.values())


async def test_register_jobs(tmp_path) -> None:
    settings = Settings(_env_file=None, scheduler_run_on_start=False)  # type: ignore[call-arg]
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'scheduler.db'}")
    worker = SchedulerWorker(
        settings=settings,
        database=database,
        schedules=default_schedules(settings),
    )

    try:
        worker.register_jobs()
        jobs = {job.id: job for job in worker.scheduler.get_jobs()}

        assert set(jobs) == {
            "crawl:nvd",
            "crawl:cisa_kev",
            "crawl:exploitdb",
            "enrich:epss",
            "score:refresh",
            "notify:alerts",
        }
        trigger = jobs["crawl:nvd"].trigger
        assert isinstance(trigger, IntervalTrigger)
        assert trigger.interval == timedelta(minutes=60)
    finally:
        await database.dispose()


async def test_run_once_dispatches_both_job_kinds(tmp_path) -> None:
    settings = Settings(_env_file=None, scheduler_run_on_start=False)  # type: ignore[call-arg]
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'dispatch.db'}")
    calls: list[str] = []

    async def fake_crawl(schedule: JobSchedule) -> None:
        calls.append(schedule.job_id)

    async def fake_enrich(schedule: JobSchedule) -> None:
        calls.append(schedule.job_id)

    async def fake_notify(schedule: JobSchedule) -> None:
        calls.append(schedule.job_id)

    async def fake_score(schedule: JobSchedule) -> None:
        calls.append(schedule.job_id)

    worker = SchedulerWorker(
        settings=settings,
        database=database,
        schedules=[],
        crawl_job=fake_crawl,
        enrich_job=fake_enrich,
        notify_job=fake_notify,
        score_job=fake_score,
    )

    try:
        await worker.run_once(JobSchedule("crawl:test", "crawl", "nvd", 60))
        await worker.run_once(JobSchedule("enrich:test", "enrich", "epss", 60))
        await worker.run_once(JobSchedule("notify:test", "notify", "alerts", 60))
        await worker.run_once(JobSchedule("score:test", "score", "risk", 60))
    finally:
        await database.dispose()

    assert calls == ["crawl:test", "enrich:test", "notify:test", "score:test"]


async def test_jobs_are_serialized(tmp_path) -> None:
    settings = Settings(_env_file=None, scheduler_run_on_start=False)  # type: ignore[call-arg]
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'serialized.db'}")
    active = 0
    max_active = 0

    async def fake_job(_: JobSchedule) -> None:
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0.01)
        active -= 1

    worker = SchedulerWorker(
        settings=settings,
        database=database,
        schedules=[],
        crawl_job=fake_job,
    )

    try:
        await asyncio.gather(
            worker.run_once(JobSchedule("crawl:one", "crawl", "nvd", 60)),
            worker.run_once(JobSchedule("crawl:two", "crawl", "cisa_kev", 60)),
        )
    finally:
        await database.dispose()

    assert max_active == 1


async def test_job_failure_does_not_propagate(tmp_path) -> None:
    settings = Settings(_env_file=None, scheduler_run_on_start=False)  # type: ignore[call-arg]
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'failing.db'}")

    async def failing(_: JobSchedule) -> None:
        raise RuntimeError("boom")

    worker = SchedulerWorker(
        settings=settings,
        database=database,
        schedules=[],
        crawl_job=failing,
    )

    logger.disable("vulpulse.scheduler.worker")
    try:
        await worker.run_once(JobSchedule("crawl:failing", "crawl", "nvd", 60))
    finally:
        logger.enable("vulpulse.scheduler.worker")
        await database.dispose()
