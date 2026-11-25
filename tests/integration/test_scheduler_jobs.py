from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import select

from vulpulse.config import Settings
from vulpulse.crawler.base import BaseSource
from vulpulse.crawler.models import RawVuln
from vulpulse.db.models import CrawlRun
from vulpulse.db.session import Database
from vulpulse.enrich.epss import EpssStats
from vulpulse.ingest import IngestService, IngestStats
from vulpulse.notifier.service import NotificationStats
from vulpulse.scheduler.jobs import run_crawl_job, run_epss_job, run_notify_job


class FakeSource(BaseSource):
    name = "job_source"
    kind = "test"

    def __init__(self, settings: Settings, records: list[RawVuln]) -> None:
        self._records = records
        super().__init__(settings)

    async def fetch(
        self,
        *,
        since: datetime | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> AsyncIterator[RawVuln]:
        for record in self._records:
            yield record


@pytest.fixture
async def db(tmp_path) -> AsyncIterator[Database]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'jobs.db'}")
    await database.create_schema()
    yield database
    await database.dispose()


async def test_run_crawl_job_persists_and_writes_checkpoint(db: Database) -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    record = RawVuln(
        source="job_source",
        source_vuln_id="CVE-2024-0001",
        cve_id="CVE-2024-0001",
        description="description",
        modified_at=datetime(2024, 2, 1),
    )
    source = FakeSource(settings, [record])

    stats = await run_crawl_job(
        "job_source",
        settings=settings,
        database=db,
        lookback_days=0,
        source_factory=lambda name, settings: source,
    )

    assert stats.created == 1

    async with db.session() as session:
        run = await session.scalar(select(CrawlRun).order_by(CrawlRun.id.desc()))
        assert run is not None
        assert run.status == "success"
        assert run.checkpoint == {"last_modified": "2024-02-01T00:00:00"}

    assert await IngestService(db).last_checkpoint("job_source") == {
        "last_modified": "2024-02-01T00:00:00"
    }


async def test_run_crawl_job_prefers_checkpoint_over_lookback() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    source = FakeSource(settings, [])
    received: dict[str, Any] = {}

    class FakeService:
        def __init__(self, database: Database | None) -> None:
            pass

        async def last_checkpoint(self, source_name: str) -> dict[str, Any]:
            return {"last_modified": "2024-02-01T00:00:00"}

        async def ingest(
            self,
            crawler: BaseSource,
            *,
            since: datetime | None = None,
            checkpoint: dict[str, Any] | None = None,
        ) -> IngestStats:
            received["since"] = since
            received["checkpoint"] = checkpoint
            return IngestStats()

    stats = await run_crawl_job(
        "job_source",
        settings=settings,
        lookback_days=7,
        source_factory=lambda name, settings: source,
        service_factory=FakeService,
    )

    assert stats.created == 0
    assert received["since"] is None
    assert received["checkpoint"] == {"last_modified": "2024-02-01T00:00:00"}


async def test_run_epss_job_delegates_and_closes() -> None:
    closed: list[bool] = []

    class FakeEnricher:
        def __init__(self, *, database: Database | None, settings: Settings) -> None:
            pass

        async def enrich(self) -> EpssStats:
            return EpssStats(matched=2, updated=2)

        async def close(self) -> None:
            closed.append(True)

    stats = await run_epss_job(
        settings=Settings(_env_file=None),  # type: ignore[call-arg]
        enricher_factory=FakeEnricher,
    )

    assert stats.matched == 2
    assert stats.updated == 2
    assert closed == [True]


async def test_run_notify_job_delegates() -> None:
    class FakeService:
        def __init__(self, *, database: Database | None, settings: Settings) -> None:
            pass

        async def run_cycle(self) -> NotificationStats:
            return NotificationStats(matched=1, sent=1)

    stats = await run_notify_job(
        settings=Settings(_env_file=None),  # type: ignore[call-arg]
        service_factory=FakeService,
    )

    assert stats.matched == 1
    assert stats.sent == 1
