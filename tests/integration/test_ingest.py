from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from vulpulse.config import Settings
from vulpulse.crawler.base import BaseSource
from vulpulse.crawler.models import RawProduct, RawVuln
from vulpulse.db.models import (
    CrawlRun,
    Cwe,
    Product,
    SourceRecord,
    VulnCwe,
    VulnProduct,
    VulnReference,
)
from vulpulse.db.repositories import VulnerabilityRepository
from vulpulse.db.session import Database
from vulpulse.ingest import IngestService


class FakeSource(BaseSource):
    def __init__(
        self,
        settings: Settings,
        name: str,
        records: list[RawVuln],
        *,
        fail_after: int | None = None,
    ) -> None:
        self.name = name
        self.kind = "test"
        self._records = records
        self._fail_after = fail_after
        super().__init__(settings)

    async def fetch(
        self,
        *,
        since: datetime | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> AsyncIterator[RawVuln]:
        for index, record in enumerate(self._records, start=1):
            yield record
            if self._fail_after is not None and index >= self._fail_after:
                raise RuntimeError("simulated failure")


@pytest.fixture
async def db(tmp_path) -> AsyncIterator[Database]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'ingest.db'}")
    await database.create_schema()
    yield database
    await database.dispose()


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


def nvd_record() -> RawVuln:
    return RawVuln(
        source="nvd_fake",
        source_vuln_id="CVE-2024-0001",
        cve_id="CVE-2024-0001",
        description="NVD description",
        severity="critical",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L",
        cvss_version="3.1",
        published_at=datetime(2024, 1, 1),
        modified_at=datetime(2024, 2, 1),
        vuln_status="Analyzed",
        references=["https://example.test/advisory"],
        products=[RawProduct(vendor="apache", product="struts", version_range="< 2.5.1")],
        cwes=["CWE-79"],
    )


def kev_record() -> RawVuln:
    return RawVuln(
        source="kev_fake",
        source_vuln_id="CVE-2024-0001",
        cve_id="CVE-2024-0001",
        title="Apache Struts RCE",
        in_kev=True,
        kev_due_date=date(2024, 1, 23),
        products=[RawProduct(vendor="Apache", product="Struts")],
    )


async def test_ingest_merges_sources_without_clobbering(
    db: Database,
    settings: Settings,
) -> None:
    nvd_source = FakeSource(settings, "nvd_fake", [nvd_record()])
    kev_source = FakeSource(settings, "kev_fake", [kev_record()])
    service = IngestService(db)

    try:
        nvd_stats = await service.ingest(nvd_source)
        kev_stats = await service.ingest(kev_source)
        nvd_again = await service.ingest(nvd_source)
    finally:
        await nvd_source.close()
        await kev_source.close()

    assert nvd_stats.created == 1
    assert nvd_stats.updated == 0
    assert kev_stats.created == 0
    assert kev_stats.updated == 1
    assert nvd_again.created == 0
    assert nvd_again.updated == 1

    async with db.session() as session:
        repo = VulnerabilityRepository(session)
        vuln = await repo.get_by_cve_id("CVE-2024-0001")

        assert vuln is not None
        assert vuln.title == "Apache Struts RCE"
        assert vuln.description == "NVD description"
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 9.8
        assert vuln.in_kev is True
        assert vuln.kev_due_date == date(2024, 1, 23)
        assert vuln.status == "analyzed"
        assert await repo.count() == 1

        assert await session.scalar(select(func.count(SourceRecord.id))) == 2
        assert await session.scalar(select(func.count(Product.id))) == 1
        assert await session.scalar(select(func.count(VulnProduct.id))) == 2
        assert await session.scalar(select(func.count(Cwe.id))) == 1
        assert await session.scalar(select(func.count()).select_from(VulnCwe)) == 1
        assert await session.scalar(select(func.count(VulnReference.id))) == 1


async def test_failed_crawl_is_recorded_and_rolled_back(
    db: Database,
    settings: Settings,
) -> None:
    source = FakeSource(settings, "failing", [nvd_record()], fail_after=1)
    service = IngestService(db)

    try:
        with pytest.raises(RuntimeError, match="simulated failure"):
            await service.ingest(source)
    finally:
        await source.close()

    async with db.session() as session:
        run = await session.scalar(select(CrawlRun).order_by(CrawlRun.id.desc()))
        assert run is not None
        assert run.status == "failed"
        assert run.error is not None
        assert "simulated failure" in run.error
        assert await VulnerabilityRepository(session).count() == 0


async def test_successful_crawl_run_records_stats(
    db: Database,
    settings: Settings,
) -> None:
    source = FakeSource(settings, "working", [nvd_record()])
    service = IngestService(db)

    try:
        stats = await service.ingest(source)
    finally:
        await source.close()

    async with db.session() as session:
        run = await session.scalar(select(CrawlRun).order_by(CrawlRun.id.desc()))
        assert run is not None
        assert run.status == "success"
        assert run.finished_at is not None
        assert run.stats == stats.as_dict()
        assert stats.fetched == 1
        assert stats.created == 1
        assert stats.products == 1
        assert stats.cwes == 1
        assert stats.references == 1


async def test_crawl_run_is_linked_to_source(db: Database, settings: Settings) -> None:
    source = FakeSource(settings, "linked", [nvd_record()])
    service = IngestService(db)

    try:
        await service.ingest(source)
    finally:
        await source.close()

    async with db.session() as session:
        run = await session.scalar(
            select(CrawlRun).options(selectinload(CrawlRun.source)).order_by(CrawlRun.id.desc())
        )
        assert run is not None
        assert run.source.name == "linked"
