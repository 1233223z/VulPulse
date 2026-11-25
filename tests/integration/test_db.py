from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from vulpulse.db.models import Vulnerability
from vulpulse.db.repositories import (
    CrawlRunRepository,
    SourceRepository,
    VulnerabilityRepository,
)
from vulpulse.db.session import Database


@pytest.fixture
async def db(tmp_path) -> AsyncIterator[Database]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    await database.create_schema()
    yield database
    await database.dispose()


async def test_source_upsert_is_idempotent(db: Database) -> None:
    async with db.session() as session:
        repo = SourceRepository(session)
        first = await repo.get_or_create("nvd", "api", base_url="https://nvd.test")
        second = await repo.get_or_create("nvd", "api", base_url="https://nvd.test")
        await session.commit()
        assert first.id == second.id

    async with db.session() as session:
        assert (await SourceRepository(session).get_by_name("nvd")) is not None


async def test_vulnerability_upsert_deduplicates_by_key(db: Database) -> None:
    async with db.session() as session:
        repo = VulnerabilityRepository(session)
        first, created = await repo.upsert(
            "cve:CVE-2024-0001",
            cve_id="CVE-2024-0001",
            title="first",
            severity="high",
        )
        assert created is True
        await session.commit()

    async with db.session() as session:
        repo = VulnerabilityRepository(session)
        second, created = await repo.upsert(
            "cve:CVE-2024-0001",
            title="second",
            severity="critical",
        )
        await session.commit()

        assert created is False
        assert second.id == first.id
        assert second.title == "second"
        assert second.severity == "critical"
        assert await repo.count() == 1


async def test_source_record_is_unique_per_source(db: Database) -> None:
    async with db.session() as session:
        sources = SourceRepository(session)
        vulns = VulnerabilityRepository(session)

        source = await sources.get_or_create("nvd", "api")
        vuln, _ = await vulns.upsert("cve:CVE-2024-0002", cve_id="CVE-2024-0002")

        first = await vulns.add_source_record(
            vuln, source, "CVE-2024-0002", url="https://nvd.test/1"
        )
        second = await vulns.add_source_record(
            vuln, source, "CVE-2024-0002", url="https://nvd.test/2"
        )
        await session.commit()

        assert first.id == second.id
        assert second.url == "https://nvd.test/1"


async def test_crawl_run_lifecycle(db: Database) -> None:
    async with db.session() as session:
        source = await SourceRepository(session).get_or_create("nvd", "api")
        runs = CrawlRunRepository(session)

        run = await runs.start(source)
        assert run.status == "running"
        assert run.finished_at is None

        await runs.finish(run, status="success", stats={"fetched": 3, "new": 2})
        await session.commit()

        assert run.status == "success"
        assert run.finished_at is not None
        assert run.stats == {"fetched": 3, "new": 2}


async def test_vulnerability_defaults(db: Database) -> None:
    async with db.session() as session:
        vuln = Vulnerability(dedupe_key="src:manual:1", cve_id=None)
        session.add(vuln)
        await session.commit()

        assert vuln.severity == "unknown"
        assert vuln.in_kev is False
        assert vuln.exploit_available is False
        assert vuln.status == "active"
        assert vuln.created_at is not None

    async with db.session() as session:
        source = await SourceRepository(session).get_or_create("manual", "manual")
        assert source.id is not None
