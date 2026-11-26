from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import text

from vulpulse.db.repositories import SourceRepository, VulnerabilityRepository
from vulpulse.db.session import Database
from vulpulse.timeutils import utcnow

POSTGRES_URL = os.environ.get("VULPULSE_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="set VULPULSE_TEST_POSTGRES_URL to run PostgreSQL integration tests",
)


async def test_postgres_roundtrip_and_trend() -> None:
    assert POSTGRES_URL is not None
    database = Database(POSTGRES_URL)
    key = f"pg-test:{uuid4().hex}"
    published_at = utcnow()

    try:
        async with database.session() as session:
            source = await SourceRepository(session).get_or_create("postgres_test", "api")
            repository = VulnerabilityRepository(session)
            vulnerability, _ = await repository.upsert(
                key,
                cve_id=None,
                title="PostgreSQL roundtrip",
                severity="high",
                published_at=published_at,
            )
            await repository.add_source_record(
                vulnerability,
                source,
                "PG-TEST-1",
                url="https://example.test/pg",
            )
            await session.commit()
            vulnerability_id = vulnerability.id

        async with database.session() as session:
            repository = VulnerabilityRepository(session)
            detail = await repository.get_detail(str(vulnerability_id))
            trend = await repository.published_trend(30)

        assert detail is not None
        assert detail.title == "PostgreSQL roundtrip"
        assert len(detail.source_records) == 1
        assert any(day == published_at.date().isoformat() for day, _ in trend)

        async with database.session() as session:
            assert await session.scalar(text("SELECT 1")) == 1
    finally:
        async with database.session() as session:
            await session.execute(
                text("DELETE FROM vulnerabilities WHERE dedupe_key LIKE 'pg-test:%'")
            )
            await session.execute(text("DELETE FROM sources WHERE name = 'postgres_test'"))
            await session.commit()
        await database.dispose()
