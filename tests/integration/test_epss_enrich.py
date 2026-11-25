from __future__ import annotations

import gzip
from collections.abc import AsyncIterator

import httpx
import pytest

from vulpulse.config import Settings
from vulpulse.crawler.http import HttpClient
from vulpulse.db.repositories import VulnerabilityRepository
from vulpulse.db.session import Database
from vulpulse.enrich.epss import EpssEnricher

CSV_TEXT = """#model_version:v2024.01.01,score_date:2024-01-01T00:00:00Z
cve,epss,percentile
CVE-2024-0001,0.42,0.97
CVE-2024-0002,0.01,0.50
CVE-2024-9999,0.90,0.99
"""


@pytest.fixture
async def db(tmp_path) -> AsyncIterator[Database]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'epss.db'}")
    await database.create_schema()
    yield database
    await database.dispose()


async def test_enrich_updates_existing_cves_only(db: Database) -> None:
    async with db.session() as session:
        repo = VulnerabilityRepository(session)
        await repo.upsert("cve:CVE-2024-0001", cve_id="CVE-2024-0001", title="one")
        await repo.upsert("cve:CVE-2024-0002", cve_id="CVE-2024-0002", title="two")
        await session.commit()

    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        epss_scores_url="https://epss.test/scores.gz",
    )
    payload = gzip.compress(CSV_TEXT.encode())
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=payload))
    client = HttpClient(transport=transport)
    enricher = EpssEnricher(db, settings, client)

    try:
        stats = await enricher.enrich()
    finally:
        await client.aclose()

    assert stats.matched == 2
    assert stats.updated == 2

    async with db.session() as session:
        repo = VulnerabilityRepository(session)
        first = await repo.get_by_cve_id("CVE-2024-0001")
        second = await repo.get_by_cve_id("CVE-2024-0002")

        assert first is not None
        assert second is not None
        assert first.epss_score == 0.42
        assert first.epss_percentile == 0.97
        assert second.epss_score == 0.01
        assert second.epss_percentile == 0.50
        assert await repo.get_by_cve_id("CVE-2024-9999") is None
        assert await repo.count() == 2


async def test_enrich_without_cves_does_not_download(db: Database) -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        epss_scores_url="https://epss.test/scores.gz",
    )
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500)

    client = HttpClient(transport=httpx.MockTransport(handler))
    enricher = EpssEnricher(db, settings, client)

    try:
        stats = await enricher.enrich()
    finally:
        await client.aclose()

    assert stats.matched == 0
    assert stats.updated == 0
    assert calls == []
