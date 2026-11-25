"""Shared fixtures for API and web integration tests."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from vulpulse.api.app import create_app
from vulpulse.api.deps import get_session
from vulpulse.config import get_settings
from vulpulse.db.repositories import (
    CrawlRunRepository,
    SourceRepository,
    VulnerabilityRepository,
)
from vulpulse.db.session import Database
from vulpulse.timeutils import utcnow


@pytest.fixture
async def db(tmp_path) -> AsyncIterator[Database]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'api.db'}")
    await database.create_schema()
    yield database
    await database.dispose()


@pytest.fixture
async def seeded(db: Database) -> dict[str, int]:
    now = utcnow()

    async with db.session() as session:
        source_repo = SourceRepository(session)
        vuln_repo = VulnerabilityRepository(session)

        source = await source_repo.get_or_create(
            "nvd",
            "api",
            base_url="https://nvd.test",
        )
        first, _ = await vuln_repo.upsert(
            "cve:CVE-2024-0001",
            cve_id="CVE-2024-0001",
            title="Apache Struts RCE",
            description="A critical Struts vulnerability.",
            severity="critical",
            risk_score=95.0,
            risk_level="critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N",
            cvss_version="3.1",
            epss_score=0.9,
            epss_percentile=0.99,
            in_kev=True,
            exploit_available=True,
            status="analyzed",
            published_at=now - timedelta(days=2),
            modified_at=now - timedelta(days=1),
        )
        await vuln_repo.add_source_record(
            first,
            source,
            "CVE-2024-0001",
            url="https://nvd.test/1",
            raw_json={"id": "CVE-2024-0001"},
        )
        product = await vuln_repo.get_or_create_product("apache", "struts")
        await vuln_repo.link_product(first, product, version_range="< 2.5.1")
        cwe = await vuln_repo.get_or_create_cwe("CWE-79")
        await vuln_repo.link_cwe(first, cwe)
        await vuln_repo.add_reference(
            first,
            "https://example.test/advisory",
            ["Vendor Advisory"],
        )

        second, _ = await vuln_repo.upsert(
            "cve:CVE-2024-0002",
            cve_id="CVE-2024-0002",
            title="Second issue",
            description="A medium issue.",
            severity="medium",
            risk_score=45.0,
            risk_level="medium",
            cvss_score=5.0,
            published_at=now - timedelta(days=1),
        )

        source.last_success_at = now
        runs = CrawlRunRepository(session)
        run = await runs.start(source)
        await runs.finish(run, status="success", stats={"fetched": 2, "created": 2})
        await session.commit()

        return {"first_id": first.id, "second_id": second.id, "source_id": source.id}


@pytest.fixture
async def client(
    db: Database,
    seeded: dict[str, int],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[AsyncClient]:
    monkeypatch.setenv("VULPULSE_SESSION_SECRET", "test-session-secret")
    get_settings.cache_clear()
    application = create_app()

    async def override_session() -> AsyncIterator:
        async with db.session() as session:
            yield session

    application.dependency_overrides[get_session] = override_session
    transport = ASGITransport(app=application)

    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client

    application.dependency_overrides.clear()
