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
async def client(db: Database, seeded: dict[str, int]) -> AsyncIterator[AsyncClient]:
    application = create_app()

    async def override_session() -> AsyncIterator:
        async with db.session() as session:
            yield session

    application.dependency_overrides[get_session] = override_session
    transport = ASGITransport(app=application)

    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client

    application.dependency_overrides.clear()


async def test_health(client: AsyncClient) -> None:
    response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


async def test_index(client: AsyncClient) -> None:
    response = await client.get("/")

    assert response.status_code == 200
    assert response.json()["docs"] == "/docs"


async def test_list_vulns_defaults_to_newest_first(client: AsyncClient) -> None:
    response = await client.get("/api/v1/vulns")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert data["pages"] == 1
    assert data["items"][0]["cve_id"] == "CVE-2024-0002"
    assert data["items"][1]["cve_id"] == "CVE-2024-0001"


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"severity": "critical"}, "CVE-2024-0001"),
        ({"kev": "true"}, "CVE-2024-0001"),
        ({"exploit": "true"}, "CVE-2024-0001"),
        ({"q": "struts"}, "CVE-2024-0001"),
        ({"vendor": "apache"}, "CVE-2024-0001"),
        ({"source": "nvd"}, "CVE-2024-0001"),
        ({"cvss_min": 9}, "CVE-2024-0001"),
        ({"epss_min": 0.5}, "CVE-2024-0001"),
    ],
)
async def test_filters(
    client: AsyncClient,
    params: dict[str, object],
    expected: str,
) -> None:
    response = await client.get("/api/v1/vulns", params=params)

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["cve_id"] == expected


async def test_pagination(client: AsyncClient) -> None:
    response = await client.get("/api/v1/vulns", params={"size": 1, "page": 2})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert data["pages"] == 2
    assert len(data["items"]) == 1
    assert data["items"][0]["cve_id"] == "CVE-2024-0001"


async def test_detail_by_cve(client: AsyncClient) -> None:
    response = await client.get("/api/v1/vulns/CVE-2024-0001")

    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Apache Struts RCE"
    assert data["description"] == "A critical Struts vulnerability."
    assert data["products"] == [
        {
            "vendor": "apache",
            "product": "struts",
            "version_range": "< 2.5.1",
            "cpe": None,
        }
    ]
    assert data["cwes"] == [{"id": "CWE-79", "name": None}]
    assert data["sources"][0]["source"] == "nvd"
    assert data["references"][0]["url"] == "https://example.test/advisory"


async def test_detail_by_numeric_id(
    client: AsyncClient,
    seeded: dict[str, int],
) -> None:
    response = await client.get(f"/api/v1/vulns/{seeded['first_id']}")

    assert response.status_code == 200
    assert response.json()["cve_id"] == "CVE-2024-0001"


async def test_detail_not_found(client: AsyncClient) -> None:
    response = await client.get("/api/v1/vulns/CVE-9999-9999")

    assert response.status_code == 404


async def test_stats_overview(client: AsyncClient) -> None:
    response = await client.get("/api/v1/stats/overview")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert data["severity"]["critical"] == 1
    assert data["severity"]["medium"] == 1
    assert data["in_kev"] == 1
    assert data["exploit_available"] == 1
    assert data["epss_scored"] == 1
    assert len(data["trend"]) == 2


async def test_sources(client: AsyncClient) -> None:
    response = await client.get("/api/v1/sources")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["name"] == "nvd"
    assert data[0]["records"] == 1
    assert data[0]["last_success_at"] is not None
    assert data[0]["last_run"]["status"] == "success"


async def test_admin_is_disabled_without_key(client: AsyncClient) -> None:
    response = await client.post("/api/v1/admin/crawl", json={"source": "nvd"})

    assert response.status_code == 503


async def test_admin_rejects_wrong_key(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "secret")
    get_settings.cache_clear()

    response = await client.post(
        "/api/v1/admin/crawl",
        json={"source": "nvd"},
        headers={"X-API-Key": "wrong"},
    )

    assert response.status_code == 401


async def test_admin_accepts_crawl(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "secret")
    get_settings.cache_clear()
    calls: list[tuple[str, int]] = []

    async def fake_run(source: str, *, settings: object, lookback_days: int) -> None:
        calls.append((source, lookback_days))

    monkeypatch.setattr("vulpulse.api.routers.admin.run_crawl_job", fake_run)

    response = await client.post(
        "/api/v1/admin/crawl",
        json={"source": "nvd", "since_days": 3},
        headers={"X-API-Key": "secret"},
    )

    assert response.status_code == 202
    assert calls == [("nvd", 3)]


async def test_admin_rejects_unknown_source(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "secret")
    get_settings.cache_clear()

    response = await client.post(
        "/api/v1/admin/crawl",
        json={"source": "does-not-exist"},
        headers={"X-API-Key": "secret"},
    )

    assert response.status_code == 400
