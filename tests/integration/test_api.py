from __future__ import annotations

import pytest
from httpx import AsyncClient

from vulpulse.config import get_settings


async def test_health(client: AsyncClient) -> None:
    response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


async def test_api_index(client: AsyncClient) -> None:
    response = await client.get("/api")

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
        ({"risk_min": 80}, "CVE-2024-0001"),
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


async def test_sort_by_risk(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/vulns",
        params={"sort": "risk_score", "order": "desc"},
    )

    assert response.status_code == 200
    assert response.json()["items"][0]["cve_id"] == "CVE-2024-0001"


async def test_detail_by_cve(client: AsyncClient) -> None:
    response = await client.get("/api/v1/vulns/CVE-2024-0001")

    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Apache Struts RCE"
    assert data["description"] == "A critical Struts vulnerability."
    assert data["risk_level"] == "critical"
    assert data["risk_score"] is not None
    assert data["risk_score"] >= 80
    assert set(data["risk_breakdown"]) == {
        "cvss",
        "epss",
        "kev",
        "exploit",
        "recency",
    }
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
    assert data["risk"]["critical"] == 1
    assert data["risk"]["medium"] == 1
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
