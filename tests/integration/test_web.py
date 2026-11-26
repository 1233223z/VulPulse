from __future__ import annotations

from httpx import AsyncClient


async def test_dashboard(client: AsyncClient) -> None:
    response = await client.get("/")

    assert response.status_code == 200
    assert "Total vulnerabilities" in response.text
    assert "Apache Struts RCE" in response.text
    assert "Latest known exploited" in response.text


async def test_vulnerability_list_and_filter(client: AsyncClient) -> None:
    response = await client.get("/vulns")

    assert response.status_code == 200
    assert "CVE-2024-0001" in response.text
    assert "CVE-2024-0002" in response.text

    filtered = await client.get("/vulns", params={"severity": "critical"})

    assert filtered.status_code == 200
    assert "CVE-2024-0001" in filtered.text
    assert "CVE-2024-0002" not in filtered.text


async def test_list_has_export_links(client: AsyncClient) -> None:
    response = await client.get("/vulns", params={"severity": "critical"})

    assert response.status_code == 200
    assert "Export MD" in response.text
    assert "Export HTML" in response.text
    assert "/api/v1/export?format=md" in response.text
    assert "severity=critical" in response.text


async def test_vulnerability_detail(client: AsyncClient) -> None:
    response = await client.get("/vulns/CVE-2024-0001")

    assert response.status_code == 200
    assert "Apache Struts RCE" in response.text
    assert "struts" in response.text
    assert "CWE-79" in response.text
    assert "https://example.test/advisory" in response.text
    assert "Risk breakdown" in response.text
    assert "Relationship graph" in response.text


async def test_vulnerability_detail_not_found(client: AsyncClient) -> None:
    response = await client.get("/vulns/CVE-9999-9999")

    assert response.status_code == 404
    assert "Vulnerability not found" in response.text


async def test_vendors_page(client: AsyncClient) -> None:
    response = await client.get("/vendors")

    assert response.status_code == 200
    assert "apache" in response.text
    assert "Vendors" in response.text


async def test_vendor_detail_page(client: AsyncClient) -> None:
    response = await client.get("/vendors/apache")

    assert response.status_code == 200
    assert "struts" in response.text
    assert "CVE-2024-0001" in response.text
    assert "Top risk vulnerabilities" in response.text


async def test_vendor_not_found_page(client: AsyncClient) -> None:
    response = await client.get("/vendors/does-not-exist")

    assert response.status_code == 404
    assert "Vendor not found" in response.text


async def test_product_filter(client: AsyncClient) -> None:
    response = await client.get("/vulns", params={"product": "struts"})

    assert response.status_code == 200
    assert "CVE-2024-0001" in response.text
    assert "CVE-2024-0002" not in response.text


async def test_sources_page(client: AsyncClient) -> None:
    response = await client.get("/sources")

    assert response.status_code == 200
    assert "nvd" in response.text
    assert "success" in response.text


async def test_static_stylesheet(client: AsyncClient) -> None:
    response = await client.get("/static/style.css")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert "--vp-bg" in response.text


async def test_vendored_assets_are_served(client: AsyncClient) -> None:
    stylesheet = await client.get("/static/vendor/bootstrap.min.css")
    bundle = await client.get("/static/vendor/bootstrap.bundle.min.js")
    chart = await client.get("/static/vendor/chart.umd.min.js")
    license_file = await client.get("/static/vendor/LICENSE.bootstrap")

    assert stylesheet.status_code == 200
    assert bundle.status_code == 200
    assert chart.status_code == 200
    assert license_file.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert bundle.headers["content-type"].startswith("text/javascript")
    assert chart.headers["content-type"].startswith("text/javascript")
    assert "v5.3.9" in stylesheet.text
    assert "v5.3.9" in bundle.text
    assert "Chart.js v4.6.2" in chart.text
    assert "MIT" in license_file.text


async def test_api_index_still_works(client: AsyncClient) -> None:
    response = await client.get("/api")

    assert response.status_code == 200
    assert response.json()["v1"] == "/api/v1"


async def test_security_headers(client: AsyncClient) -> None:
    response = await client.get("/")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in response.headers["permissions-policy"]

    admin = await client.get("/admin/login")

    assert admin.headers["Cache-Control"] == "no-store"
