from __future__ import annotations

from httpx import AsyncClient


async def test_markdown_export(client: AsyncClient) -> None:
    response = await client.get("/api/v1/export", params={"format": "md"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.headers["content-disposition"].startswith("attachment;")
    assert ".md" in response.headers["content-disposition"]
    assert "# VulPulse Vulnerability Report" in response.text
    assert "CVE-2024-0001" in response.text
    assert "CVE-2024-0002" in response.text


async def test_html_export(client: AsyncClient) -> None:
    response = await client.get("/api/v1/export", params={"format": "html"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<!doctype html>" in response.text
    assert "<table>" in response.text
    assert "CVE-2024-0001" in response.text


async def test_csv_export(client: AsyncClient) -> None:
    response = await client.get("/api/v1/export", params={"format": "csv"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["content-disposition"].startswith("attachment;")
    assert ".csv" in response.headers["content-disposition"]
    lines = response.text.splitlines()
    assert lines[0].startswith("cve_id,title,severity")
    assert any("CVE-2024-0001" in line for line in lines)
    assert any("apache" in line and "struts" in line for line in lines)
    assert any("CWE-79" in line for line in lines)


async def test_export_filters(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/export",
        params={"format": "md", "severity": "critical", "risk_min": 80},
    )

    assert response.status_code == 200
    assert "CVE-2024-0001" in response.text
    assert "CVE-2024-0002" not in response.text


async def test_export_product_filter(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/export",
        params={"format": "md", "product": "struts"},
    )

    assert response.status_code == 200
    assert "CVE-2024-0001" in response.text
    assert "CVE-2024-0002" not in response.text


async def test_export_rejects_unknown_format(client: AsyncClient) -> None:
    response = await client.get("/api/v1/export", params={"format": "pdf"})

    assert response.status_code == 422
