from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from vulpulse.api.app import create_app
from vulpulse.config import get_settings


async def test_metrics_endpoint_and_response_time(client: AsyncClient) -> None:
    api = await client.get("/api/v1/vulns", params={"size": 1})
    metrics = await client.get("/metrics")

    assert api.status_code == 200
    assert api.headers["X-Response-Time-ms"]
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    assert "vulpulse_http_requests_total" in metrics.text
    assert 'route="api:/vulns"' in metrics.text
    assert 'status="200"' in metrics.text
    assert "vulpulse_http_request_duration_seconds" in metrics.text


async def test_metrics_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setenv("VULPULSE_METRICS_ENABLED", "false")
    get_settings.cache_clear()
    application = create_app()
    transport = ASGITransport(app=application)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        metrics = await client.get("/metrics")
        index = await client.get("/api")

    assert metrics.status_code == 404
    assert index.status_code == 200
    assert index.headers["X-Response-Time-ms"]
