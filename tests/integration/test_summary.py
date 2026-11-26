from __future__ import annotations

import re

from httpx import AsyncClient

from vulpulse.ai.service import SummaryService
from vulpulse.ai.summarizer import (
    SummaryConfigurationError,
    SummaryError,
    SummaryRefused,
    SummaryResult,
    VulnSummarizer,
)
from vulpulse.config import Settings, get_settings
from vulpulse.db.repositories import VulnerabilityRepository
from vulpulse.db.session import Database
from vulpulse.timeutils import utcnow


class FakeSummarizer:
    calls = 0

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def summarize(self, vulnerability: object) -> SummaryResult:
        type(self).calls += 1
        return SummaryResult(
            text="Defensive summary text.",
            model="claude-opus-5-5",
            generated_at=utcnow(),
        )

    async def close(self) -> None:
        return None


async def test_summary_service_caches_and_refreshes(db: Database, seeded: dict[str, int]) -> None:
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        llm_enabled=True,
        llm_api_key="test-key",
    )
    FakeSummarizer.calls = 0

    async with db.session() as session:
        service = SummaryService(
            session,
            settings=settings,
            summarizer_factory=lambda _: FakeSummarizer(settings),
        )
        first = await service.generate("CVE-2024-0001")
        cached = await service.generate("CVE-2024-0001")
        refreshed = await service.generate("CVE-2024-0001", refresh=True)
        missing = await service.generate("CVE-9999-9999")

    assert first is not None
    assert first.cached is False
    assert first.text == "Defensive summary text."
    assert cached is not None and cached.cached is True
    assert refreshed is not None and refreshed.cached is False
    assert missing is None
    assert FakeSummarizer.calls == 2

    async with db.session() as session:
        vulnerability = await VulnerabilityRepository(session).get_detail("CVE-2024-0001")

    assert vulnerability is not None
    assert vulnerability.ai_summary == "Defensive summary text."
    assert vulnerability.ai_summary_model == "claude-opus-5-5"
    assert vulnerability.ai_summary_at is not None


async def test_summary_endpoint_generates_and_caches(
    client: AsyncClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "secret")
    monkeypatch.setenv("VULPULSE_LLM_ENABLED", "true")
    monkeypatch.setenv("VULPULSE_LLM_API_KEY", "test-key")
    get_settings.cache_clear()
    calls: list[str] = []

    async def fake_summarize(self: VulnSummarizer, vulnerability: object) -> SummaryResult:
        calls.append("called")
        return SummaryResult("API summary text.", "claude-opus-5-5", utcnow())

    monkeypatch.setattr(VulnSummarizer, "summarize", fake_summarize)

    response = await client.post(
        "/api/v1/admin/vulns/CVE-2024-0001/summary",
        headers={"X-API-Key": "secret"},
    )
    cached = await client.post(
        "/api/v1/admin/vulns/CVE-2024-0001/summary",
        headers={"X-API-Key": "secret"},
    )
    refreshed = await client.post(
        "/api/v1/admin/vulns/CVE-2024-0001/summary",
        params={"refresh": "true"},
        headers={"X-API-Key": "secret"},
    )

    assert response.status_code == 200
    assert response.json()["text"] == "API summary text."
    assert response.json()["cached"] is False
    assert cached.json()["cached"] is True
    assert refreshed.json()["cached"] is False
    assert len(calls) == 2

    detail = await client.get("/api/v1/vulns/CVE-2024-0001")

    assert detail.status_code == 200
    assert detail.json()["ai_summary"] == "API summary text."
    assert detail.json()["ai_summary_model"] == "claude-opus-5-5"


async def test_summary_endpoint_rejects_disabled_or_unconfigured(
    client: AsyncClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "secret")
    monkeypatch.setenv("VULPULSE_LLM_ENABLED", "false")
    get_settings.cache_clear()

    disabled = await client.post(
        "/api/v1/admin/vulns/CVE-2024-0001/summary",
        headers={"X-API-Key": "secret"},
    )

    monkeypatch.setenv("VULPULSE_LLM_ENABLED", "true")
    monkeypatch.setenv("VULPULSE_LLM_API_KEY", "")
    get_settings.cache_clear()

    unconfigured = await client.post(
        "/api/v1/admin/vulns/CVE-2024-0001/summary",
        headers={"X-API-Key": "secret"},
    )

    assert disabled.status_code == 503
    assert unconfigured.status_code == 503


async def test_summary_endpoint_unknown_vulnerability(
    client: AsyncClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "secret")
    monkeypatch.setenv("VULPULSE_LLM_ENABLED", "true")
    monkeypatch.setenv("VULPULSE_LLM_API_KEY", "test-key")
    get_settings.cache_clear()

    response = await client.post(
        "/api/v1/admin/vulns/CVE-9999-9999/summary",
        headers={"X-API-Key": "secret"},
    )

    assert response.status_code == 404


async def test_summary_endpoint_maps_provider_errors(
    client: AsyncClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "secret")
    monkeypatch.setenv("VULPULSE_LLM_ENABLED", "true")
    monkeypatch.setenv("VULPULSE_LLM_API_KEY", "test-key")
    get_settings.cache_clear()

    cases = [
        (SummaryRefused("refused"), 422),
        (SummaryConfigurationError("bad config"), 503),
        (SummaryError("provider failed"), 502),
    ]
    for error, expected in cases:

        async def fail(
            self: VulnSummarizer,
            vulnerability: object,
            error: Exception = error,
        ) -> SummaryResult:
            raise error

        monkeypatch.setattr(VulnSummarizer, "summarize", fail)
        response = await client.post(
            "/api/v1/admin/vulns/CVE-2024-0001/summary",
            headers={"X-API-Key": "secret"},
        )

        assert response.status_code == expected


async def test_admin_ui_generates_summary(
    client: AsyncClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "secret")
    monkeypatch.setenv("VULPULSE_LLM_ENABLED", "true")
    monkeypatch.setenv("VULPULSE_LLM_API_KEY", "test-key")
    get_settings.cache_clear()

    async def fake_summarize(self: VulnSummarizer, vulnerability: object) -> SummaryResult:
        return SummaryResult("UI summary text.", "claude-opus-5-5", utcnow())

    monkeypatch.setattr(VulnSummarizer, "summarize", fake_summarize)

    public_page = await client.get("/vulns/CVE-2024-0001")
    assert "Generate AI summary" not in public_page.text

    login = await client.post("/admin/login", data={"api_key": "secret"})
    assert login.status_code == 303

    page = await client.get("/vulns/CVE-2024-0001")
    assert "Generate AI summary" in page.text
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None

    response = await client.post(
        "/admin/vulns/CVE-2024-0001/summary",
        data={"csrf_token": match.group(1)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    summary_page = await client.get("/vulns/CVE-2024-0001")
    assert "UI summary text." in summary_page.text
    assert "Regenerate AI summary" in summary_page.text


async def test_detail_page_shows_cached_summary(
    client: AsyncClient,
    db: Database,
    seeded: dict[str, int],
) -> None:
    async with db.session() as session:
        vulnerability = await VulnerabilityRepository(session).get_detail("CVE-2024-0001")
        assert vulnerability is not None
        vulnerability.ai_summary = "Cached defensive summary."
        vulnerability.ai_summary_model = "claude-opus-5-5"
        vulnerability.ai_summary_at = utcnow()
        await session.commit()

    response = await client.get("/vulns/CVE-2024-0001")

    assert response.status_code == 200
    assert "AI summary" in response.text
    assert "Cached defensive summary." in response.text
    assert "AI-generated" in response.text
