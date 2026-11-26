"""Persistence layer for optional AI summaries."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.ai.summarizer import VulnSummarizer
from vulpulse.config import Settings, get_settings
from vulpulse.db.repositories import VulnerabilityRepository
from vulpulse.timeutils import utcnow


@dataclass(frozen=True)
class SummaryOutcome:
    text: str
    model: str | None
    generated_at: datetime | None
    cached: bool


class SummaryService:
    """Generate and cache one summary per vulnerability."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings | None = None,
        summarizer_factory: Callable[[Settings], VulnSummarizer] = VulnSummarizer,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.summarizer_factory = summarizer_factory

    async def generate(self, identifier: str, *, refresh: bool = False) -> SummaryOutcome | None:
        repository = VulnerabilityRepository(self.session)
        vulnerability = await repository.get_detail(identifier)
        if vulnerability is None:
            return None

        if vulnerability.ai_summary and not refresh:
            return SummaryOutcome(
                text=vulnerability.ai_summary,
                model=vulnerability.ai_summary_model,
                generated_at=vulnerability.ai_summary_at,
                cached=True,
            )

        summarizer = self.summarizer_factory(self.settings)
        try:
            result = await summarizer.summarize(vulnerability)
        finally:
            await summarizer.close()

        generated_at = utcnow()
        vulnerability.ai_summary = result.text
        vulnerability.ai_summary_model = result.model
        vulnerability.ai_summary_at = generated_at
        await self.session.commit()

        return SummaryOutcome(
            text=result.text,
            model=result.model,
            generated_at=generated_at,
            cached=False,
        )
