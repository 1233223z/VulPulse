"""Base class for vulnerability data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from vulpulse.config import Settings
from vulpulse.crawler.http import HttpClient
from vulpulse.crawler.models import RawVuln
from vulpulse.crawler.rate_limit import AsyncRateLimiter

PLUGIN_API_VERSION = 1


@dataclass(frozen=True)
class SchedulePolicy:
    """How a source participates in the scheduler."""

    interval_seconds: int
    lookback_days: int = 0
    run_on_start: bool = True


class BaseSource(ABC):
    """A concrete data source (NVD, CISA KEV, ...).

    Subclasses implement :meth:`fetch` as an async generator. The base class
    only owns the HTTP client lifecycle; persistence and merging happen in the
    service layer.

    Source plugins are regular ``BaseSource`` subclasses with metadata and a
    ``vulpulse.sources`` entry point. See ``docs/plugins.md``.
    """

    name: str
    kind: str = "api"
    description: str = ""
    plugin_api_version: int = PLUGIN_API_VERSION
    #: Default scheduler interval for plugins that do not override
    #: :meth:`plugin_schedule`.
    default_interval_minutes: int = 360
    default_lookback_days: int = 7
    #: (requests, seconds) used when this source does not supply a client.
    default_rate_limit: tuple[int, float] = (1, 1.0)

    def __init__(self, settings: Settings, client: HttpClient | None = None) -> None:
        self.settings = settings
        self._owns_client = client is None

        if client is None:
            rate, period = self.default_rate_limit
            client = HttpClient(
                timeout=settings.http_timeout_seconds,
                user_agent=settings.http_user_agent,
                rate_limiter=AsyncRateLimiter(rate, period),
                max_response_bytes=settings.http_max_response_bytes,
                max_redirects=settings.http_max_redirects,
            )
        self.client = client

    @classmethod
    def plugin_schedule(cls, settings: Settings) -> SchedulePolicy:
        """Return the default schedule for this source plugin."""
        if cls.default_interval_minutes <= 0:
            raise ValueError("default_interval_minutes must be positive")
        if cls.default_lookback_days < 0:
            raise ValueError("default_lookback_days must be zero or positive")
        return SchedulePolicy(
            interval_seconds=cls.default_interval_minutes * 60,
            lookback_days=cls.default_lookback_days,
            run_on_start=settings.scheduler_run_on_start,
        )

    @abstractmethod
    def fetch(
        self,
        *,
        since: datetime | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> AsyncIterator[RawVuln]:
        """Yield raw vulnerabilities, optionally since a checkpoint."""

    async def close(self) -> None:
        """Release the HTTP client if this source created it."""
        if self._owns_client:
            await self.client.aclose()
