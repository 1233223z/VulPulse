"""Base class for vulnerability data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

from vulpulse.config import Settings
from vulpulse.crawler.http import HttpClient
from vulpulse.crawler.models import RawVuln
from vulpulse.crawler.rate_limit import AsyncRateLimiter


class BaseSource(ABC):
    """A concrete data source (NVD, CISA KEV, ...).

    Subclasses implement :meth:`fetch` as an async generator. The base class
    only owns the HTTP client lifecycle; persistence and merging happen in the
    service layer.
    """

    name: str
    kind: str = "api"
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
            )
        self.client = client

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
