"""Example VulPulse source plugin.

Install this package to see a third-party source appear in ``vulpulse
plugins`` and the scheduler. Replace ``fetch`` with a real public source.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

from vulpulse.crawler.base import BaseSource
from vulpulse.crawler.models import RawVuln


class ExampleSource(BaseSource):
    """Synthetic source used to demonstrate the plugin contract."""

    name = "example"
    kind = "demo"
    description = "Example plugin that emits one synthetic vulnerability."
    plugin_api_version = 1
    default_interval_minutes = 720
    default_lookback_days = 0

    async def fetch(
        self,
        *,
        since: datetime | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> AsyncIterator[RawVuln]:
        yield RawVuln(
            source=self.name,
            source_vuln_id="EXAMPLE-0001",
            title="Example plugin record",
            description=(
                "Synthetic record produced by the VulPulse example source "
                "plugin. It is not a real vulnerability."
            ),
            severity="low",
            source_url="https://example.invalid/vulpulse-plugin",
            raw={"demo": True},
        )
