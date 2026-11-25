"""CISA Known Exploited Vulnerabilities (KEV) feed source."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date, datetime
from typing import Any

from vulpulse.crawler.base import BaseSource
from vulpulse.crawler.models import RawProduct, RawVuln
from vulpulse.crawler.registry import register_source

_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


@register_source
class CisaKevSource(BaseSource):
    """Download the full KEV catalog. It is small enough to sync wholesale."""

    name = "cisa_kev"
    kind = "feed"
    default_rate_limit = (1, 10.0)

    async def fetch(
        self,
        *,
        since: datetime | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> AsyncIterator[RawVuln]:
        payload = await self.client.get_json(self.settings.kev_feed_url)
        if not isinstance(payload, dict):
            return

        for entry in payload.get("vulnerabilities") or []:
            if isinstance(entry, dict):
                parsed = parse_entry(entry)
                if parsed is not None:
                    yield parsed


def parse_entry(entry: dict[str, Any]) -> RawVuln | None:
    cve_id = entry.get("cveID")
    if not isinstance(cve_id, str) or not cve_id:
        return None

    due_date = _parse_date(entry.get("dueDate"))
    vendor = _text(entry.get("vendorProject"))
    product = _text(entry.get("product"))
    products = [RawProduct(vendor=vendor, product=product)] if product else []

    return RawVuln(
        source="cisa_kev",
        source_vuln_id=cve_id,
        cve_id=cve_id,
        title=_text(entry.get("vulnerabilityName")),
        in_kev=True,
        kev_due_date=due_date,
        products=products,
        source_url=_KEV_CATALOG_URL,
        raw=entry,
    )


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None
