from __future__ import annotations

from datetime import date

import httpx
import respx

from vulpulse.config import Settings
from vulpulse.crawler.http import HttpClient
from vulpulse.crawler.rate_limit import AsyncRateLimiter
from vulpulse.crawler.sources.cisa_kev import CisaKevSource, parse_entry

KEV_ENTRY = {
    "cveID": "CVE-2024-0001",
    "vendorProject": "Apache",
    "product": "Struts",
    "vulnerabilityName": "Apache Struts Remote Code Execution",
    "dateAdded": "2024-01-02",
    "shortDescription": "A vulnerability in Apache Struts.",
    "requiredAction": "Apply updates.",
    "dueDate": "2024-01-23",
    "knownRansomwareCampaignUse": "Unknown",
}


def test_parse_entry_maps_kev_fields() -> None:
    vuln = parse_entry(KEV_ENTRY)

    assert vuln is not None
    assert vuln.cve_id == "CVE-2024-0001"
    assert vuln.title == "Apache Struts Remote Code Execution"
    assert vuln.in_kev is True
    assert vuln.kev_due_date == date(2024, 1, 23)
    assert vuln.products[0].vendor == "Apache"
    assert vuln.products[0].product == "Struts"
    assert vuln.description is None


def test_parse_entry_without_cve_returns_none() -> None:
    assert parse_entry({"vendorProject": "Apache"}) is None


@respx.mock
async def test_fetch_reads_the_whole_feed() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        kev_feed_url="https://kev.test/feed.json",
    )
    respx.get("https://kev.test/feed.json").mock(
        return_value=httpx.Response(
            200,
            json={"vulnerabilities": [KEV_ENTRY, {"vendorProject": "No CVE"}]},
        )
    )

    client = HttpClient(rate_limiter=AsyncRateLimiter(10, 1.0))
    source = CisaKevSource(settings, client=client)
    try:
        items = [item async for item in source.fetch()]
    finally:
        await client.aclose()

    assert [item.cve_id for item in items] == ["CVE-2024-0001"]
