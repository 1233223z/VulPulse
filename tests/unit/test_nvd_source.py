from __future__ import annotations

from datetime import datetime, timedelta

import httpx
import respx

from vulpulse.config import Settings
from vulpulse.crawler.http import HttpClient
from vulpulse.crawler.rate_limit import AsyncRateLimiter
from vulpulse.crawler.sources.nvd import (
    NvdSource,
    _windows,
    extract_cvss,
    parse_cpe,
    parse_cve,
)
from vulpulse.timeutils import utcnow

NVD_CVE = {
    "id": "CVE-2024-0001",
    "published": "2024-01-01T00:00:00.000",
    "lastModified": "2024-02-01T12:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {"lang": "es", "value": "Ejemplo"},
        {"lang": "en", "value": "A sample vulnerability."},
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "type": "Secondary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L",
                    "baseScore": 7.5,
                    "baseSeverity": "HIGH",
                },
            }
        ]
    },
    "weaknesses": [
        {
            "description": [
                {"lang": "en", "value": "CWE-79"},
                {"lang": "en", "value": "NVD-CWE-Other"},
            ]
        }
    ],
    "configurations": [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:apache:struts:2.5.0:*:*:*:*:*:*:*",
                            "versionEndExcluding": "2.5.1",
                        }
                    ]
                }
            ]
        }
    ],
    "references": [{"url": "https://example.test/advisory"}],
}


def test_parse_cve_maps_core_fields() -> None:
    vuln = parse_cve(NVD_CVE)

    assert vuln is not None
    assert vuln.cve_id == "CVE-2024-0001"
    assert vuln.description == "A sample vulnerability."
    assert vuln.severity == "high"
    assert vuln.cvss_score == 7.5
    assert vuln.cvss_vector == "CVSS:3.1/AV:N/AC:L"
    assert vuln.cvss_version == "3.1"
    assert vuln.vuln_status == "Analyzed"
    assert vuln.published_at == datetime(2024, 1, 1)
    assert vuln.modified_at == datetime(2024, 2, 1, 12, 0)
    assert vuln.cwes == ["CWE-79"]
    assert vuln.references == ["https://example.test/advisory"]
    assert vuln.source_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"


def test_parse_cve_maps_products_and_version_ranges() -> None:
    vuln = parse_cve(NVD_CVE)

    assert vuln is not None
    assert len(vuln.products) == 1
    product = vuln.products[0]
    assert product.vendor == "apache"
    assert product.product == "struts"
    assert product.version_range == "< 2.5.1"
    assert product.cpe is not None


def test_parse_cve_without_id_returns_none() -> None:
    assert parse_cve({"descriptions": []}) is None


def test_cvss_prefers_v4_over_v3() -> None:
    metrics = {
        "cvssMetricV31": [
            {
                "type": "Primary",
                "cvssData": {"version": "3.1", "baseScore": 5.0, "baseSeverity": "MEDIUM"},
            }
        ],
        "cvssMetricV40": [
            {
                "type": "Primary",
                "cvssData": {"version": "4.0", "baseScore": 9.1, "baseSeverity": "CRITICAL"},
            }
        ],
    }

    score, _, version, severity = extract_cvss(metrics)

    assert score == 9.1
    assert version == "4.0"
    assert severity == "critical"


def test_parse_cpe() -> None:
    assert parse_cpe("cpe:2.3:a:apache:struts:2.5.0:*:*:*:*:*:*:*") == (
        "apache",
        "struts",
    )
    assert parse_cpe("not-a-cpe") == (None, None)
    assert parse_cpe("cpe:2.3:a:*:*:*:*:*:*:*:*:*") == (None, None)


def test_windows_split_long_ranges() -> None:
    start = datetime(2024, 1, 1)
    end = start + timedelta(days=365)

    windows = list(_windows(start, end))

    assert len(windows) == 4
    assert windows[0][0] == start
    assert windows[-1][1] == end


@respx.mock
async def test_fetch_paginates_and_sends_api_key() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        nvd_base_url="https://nvd.test/cves",
        nvd_api_key="secret-key",
    )
    page_one = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 2,
        "vulnerabilities": [{"cve": NVD_CVE}],
    }
    page_two = {
        "resultsPerPage": 1,
        "startIndex": 1,
        "totalResults": 2,
        "vulnerabilities": [{"cve": {**NVD_CVE, "id": "CVE-2024-0002"}}],
    }
    route = respx.get("https://nvd.test/cves").mock(
        side_effect=[
            httpx.Response(200, json=page_one),
            httpx.Response(200, json=page_two),
        ]
    )

    client = HttpClient(rate_limiter=AsyncRateLimiter(100, 1.0))
    source = NvdSource(settings, client=client)
    try:
        items = [item async for item in source.fetch(since=utcnow() - timedelta(days=1))]
    finally:
        await client.aclose()

    assert [item.cve_id for item in items] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert route.call_count == 2
    first_request = route.calls[0].request
    assert first_request.headers["apiKey"] == "secret-key"
    assert first_request.url.params["startIndex"] == "0"
    assert route.calls[1].request.url.params["startIndex"] == "1"
