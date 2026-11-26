"""CSV export with spreadsheet formula-injection protection."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote

HEADERS = [
    "cve_id",
    "title",
    "severity",
    "risk_score",
    "risk_level",
    "cvss_score",
    "epss_score",
    "in_kev",
    "exploit_available",
    "published_at",
    "modified_at",
    "vendors",
    "products",
    "cwes",
    "source_count",
    "url",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    # Prevent spreadsheet formula injection when the CSV is opened in Excel.
    if text.startswith(_FORMULA_PREFIXES):
        return f"'{text}"
    return text


def _vuln_url(vulnerability: Any, base_url: str) -> str:
    identifier = vulnerability.cve_id or str(vulnerability.id)
    return f"{base_url.rstrip('/')}/vulns/{quote(identifier, safe='')}"


def build_csv(items: Iterable[Any], base_url: str) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(HEADERS)

    for vulnerability in items:
        vendors = {
            link.product.vendor for link in vulnerability.product_links if link.product.vendor
        }
        products = {link.product.product for link in vulnerability.product_links}
        cwe_ids = {link.cwe.id for link in vulnerability.cwe_links}
        writer.writerow(
            [
                _cell(vulnerability.cve_id),
                _cell(vulnerability.title),
                _cell(vulnerability.severity),
                _cell(vulnerability.risk_score),
                _cell(vulnerability.risk_level),
                _cell(vulnerability.cvss_score),
                _cell(vulnerability.epss_score),
                _cell("true" if vulnerability.in_kev else "false"),
                _cell("true" if vulnerability.exploit_available else "false"),
                _cell(
                    vulnerability.published_at.isoformat() if vulnerability.published_at else None
                ),
                _cell(vulnerability.modified_at.isoformat() if vulnerability.modified_at else None),
                _cell(", ".join(sorted(vendors))),
                _cell(", ".join(sorted(products))),
                _cell(", ".join(sorted(cwe_ids))),
                _cell(len(vulnerability.source_records)),
                _cell(_vuln_url(vulnerability, base_url)),
            ]
        )
    return buffer.getvalue()
