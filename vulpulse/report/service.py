"""Build a vulnerability report from repository data."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.config import Settings, get_settings
from vulpulse.db.repositories import VulnerabilityRepository
from vulpulse.report.builder import (
    ReportSummary,
    build_html,
    build_markdown,
)
from vulpulse.report.csv import build_csv
from vulpulse.timeutils import utcnow


@dataclass
class ReportFilters:
    q: str | None = None
    severity: str | None = None
    source: str | None = None
    vendor: str | None = None
    product: str | None = None
    kev: bool | None = None
    exploit: bool | None = None
    cvss_min: float | None = None
    epss_min: float | None = None
    risk_min: float | None = None
    published_from: datetime | None = None
    published_to: datetime | None = None
    sort: str = "risk_score"
    order: str = "desc"
    limit: int = 500

    def describe(self) -> str:
        parts: list[str] = []
        if self.q:
            parts.append(f'search "{self.q}"')
        if self.severity:
            parts.append(f"severity {self.severity}")
        if self.source:
            parts.append(f"source {self.source}")
        if self.vendor:
            parts.append(f"vendor {self.vendor}")
        if self.product:
            parts.append(f"product {self.product}")
        if self.kev:
            parts.append("KEV only")
        if self.exploit:
            parts.append("public exploit only")
        if self.cvss_min is not None:
            parts.append(f"CVSS >= {self.cvss_min}")
        if self.epss_min is not None:
            parts.append(f"EPSS >= {self.epss_min}")
        if self.risk_min is not None:
            parts.append(f"risk >= {self.risk_min}")
        if self.published_from:
            parts.append(f"published >= {self.published_from:%Y-%m-%d}")
        if self.published_to:
            parts.append(f"published <= {self.published_to:%Y-%m-%d}")
        return " · ".join(parts) if parts else "no filters"


@dataclass
class ReportResult:
    content: str
    filename: str
    total: int
    included: int
    summary: ReportSummary = field(repr=False)


async def generate_report(
    session: AsyncSession,
    filters: ReportFilters,
    report_format: str,
    *,
    settings: Settings | None = None,
) -> ReportResult:
    if report_format not in {"md", "html", "csv"}:
        raise ValueError("report_format must be 'md', 'html' or 'csv'")

    settings = settings or get_settings()
    items, total = await VulnerabilityRepository(session).search(
        q=filters.q,
        severity=filters.severity,
        source=filters.source,
        vendor=filters.vendor,
        product=filters.product,
        in_kev=filters.kev,
        exploit_available=filters.exploit,
        cvss_min=filters.cvss_min,
        epss_min=filters.epss_min,
        risk_min=filters.risk_min,
        published_from=filters.published_from,
        published_to=filters.published_to,
        sort=filters.sort,
        order=filters.order,
        limit=filters.limit,
        offset=0,
        with_details=report_format == "csv",
    )

    generated_at = utcnow()
    summary = ReportSummary.from_items(items, total)
    filters_text = filters.describe()
    base_url = settings.public_base_url

    if report_format == "md":
        content = build_markdown(
            items,
            summary,
            filters_text,
            generated_at,
            base_url,
        )
    elif report_format == "html":
        content = build_html(
            items,
            summary,
            filters_text,
            generated_at,
            base_url,
        )
    else:
        content = build_csv(items, base_url)

    suffix = report_format
    filename = f"vulpulse-report-{generated_at:%Y%m%d-%H%M%S}.{suffix}"
    return ReportResult(
        content=content,
        filename=filename,
        total=total,
        included=len(items),
        summary=summary,
    )
