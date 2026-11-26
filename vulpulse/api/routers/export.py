"""Report export endpoint."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.api.deps import get_session
from vulpulse.api.schemas import Order, Severity, SortField
from vulpulse.report.service import ReportFilters, generate_report

router = APIRouter(tags=["export"])


@router.get("/export")
async def export_report(
    report_format: Literal["md", "html", "csv"] = Query(default="md", alias="format"),
    q: str | None = Query(default=None, max_length=200),
    severity: Severity | None = None,
    source: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    kev: bool | None = None,
    exploit: bool | None = None,
    cvss_min: float | None = Query(default=None, ge=0, le=10),
    epss_min: float | None = Query(default=None, ge=0, le=1),
    risk_min: float | None = Query(default=None, ge=0, le=100),
    published_from: datetime | None = None,
    published_to: datetime | None = None,
    sort: SortField = "risk_score",
    order: Order = "desc",
    limit: int = Query(default=500, ge=1, le=2000),
    session: AsyncSession = Depends(get_session),
) -> Response:
    result = await generate_report(
        session,
        ReportFilters(
            q=q,
            severity=severity,
            source=source,
            vendor=vendor,
            product=product,
            kev=kev,
            exploit=exploit,
            cvss_min=cvss_min,
            epss_min=epss_min,
            risk_min=risk_min,
            published_from=published_from,
            published_to=published_to,
            sort=sort,
            order=order,
            limit=limit,
        ),
        report_format,
    )

    media_types = {
        "md": "text/markdown; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "csv": "text/csv; charset=utf-8",
    }
    return Response(
        content=result.content,
        media_type=media_types[report_format],
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"',
        },
    )
