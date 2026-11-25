"""Vulnerability list and detail endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.analyzer.scorer import RiskWeights, score_risk
from vulpulse.api.deps import get_session
from vulpulse.api.schemas import (
    CweOut,
    Order,
    ProductOut,
    ReferenceOut,
    Severity,
    SortField,
    SourceRecordOut,
    VulnDetail,
    VulnPage,
    VulnSummary,
)
from vulpulse.config import get_settings
from vulpulse.db.repositories import VulnerabilityRepository

router = APIRouter(prefix="/vulns", tags=["vulnerabilities"])


@router.get("", response_model=VulnPage)
async def list_vulns(
    q: str | None = Query(default=None, max_length=200),
    severity: Severity | None = None,
    source: str | None = None,
    vendor: str | None = None,
    kev: bool | None = None,
    exploit: bool | None = None,
    cvss_min: float | None = Query(default=None, ge=0, le=10),
    epss_min: float | None = Query(default=None, ge=0, le=1),
    risk_min: float | None = Query(default=None, ge=0, le=100),
    published_from: datetime | None = None,
    published_to: datetime | None = None,
    sort: SortField = "published_at",
    order: Order = "desc",
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> VulnPage:
    repository = VulnerabilityRepository(session)
    items, total = await repository.search(
        q=q,
        severity=severity,
        source=source,
        vendor=vendor,
        in_kev=kev,
        exploit_available=exploit,
        cvss_min=cvss_min,
        epss_min=epss_min,
        risk_min=risk_min,
        published_from=published_from,
        published_to=published_to,
        sort=sort,
        order=order,
        limit=size,
        offset=(page - 1) * size,
    )

    return VulnPage(
        items=[VulnSummary.model_validate(item) for item in items],
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size,
    )


@router.get("/{identifier}", response_model=VulnDetail)
async def get_vuln(
    identifier: str,
    session: AsyncSession = Depends(get_session),
) -> VulnDetail:
    repository = VulnerabilityRepository(session)
    vuln = await repository.get_detail(identifier)
    if vuln is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )

    settings = get_settings()
    risk = score_risk(
        vuln,
        RiskWeights.from_settings(settings),
        recency_days=settings.risk_recency_days,
    )

    summary = VulnSummary.model_validate(vuln)
    summary.risk_score = risk.score
    summary.risk_level = risk.level

    return VulnDetail(
        **summary.model_dump(),
        description=vuln.description,
        cvss_vector=vuln.cvss_vector,
        cvss_version=vuln.cvss_version,
        epss_percentile=vuln.epss_percentile,
        kev_due_date=vuln.kev_due_date,
        status=vuln.status,
        risk_breakdown=risk.components,
        sources=[
            SourceRecordOut(
                source=record.source.name,
                source_vuln_id=record.source_vuln_id,
                url=record.url,
                fetched_at=record.fetched_at,
            )
            for record in vuln.source_records
        ],
        products=[
            ProductOut(
                vendor=link.product.vendor,
                product=link.product.product,
                version_range=link.version_range,
                cpe=link.cpe,
            )
            for link in vuln.product_links
        ],
        cwes=[CweOut(id=link.cwe.id, name=link.cwe.name) for link in vuln.cwe_links],
        references=[
            ReferenceOut(url=reference.url, tags=reference.tags) for reference in vuln.references
        ],
    )
