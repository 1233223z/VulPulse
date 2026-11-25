"""Vendor and product correlation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.api.deps import get_session
from vulpulse.api.schemas import (
    VendorDetail,
    VendorProduct,
    VendorSummary,
    VulnSummary,
)
from vulpulse.db.repositories import VendorRepository, VulnerabilityRepository

router = APIRouter(prefix="/vendors", tags=["vendors"])


@router.get("", response_model=list[VendorSummary])
async def list_vendors(
    limit: int = Query(default=20, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> list[VendorSummary]:
    rows = await VendorRepository(session).list_top(limit)
    return [VendorSummary(**row) for row in rows]


@router.get("/{vendor}", response_model=VendorDetail)
async def vendor_detail(
    vendor: str,
    session: AsyncSession = Depends(get_session),
) -> VendorDetail:
    repository = VendorRepository(session)
    summary = await repository.get_summary(vendor)
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vendor not found",
        )

    products = await repository.get_products(vendor)
    top_vulnerabilities, _ = await VulnerabilityRepository(session).search(
        vendor=vendor,
        sort="risk_score",
        order="desc",
        limit=10,
    )

    return VendorDetail(
        vendor=summary["vendor"],
        summary=VendorSummary(**summary),
        products=[VendorProduct(**item) for item in products],
        top_vulnerabilities=[
            VulnSummary.model_validate(vulnerability) for vulnerability in top_vulnerabilities
        ],
    )
