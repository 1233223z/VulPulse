"""Pydantic request/response models for the public API."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "none", "unknown"]
SortField = Literal[
    "published_at",
    "modified_at",
    "cvss_score",
    "epss_score",
    "created_at",
]
Order = Literal["asc", "desc"]


class VulnSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str | None
    title: str | None
    severity: str
    cvss_score: float | None
    epss_score: float | None
    in_kev: bool
    exploit_available: bool
    published_at: datetime | None
    modified_at: datetime | None


class VulnPage(BaseModel):
    items: list[VulnSummary]
    total: int
    page: int
    size: int
    pages: int


class SourceRecordOut(BaseModel):
    source: str
    source_vuln_id: str
    url: str | None
    fetched_at: datetime


class ProductOut(BaseModel):
    vendor: str | None
    product: str
    version_range: str | None
    cpe: str | None


class CweOut(BaseModel):
    id: str
    name: str | None


class ReferenceOut(BaseModel):
    url: str
    tags: list[str] | None


class VulnDetail(VulnSummary):
    description: str | None
    cvss_vector: str | None
    cvss_version: str | None
    epss_percentile: float | None
    kev_due_date: date | None
    status: str
    sources: list[SourceRecordOut]
    products: list[ProductOut]
    cwes: list[CweOut]
    references: list[ReferenceOut]


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    none: int = 0
    unknown: int = 0


class TrendPoint(BaseModel):
    date: str
    count: int


class StatsOverview(BaseModel):
    total: int
    severity: SeverityCounts
    in_kev: int
    exploit_available: int
    epss_scored: int
    trend: list[TrendPoint]


class LastRunOut(BaseModel):
    status: str
    started_at: datetime
    finished_at: datetime | None
    stats: dict[str, int] | None


class SourceInfo(BaseModel):
    id: int
    name: str
    kind: str
    base_url: str | None
    enabled: bool
    last_success_at: datetime | None
    records: int
    last_run: LastRunOut | None


class CrawlRequest(BaseModel):
    source: str = Field(min_length=1, max_length=64)
    since_days: int = Field(7, ge=0, le=365)


class CrawlAccepted(BaseModel):
    status: str
    source: str
    since_days: int


class HealthStatus(BaseModel):
    status: str
    database: str
