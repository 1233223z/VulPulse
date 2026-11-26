"""Pydantic request/response models for the public API."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "none", "unknown"]
SortField = Literal[
    "published_at",
    "modified_at",
    "cvss_score",
    "epss_score",
    "risk_score",
    "created_at",
]
Order = Literal["asc", "desc"]


class VulnSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str | None
    title: str | None
    severity: str
    risk_score: float | None
    risk_level: str | None
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


class PluginInfoOut(BaseModel):
    name: str
    description: str
    kind: str
    interval_seconds: int
    lookback_days: int
    run_on_start: bool
    api_version: int
    module: str
    entry_point: str | None
    builtin: bool


class GraphNodeOut(BaseModel):
    id: str
    type: Literal["vulnerability", "product", "cwe", "source"]
    label: str
    url: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    severity: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdgeOut(BaseModel):
    source: str
    target: str
    kind: Literal["affects", "classified_as", "reported_by"]


class VulnGraphOut(BaseModel):
    center: str
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    truncated: bool


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
    risk_breakdown: dict[str, Any] | None
    ai_summary: str | None = None
    ai_summary_model: str | None = None
    ai_summary_at: datetime | None = None
    sources: list[SourceRecordOut]
    products: list[ProductOut]
    cwes: list[CweOut]
    references: list[ReferenceOut]


class SummaryOut(BaseModel):
    text: str
    model: str | None
    generated_at: datetime | None
    cached: bool


class VendorSummary(BaseModel):
    vendor: str
    vulnerabilities: int
    products: int
    critical: int
    high: int
    medium: int
    low: int
    minimal: int
    avg_risk: float | None
    max_risk: float | None


class VendorProduct(BaseModel):
    product: str
    vulnerabilities: int
    avg_risk: float | None
    max_risk: float | None


class VendorDetail(BaseModel):
    vendor: str
    summary: VendorSummary
    products: list[VendorProduct]
    top_vulnerabilities: list[VulnSummary]


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


class RiskCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    minimal: int = 0


class StatsOverview(BaseModel):
    total: int
    severity: SeverityCounts
    risk: RiskCounts
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
