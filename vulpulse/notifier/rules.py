"""Subscription rule model and matching logic."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulpulse.db.models import Vulnerability
from vulpulse.timeutils import utcnow


class SubscriptionRule(BaseModel):
    """A user-defined filter evaluated against each candidate vulnerability."""

    model_config = ConfigDict(extra="forbid")

    severities: list[str] = Field(default_factory=lambda: ["critical", "high"])
    keywords: list[str] = Field(default_factory=list)
    vendors: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    in_kev: bool | None = None
    exploit_available: bool | None = None
    cvss_min: float | None = Field(default=None, ge=0, le=10)
    epss_min: float | None = Field(default=None, ge=0, le=1)
    published_within_days: int | None = Field(default=None, ge=1, le=365)

    @field_validator("severities", "vendors", "products", "sources", mode="before")
    @classmethod
    def _normalize_lower(cls, value: Any) -> Any:
        if isinstance(value, list):
            return sorted({str(item).strip().lower() for item in value if str(item).strip()})
        return value

    @field_validator("keywords", mode="before")
    @classmethod
    def _normalize_keywords(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return value

    def matches(self, vuln: Vulnerability) -> bool:
        severity = (vuln.severity or "unknown").lower()
        if self.severities and severity not in self.severities:
            return False

        if self.in_kev is not None and vuln.in_kev != self.in_kev:
            return False
        if self.exploit_available is not None and vuln.exploit_available != self.exploit_available:
            return False
        if self.cvss_min is not None and (
            vuln.cvss_score is None or vuln.cvss_score < self.cvss_min
        ):
            return False
        if self.epss_min is not None and (
            vuln.epss_score is None or vuln.epss_score < self.epss_min
        ):
            return False

        if self.keywords:
            haystack = " ".join(
                part for part in (vuln.cve_id, vuln.title, vuln.description) if part
            ).lower()
            if not any(keyword.lower() in haystack for keyword in self.keywords):
                return False

        if self.sources:
            source_names = {
                record.source.name
                for record in vuln.source_records
                if record.source is not None and record.source.name
            }
            if not source_names.intersection(self.sources):
                return False

        if (self.vendors or self.products) and not any(
            self._product_matches(link) for link in vuln.product_links
        ):
            return False

        if self.published_within_days is not None:
            reference = vuln.published_at or vuln.created_at
            if reference is not None and reference < utcnow() - timedelta(
                days=self.published_within_days
            ):
                return False

        return True

    def _product_matches(self, link: Any) -> bool:
        product = getattr(link, "product", None)
        if product is None:
            return False
        if self.vendors and (product.vendor or "").lower() not in self.vendors:
            return False
        if self.products:
            return (product.product or "").lower() in self.products
        return True
