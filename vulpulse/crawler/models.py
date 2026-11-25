"""Source-agnostic raw vulnerability models."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RawProduct(BaseModel):
    """A vendor/product pair as reported by a source."""

    model_config = ConfigDict(frozen=True)

    vendor: str | None = None
    product: str | None = None
    version_range: str | None = None
    cpe: str | None = None


class RawVuln(BaseModel):
    """Normalized-in-shape record produced by a crawler.

    Source adapters are responsible for mapping their payload into this model;
    the analyzer layer decides how conflicts between sources are resolved.
    """

    model_config = ConfigDict(extra="forbid")

    source: str
    source_vuln_id: str
    cve_id: str | None = None
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    in_kev: bool | None = None
    kev_due_date: date | None = None
    exploit_available: bool | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    references: list[str] = Field(default_factory=list)
    products: list[RawProduct] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    source_url: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cve_id")
    @classmethod
    def _normalize_cve_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        return normalized or None

    @field_validator("severity")
    @classmethod
    def _normalize_severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        return normalized or None

    @field_validator("cvss_score")
    @classmethod
    def _validate_cvss_score(cls, value: float | None) -> float | None:
        if value is not None and not 0.0 <= value <= 10.0:
            raise ValueError("cvss_score must be between 0 and 10")
        return value

    @field_validator("epss_score", "epss_percentile")
    @classmethod
    def _validate_epss(cls, value: float | None) -> float | None:
        if value is not None and not 0.0 <= value <= 1.0:
            raise ValueError("EPSS values must be between 0 and 1")
        return value

    @property
    def dedupe_key(self) -> str:
        """Stable key used to merge records across sources."""
        if self.cve_id:
            return f"cve:{self.cve_id}"
        return f"src:{self.source}:{self.source_vuln_id}"
