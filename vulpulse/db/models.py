"""SQLAlchemy ORM models for VulPulse.

The schema is intentionally CVE-centric: one canonical row per vulnerability,
with per-source raw records kept alongside for auditability.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vulpulse.db.base import Base, TimestampMixin, utcnow


class Source(Base, TimestampMixin):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(512))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime)

    records: Mapped[list[SourceRecord]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )
    crawl_runs: Mapped[list[CrawlRun]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vuln_published_at", "published_at"),
        Index("ix_vuln_severity", "severity"),
        Index("ix_vuln_risk_score", "risk_score"),
        Index("ix_vuln_cvss_score", "cvss_score"),
        Index("ix_vuln_in_kev", "in_kev"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dedupe_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(32), unique=True)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    risk_score: Mapped[float | None] = mapped_column(Float)
    risk_level: Mapped[str | None] = mapped_column(String(16))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    cvss_version: Mapped[str | None] = mapped_column(String(16))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="active", nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime)

    source_records: Mapped[list[SourceRecord]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    product_links: Mapped[list[VulnProduct]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    cwe_links: Mapped[list[VulnCwe]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    references: Mapped[list[VulnReference]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class SourceRecord(Base):
    __tablename__ = "source_records"
    __table_args__ = (
        UniqueConstraint("source_id", "source_vuln_id", name="uq_source_records_source_vuln"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    source_id: Mapped[int] = mapped_column(
        ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
    )
    source_vuln_id: Mapped[str] = mapped_column(String(128), nullable=False)
    url: Mapped[str | None] = mapped_column(String(1024))
    raw_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="source_records")
    source: Mapped[Source] = relationship(back_populates="records")


class Product(Base):
    __tablename__ = "products"
    __table_args__ = (UniqueConstraint("vendor", "product", name="uq_products_vendor_product"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vendor: Mapped[str | None] = mapped_column(String(128))
    product: Mapped[str] = mapped_column(String(128), nullable=False)

    vuln_links: Mapped[list[VulnProduct]] = relationship(
        back_populates="product", cascade="all, delete-orphan"
    )


class VulnProduct(Base):
    __tablename__ = "vuln_products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"), nullable=False
    )
    version_range: Mapped[str | None] = mapped_column(String(255))
    cpe: Mapped[str | None] = mapped_column(String(512))

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="product_links")
    product: Mapped[Product] = relationship(back_populates="vuln_links")


class Cwe(Base):
    __tablename__ = "cwe"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str | None] = mapped_column(String(255))

    vuln_links: Mapped[list[VulnCwe]] = relationship(
        back_populates="cwe", cascade="all, delete-orphan"
    )


class VulnCwe(Base):
    __tablename__ = "vuln_cwe"

    vuln_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True
    )
    cwe_id: Mapped[str] = mapped_column(ForeignKey("cwe.id"), primary_key=True)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="cwe_links")
    cwe: Mapped[Cwe] = relationship(back_populates="vuln_links")


class VulnReference(Base):
    __tablename__ = "vuln_references"
    __table_args__ = (UniqueConstraint("vuln_id", "url", name="uq_vuln_references_vuln_url"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    tags: Mapped[list[str] | None] = mapped_column(JSON)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="references")


class Channel(Base, TimestampMixin):
    __tablename__ = "channels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    subscriptions: Mapped[list[Subscription]] = relationship(
        back_populates="channel", cascade="all, delete-orphan"
    )


class Subscription(Base, TimestampMixin):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    rule_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    channel_id: Mapped[int] = mapped_column(
        ForeignKey("channels.id", ondelete="CASCADE"), nullable=False
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)

    channel: Mapped[Channel] = relationship(back_populates="subscriptions")
    deliveries: Mapped[list[Delivery]] = relationship(
        back_populates="subscription", cascade="all, delete-orphan"
    )


class Delivery(Base):
    __tablename__ = "deliveries"
    __table_args__ = (
        UniqueConstraint("subscription_id", "vuln_id", "channel_id", name="uq_deliveries_target"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subscription_id: Mapped[int] = mapped_column(
        ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False
    )
    vuln_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    channel_id: Mapped[int] = mapped_column(
        ForeignKey("channels.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    subscription: Mapped[Subscription] = relationship(back_populates="deliveries")
    vulnerability: Mapped[Vulnerability] = relationship()
    channel: Mapped[Channel] = relationship()


class CrawlRun(Base):
    __tablename__ = "crawl_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("sources.id", ondelete="CASCADE"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(16), default="running", nullable=False)
    stats: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    checkpoint: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    source: Mapped[Source] = relationship(back_populates="crawl_runs")
