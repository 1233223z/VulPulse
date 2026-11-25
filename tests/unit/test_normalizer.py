from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vulpulse.analyzer.normalizer import (
    first_sentence,
    normalize_raw,
    normalize_severity,
    severity_from_score,
)
from vulpulse.crawler.models import RawVuln
from vulpulse.timeutils import parse_datetime


def test_severity_from_score() -> None:
    assert severity_from_score(None) == "unknown"
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(4.0) == "medium"
    assert severity_from_score(0.1) == "low"
    assert severity_from_score(0.0) == "none"


def test_normalize_severity_aliases_and_fallback() -> None:
    assert normalize_severity("MODERATE", None) == "medium"
    assert normalize_severity("Important", None) == "high"
    assert normalize_severity(None, 5.5) == "medium"
    assert normalize_severity("nonsense", None) == "unknown"


def test_kev_record_only_sets_its_own_fields() -> None:
    raw = RawVuln(
        source="cisa_kev",
        source_vuln_id="CVE-2024-0001",
        cve_id="CVE-2024-0001",
        title="KEV title",
        in_kev=True,
    )

    fields = normalize_raw(raw)

    assert fields["title"] == "KEV title"
    assert fields["in_kev"] is True
    for key in ("severity", "description", "status", "cvss_score", "published_at"):
        assert key not in fields


def test_nvd_record_keeps_base_fields() -> None:
    raw = RawVuln(
        source="nvd",
        source_vuln_id="CVE-2024-0001",
        cve_id="CVE-2024-0001",
        description="NVD description",
        severity="HIGH",
        cvss_score=8.1,
        vuln_status="Analyzed",
    )

    fields = normalize_raw(raw)

    assert fields["description"] == "NVD description"
    assert fields["severity"] == "high"
    assert fields["cvss_score"] == 8.1
    assert fields["status"] == "analyzed"
    assert "in_kev" not in fields


def test_aware_datetime_is_converted_to_naive_utc() -> None:
    raw = RawVuln(
        source="nvd",
        source_vuln_id="CVE-2024-0001",
        published_at=datetime(2024, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=8))),
    )

    fields = normalize_raw(raw)

    assert fields["published_at"] == datetime(2024, 1, 1, 4, 0)


def test_first_sentence() -> None:
    assert first_sentence("Hello world. More text") == "Hello world"
    assert first_sentence("中文句子。后面") == "中文句子"
    assert first_sentence(None) is None


def test_parse_datetime() -> None:
    assert parse_datetime("2024-01-01T00:00:00.000") == datetime(2024, 1, 1)
    assert parse_datetime("2024-01-01T00:00:00Z") == datetime(2024, 1, 1)
    assert parse_datetime("not-a-date") is None
