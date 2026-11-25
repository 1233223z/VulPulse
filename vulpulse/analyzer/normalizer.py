"""Turn :class:`RawVuln` records into database-ready field mappings.

Only fields a source actually knows about are returned. This is what makes
merging safe: a KEV record can set ``in_kev=True`` without clobbering the
CVSS score that NVD supplied earlier.
"""

from __future__ import annotations

from typing import Any

from vulpulse.crawler.models import RawVuln
from vulpulse.timeutils import to_naive_utc

_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "negligible": "low",
    "none": "none",
    "unknown": "unknown",
}


def severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to a qualitative severity."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def normalize_severity(value: str | None, score: float | None) -> str:
    """Prefer an explicit severity, falling back to the CVSS score."""
    if value:
        mapped = _SEVERITY_ALIASES.get(value.strip().lower())
        if mapped is not None:
            return mapped
    return severity_from_score(score)


def normalize_raw(raw: RawVuln) -> dict[str, Any]:
    """Build the subset of ORM fields this raw record should update."""
    fields: dict[str, Any] = {
        "cve_id": raw.cve_id,
        "title": raw.title,
        "description": raw.description,
        "cvss_score": raw.cvss_score,
        "cvss_vector": raw.cvss_vector,
        "cvss_version": raw.cvss_version,
        "epss_score": raw.epss_score,
        "epss_percentile": raw.epss_percentile,
        "published_at": to_naive_utc(raw.published_at),
        "modified_at": to_naive_utc(raw.modified_at),
    }

    if raw.severity is not None or raw.cvss_score is not None:
        fields["severity"] = normalize_severity(raw.severity, raw.cvss_score)

    if raw.vuln_status:
        fields["status"] = raw.vuln_status.strip().lower()

    if raw.in_kev:
        fields["in_kev"] = True
        fields["kev_due_date"] = raw.kev_due_date

    if raw.exploit_available:
        fields["exploit_available"] = True

    return {key: value for key, value in fields.items() if value is not None}


def first_sentence(text: str | None, max_length: int = 200) -> str | None:
    """Small helper for deriving a display title from a description."""
    if not text:
        return None
    cleaned = " ".join(text.split())
    if not cleaned:
        return None
    for separator in (". ", "。", "\n"):
        if separator in cleaned:
            cleaned = cleaned.split(separator, 1)[0]
            break
    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 1].rstrip() + "…"
    return cleaned
