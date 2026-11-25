"""Explainable 0-100 vulnerability risk scoring.

The score combines five signals into a weighted average:

- CVSS base score (or a severity fallback when no CVSS is available)
- FIRST EPSS probability
- CISA KEV membership
- Public exploit availability
- Recency, decaying over a configurable window

Every component is exposed in the result so the UI can explain the score.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from vulpulse.config import Settings
from vulpulse.timeutils import utcnow

_SEVERITY_FALLBACK = {
    "critical": 90.0,
    "high": 70.0,
    "medium": 45.0,
    "low": 20.0,
    "none": 0.0,
    "unknown": 30.0,
}


class RiskFields(Protocol):
    severity: str
    cvss_score: float | None
    epss_score: float | None
    in_kev: bool
    exploit_available: bool
    published_at: datetime | None
    modified_at: datetime | None
    created_at: datetime | None


@dataclass(frozen=True)
class RiskWeights:
    cvss: float = 0.40
    epss: float = 0.25
    kev: float = 0.20
    exploit: float = 0.10
    recency: float = 0.05

    @classmethod
    def from_settings(cls, settings: Settings) -> RiskWeights:
        return cls(
            cvss=settings.risk_weight_cvss,
            epss=settings.risk_weight_epss,
            kev=settings.risk_weight_kev,
            exploit=settings.risk_weight_exploit,
            recency=settings.risk_weight_recency,
        )

    def normalized(self) -> dict[str, float]:
        values = {
            "cvss": self.cvss,
            "epss": self.epss,
            "kev": self.kev,
            "exploit": self.exploit,
            "recency": self.recency,
        }
        total = sum(values.values())
        if total <= 0:
            raise ValueError("risk weights must sum to a positive value")
        return {key: value / total for key, value in values.items()}


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: str
    components: dict[str, dict[str, Any]]


def risk_level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


def score_risk(
    vuln: RiskFields,
    weights: RiskWeights | None = None,
    *,
    recency_days: int = 90,
    now: datetime | None = None,
) -> RiskResult:
    weights = weights or RiskWeights()
    normalized = weights.normalized()
    now = now or utcnow()

    if vuln.cvss_score is not None:
        cvss_raw: float | None = vuln.cvss_score
        cvss_component = max(0.0, min(100.0, vuln.cvss_score * 10.0))
    else:
        cvss_raw = None
        cvss_component = _SEVERITY_FALLBACK.get(
            (vuln.severity or "unknown").lower(),
            30.0,
        )

    epss_component = max(0.0, min(100.0, (vuln.epss_score or 0.0) * 100.0))
    kev_component = 100.0 if vuln.in_kev else 0.0
    exploit_component = 100.0 if vuln.exploit_available else 0.0

    reference = vuln.published_at or vuln.modified_at or vuln.created_at
    if reference is None:
        age_days: float | None = None
        recency_component = 0.0
    else:
        age_days = max(0.0, (now - reference).total_seconds() / 86400.0)
        window = max(1, recency_days)
        recency_component = max(0.0, min(100.0, 100.0 * (1.0 - age_days / window)))

    components = {
        "cvss": {
            "raw": cvss_raw,
            "normalized": round(cvss_component, 2),
            "weight": round(normalized["cvss"], 4),
            "contribution": round(cvss_component * normalized["cvss"], 2),
        },
        "epss": {
            "normalized": round(epss_component, 2),
            "weight": round(normalized["epss"], 4),
            "contribution": round(epss_component * normalized["epss"], 2),
        },
        "kev": {
            "normalized": kev_component,
            "weight": round(normalized["kev"], 4),
            "contribution": round(kev_component * normalized["kev"], 2),
        },
        "exploit": {
            "normalized": exploit_component,
            "weight": round(normalized["exploit"], 4),
            "contribution": round(exploit_component * normalized["exploit"], 2),
        },
        "recency": {
            "age_days": round(age_days, 1) if age_days is not None else None,
            "normalized": round(recency_component, 2),
            "weight": round(normalized["recency"], 4),
            "contribution": round(recency_component * normalized["recency"], 2),
        },
    }
    score = round(sum(component["contribution"] for component in components.values()), 2)
    return RiskResult(score=score, level=risk_level(score), components=components)
