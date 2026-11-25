from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from vulpulse.analyzer.scorer import RiskWeights, risk_level, score_risk
from vulpulse.config import Settings
from vulpulse.timeutils import utcnow


def make_vuln(**overrides):
    data = {
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.9,
        "in_kev": True,
        "exploit_available": True,
        "published_at": utcnow() - timedelta(days=1),
        "modified_at": None,
        "created_at": utcnow() - timedelta(days=1),
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_high_signal_vulnerability_scores_critical() -> None:
    result = score_risk(make_vuln())

    assert result.score >= 80
    assert result.level == "critical"
    assert set(result.components) == {"cvss", "epss", "kev", "exploit", "recency"}


def test_low_signal_vulnerability_scores_low() -> None:
    result = score_risk(
        make_vuln(
            severity="low",
            cvss_score=2.0,
            epss_score=0.01,
            in_kev=False,
            exploit_available=False,
            published_at=utcnow() - timedelta(days=365),
            created_at=utcnow() - timedelta(days=365),
        )
    )

    assert result.score < 20
    assert result.level == "minimal"


def test_cvss_missing_uses_severity_fallback() -> None:
    result = score_risk(make_vuln(cvss_score=None, severity="high"))

    assert result.components["cvss"]["raw"] is None
    assert result.components["cvss"]["normalized"] == 70.0


def test_epss_missing_is_zero() -> None:
    result = score_risk(make_vuln(epss_score=None))

    assert result.components["epss"]["normalized"] == 0.0


def test_recent_vulnerability_gets_more_recency_weight() -> None:
    recent = score_risk(make_vuln(published_at=utcnow() - timedelta(days=1)))
    old = score_risk(make_vuln(published_at=utcnow() - timedelta(days=200)))

    assert recent.components["recency"]["normalized"] > old.components["recency"]["normalized"]


def test_weights_are_normalized() -> None:
    weights = RiskWeights(cvss=2.0, epss=0.0, kev=0.0, exploit=0.0, recency=0.0)
    result = score_risk(make_vuln(epss_score=None, in_kev=False, exploit_available=False), weights)

    assert result.components["cvss"]["weight"] == 1.0
    assert result.score == result.components["cvss"]["normalized"] == 98.0


def test_components_sum_to_score() -> None:
    result = score_risk(make_vuln())

    total = sum(component["contribution"] for component in result.components.values())
    assert abs(total - result.score) < 0.05


def test_risk_level_thresholds() -> None:
    assert risk_level(80) == "critical"
    assert risk_level(60) == "high"
    assert risk_level(40) == "medium"
    assert risk_level(20) == "low"
    assert risk_level(0) == "minimal"


def test_weights_from_settings() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        risk_weight_cvss=0.5,
        risk_weight_epss=0.2,
        risk_weight_kev=0.15,
        risk_weight_exploit=0.1,
        risk_weight_recency=0.05,
    )
    weights = RiskWeights.from_settings(settings)

    assert weights.cvss == 0.5
    assert weights.epss == 0.2
