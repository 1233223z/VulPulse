from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from vulpulse.db.models import Product, Source, SourceRecord, Vulnerability, VulnProduct
from vulpulse.notifier.rules import SubscriptionRule
from vulpulse.timeutils import utcnow


def make_vuln(**overrides) -> Vulnerability:
    data = {
        "id": 1,
        "dedupe_key": "cve:CVE-2024-0001",
        "cve_id": "CVE-2024-0001",
        "title": "Apache Struts RCE",
        "description": "Remote code execution in Struts.",
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.9,
        "in_kev": True,
        "exploit_available": True,
        "published_at": utcnow() - timedelta(days=1),
    }
    data.update(overrides)
    vuln = Vulnerability(**data)

    source = Source(id=1, name="nvd", kind="api")
    record = SourceRecord(
        id=1,
        vuln_id=1,
        source_id=1,
        source_vuln_id="CVE-2024-0001",
        fetched_at=utcnow(),
    )
    record.source = source
    vuln.source_records = [record]

    product = Product(id=1, vendor="apache", product="struts")
    link = VulnProduct(id=1, vuln_id=1, product_id=1)
    link.product = product
    vuln.product_links = [link]
    return vuln


def test_default_rule_matches_critical_and_high() -> None:
    rule = SubscriptionRule()

    assert rule.matches(make_vuln())
    assert rule.matches(make_vuln(severity="high"))
    assert not rule.matches(make_vuln(severity="medium"))


def test_explicit_severities() -> None:
    rule = SubscriptionRule(severities=["medium"])

    assert rule.matches(make_vuln(severity="medium"))
    assert not rule.matches(make_vuln(severity="critical"))


def test_keyword_matching_is_case_insensitive() -> None:
    assert SubscriptionRule(keywords=["STRUTS"]).matches(make_vuln())
    assert not SubscriptionRule(keywords=["jenkins"]).matches(make_vuln())


def test_vendor_and_product_matching() -> None:
    assert SubscriptionRule(vendors=["apache"]).matches(make_vuln())
    assert not SubscriptionRule(vendors=["oracle"]).matches(make_vuln())
    assert SubscriptionRule(products=["struts"]).matches(make_vuln())
    assert not SubscriptionRule(products=["tomcat"]).matches(make_vuln())


def test_source_matching() -> None:
    assert SubscriptionRule(sources=["nvd"]).matches(make_vuln())
    assert not SubscriptionRule(sources=["cisa_kev"]).matches(make_vuln())


def test_flag_matching() -> None:
    assert SubscriptionRule(in_kev=True).matches(make_vuln())
    assert not SubscriptionRule(in_kev=False).matches(make_vuln())
    assert SubscriptionRule(exploit_available=True).matches(make_vuln())
    assert not SubscriptionRule(exploit_available=False).matches(make_vuln())


def test_score_thresholds() -> None:
    assert SubscriptionRule(cvss_min=9.0).matches(make_vuln())
    assert not SubscriptionRule(cvss_min=9.9).matches(make_vuln())
    assert SubscriptionRule(epss_min=0.8).matches(make_vuln())
    assert not SubscriptionRule(epss_min=0.95).matches(make_vuln())


def test_published_within_days() -> None:
    recent = make_vuln(published_at=utcnow() - timedelta(days=2))
    old = make_vuln(published_at=utcnow() - timedelta(days=30))

    assert SubscriptionRule(published_within_days=5).matches(recent)
    assert not SubscriptionRule(published_within_days=5).matches(old)


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        SubscriptionRule.model_validate({"severities": ["critical"], "typo": True})
