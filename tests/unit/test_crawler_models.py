from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulpulse.crawler.models import RawProduct, RawVuln


def test_dedupe_key_prefers_cve() -> None:
    vuln = RawVuln(
        source="nvd",
        source_vuln_id="CVE-2024-0001",
        cve_id="cve-2024-0001",
    )

    assert vuln.cve_id == "CVE-2024-0001"
    assert vuln.dedupe_key == "cve:CVE-2024-0001"


def test_dedupe_key_falls_back_to_source_id() -> None:
    vuln = RawVuln(source="manual", source_vuln_id="advisory-42")

    assert vuln.dedupe_key == "src:manual:advisory-42"


def test_severity_is_lowercased() -> None:
    vuln = RawVuln(source="nvd", source_vuln_id="1", severity="HIGH")

    assert vuln.severity == "high"


@pytest.mark.parametrize("score", [-0.1, 10.1])
def test_cvss_score_range_is_validated(score: float) -> None:
    with pytest.raises(ValidationError):
        RawVuln(source="nvd", source_vuln_id="1", cvss_score=score)


def test_epss_range_is_validated() -> None:
    with pytest.raises(ValidationError):
        RawVuln(source="epss", source_vuln_id="1", epss_score=1.5)


def test_products_and_references_default_to_empty_lists() -> None:
    vuln = RawVuln(source="nvd", source_vuln_id="1")

    assert vuln.products == []
    assert vuln.references == []

    assert RawProduct(vendor="apache", product="struts").vendor == "apache"
