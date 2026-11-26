from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from vulpulse.report.builder import ReportSummary, build_html, build_markdown
from vulpulse.report.csv import build_csv
from vulpulse.report.service import ReportFilters


def make_vuln(**overrides):
    data = {
        "id": 1,
        "cve_id": "CVE-2024-0001",
        "title": "Example | vulnerability",
        "severity": "critical",
        "risk_score": 91.5,
        "risk_level": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.9,
        "in_kev": True,
        "exploit_available": True,
        "published_at": datetime(2024, 1, 1),
        "modified_at": None,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_summary_counts() -> None:
    items = [
        make_vuln(),
        make_vuln(
            id=2,
            cve_id="CVE-2024-0002",
            severity="medium",
            risk_score=45.0,
            risk_level="medium",
            in_kev=False,
            exploit_available=False,
        ),
    ]

    summary = ReportSummary.from_items(items, total=2)

    assert summary.included == 2
    assert summary.total == 2
    assert summary.severity == {"critical": 1, "medium": 1}
    assert summary.risk == {"critical": 1, "medium": 1}
    assert summary.in_kev == 1
    assert summary.exploit == 1


def test_markdown_escapes_pipes_and_contains_links() -> None:
    item = make_vuln(title="Example | [click](https://evil.test) <b>bold</b>")

    markdown = build_markdown(
        [item],
        ReportSummary.from_items([item], total=1),
        'search "[x](https://evil.test)"',
        datetime(2026, 11, 25, 14, 0),
        "https://vulpulse.example",
    )

    assert "# VulPulse Vulnerability Report" in markdown
    assert "Example \\| \\[click\\](https://evil.test)" in markdown
    assert "&lt;b&gt;bold&lt;/b&gt;" in markdown
    assert "[click](https://evil.test)" not in markdown
    assert "\\[x\\](https://evil.test)" in markdown
    assert "https://vulpulse.example/vulns/CVE-2024-0001" in markdown
    assert "| CVE-2024-0001 |" not in markdown


def test_markdown_escapes_identifier_and_quotes_url() -> None:
    item = make_vuln(cve_id="CVE-2024-1) [x](https://evil.test)")

    markdown = build_markdown(
        [item],
        ReportSummary.from_items([item], total=1),
        "no filters",
        datetime(2026, 11, 25, 14, 0),
        "https://vulpulse.example",
    )

    assert "[x](https://evil.test)" not in markdown
    assert "\\[x\\](https://evil.test)" in markdown
    assert "CVE-2024-1%29" in markdown


def test_html_escapes_untrusted_text() -> None:
    item = make_vuln(title="<script>alert(1)</script>")

    html = build_html(
        [item],
        ReportSummary.from_items([item], total=1),
        "no filters",
        datetime(2026, 11, 25, 14, 0),
        "https://vulpulse.example",
    )

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<table>" in html
    assert "https://vulpulse.example/vulns/CVE-2024-0001" in html


def test_filter_description() -> None:
    filters = ReportFilters(
        severity="critical",
        vendor="apache",
        kev=True,
        risk_min=60,
    )

    text = filters.describe()

    assert "severity critical" in text
    assert "vendor apache" in text
    assert "KEV only" in text
    assert "risk >= 60" in text


def test_csv_escapes_spreadsheet_formulas() -> None:
    product = SimpleNamespace(vendor="apache", product="struts")
    cwe = SimpleNamespace(id="CWE-79", name="XSS")
    item = make_vuln(
        title="=SUM(1,1)",
        description="ignored",
        product_links=[SimpleNamespace(product=product)],
        cwe_links=[SimpleNamespace(cwe=cwe)],
        source_records=[SimpleNamespace()],
    )

    content = build_csv([item], "https://vulpulse.example")

    assert "'=SUM" in content
    assert "apache" in content
    assert "struts" in content
    assert "CWE-79" in content
    assert "https://vulpulse.example/vulns/CVE-2024-0001" in content
