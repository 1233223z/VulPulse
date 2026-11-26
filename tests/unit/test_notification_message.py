from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from vulpulse.notifier.message import build_message


def test_build_message_includes_scores_and_truncates_description() -> None:
    vulnerability = SimpleNamespace(
        id=7,
        cve_id="CVE-2024-0001",
        title="Example vulnerability",
        description="d" * 1000,
        severity="critical",
        cvss_score=9.8,
        epss_score=0.9123,
        in_kev=True,
        exploit_available=True,
        published_at=datetime(2024, 1, 2),
    )

    message = build_message(vulnerability, "https://vulpulse.example/")

    assert message.subject == "[VulPulse] CVE-2024-0001 Example vulnerability"
    assert message.url == "https://vulpulse.example/vulns/CVE-2024-0001"
    assert "Severity: CRITICAL" in message.text
    assert "CVSS: 9.8" in message.text
    assert "EPSS: 0.91" in message.text
    assert "KEV: yes" in message.text
    assert "Public exploit: yes" in message.text
    assert "Published: 2024-01-02" in message.text
    assert "d" * 600 + "…" in message.markdown
    assert "d" * 1000 not in message.markdown


def test_build_message_handles_missing_fields() -> None:
    vulnerability = SimpleNamespace(
        id=42,
        cve_id=None,
        title=None,
        description=None,
        severity=None,
        cvss_score=None,
        epss_score=None,
        in_kev=False,
        exploit_available=False,
        published_at=None,
    )

    message = build_message(vulnerability, "https://vulpulse.example")

    assert message.subject.startswith("[VulPulse] VULN-42")
    assert message.url == "https://vulpulse.example/vulns/VULN-42"
    assert "CVSS: —" in message.text
    assert "EPSS: —" in message.text
    assert "KEV: no" in message.text
    assert "Published:" not in message.text
