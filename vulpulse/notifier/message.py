"""Build notification payloads from a vulnerability row."""

from __future__ import annotations

from vulpulse.db.models import Vulnerability
from vulpulse.notifier.base import NotificationMessage


def _fmt(value: float | None, digits: int = 1) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def build_message(vuln: Vulnerability, base_url: str) -> NotificationMessage:
    identifier = vuln.cve_id or f"VULN-{vuln.id}"
    title = vuln.title or (vuln.description or "Vulnerability")[:120]
    url = f"{base_url.rstrip('/')}/vulns/{identifier}"
    severity = (vuln.severity or "unknown").upper()
    kev = "yes" if vuln.in_kev else "no"
    exploit = "yes" if vuln.exploit_available else "no"

    lines = [
        f"{identifier} — {title}",
        f"Severity: {severity} | CVSS: {_fmt(vuln.cvss_score)} | EPSS: {_fmt(vuln.epss_score, 2)}",
        f"KEV: {kev} | Public exploit: {exploit}",
    ]
    if vuln.published_at is not None:
        lines.append(f"Published: {vuln.published_at.strftime('%Y-%m-%d')}")
    if vuln.description:
        lines.extend(["", vuln.description[:800]])
    lines.extend(["", url])
    text = "\n".join(lines)

    description = ""
    if vuln.description:
        description = vuln.description[:600]
        if len(vuln.description) > 600:
            description += "…"

    markdown = "\n".join(
        [
            f"## {identifier}",
            f"**{title}**",
            f"> Severity: **{severity}** · CVSS {_fmt(vuln.cvss_score)} · "
            f"EPSS {_fmt(vuln.epss_score, 2)}",
            f"> KEV: {kev} · Public exploit: {exploit}",
            "",
            description,
            "",
            f"[Open in VulPulse]({url})",
        ]
    )

    return NotificationMessage(
        subject=f"[VulPulse] {identifier} {title}"[:200],
        text=text,
        markdown=markdown,
        url=url,
    )
