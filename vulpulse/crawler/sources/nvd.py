"""NVD CVE API 2.0 source."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timedelta
from typing import Any

from vulpulse.config import Settings
from vulpulse.crawler.base import BaseSource, SchedulePolicy
from vulpulse.crawler.models import RawProduct, RawVuln
from vulpulse.crawler.registry import register_source
from vulpulse.timeutils import parse_datetime, to_naive_utc, utcnow

_MAX_WINDOW = timedelta(days=120)
_PAGE_SIZE = 2000
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000"


@register_source
class NvdSource(BaseSource):
    """Fetch CVEs from NVD, using incremental ``lastMod`` windows."""

    name = "nvd"
    kind = "api"
    description = "NVD CVE API 2.0 with incremental lastModified windows."

    @property
    def default_rate_limit(self) -> tuple[int, float]:
        # NVD allows 5 requests / 30s anonymously, 50 / 30s with an API key.
        return (50, 30.0) if self.settings.nvd_api_key else (5, 30.0)

    @classmethod
    def plugin_schedule(cls, settings: Settings) -> SchedulePolicy:
        return SchedulePolicy(
            interval_seconds=settings.nvd_interval_minutes * 60,
            lookback_days=settings.nvd_lookback_days,
            run_on_start=settings.scheduler_run_on_start,
        )

    async def fetch(
        self,
        *,
        since: datetime | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> AsyncIterator[RawVuln]:
        start = self._start_time(since, checkpoint)
        end = utcnow()

        for window_start, window_end in _windows(start, end):
            async for vuln in self._fetch_window(window_start, window_end):
                yield vuln

    def _start_time(
        self,
        since: datetime | None,
        checkpoint: dict[str, Any] | None,
    ) -> datetime:
        if since is not None:
            return to_naive_utc(since) or utcnow()

        if checkpoint and checkpoint.get("last_modified"):
            parsed = parse_datetime(str(checkpoint["last_modified"]))
            if parsed is not None:
                return parsed

        return utcnow() - timedelta(days=30)

    async def _fetch_window(
        self,
        start: datetime,
        end: datetime,
    ) -> AsyncIterator[RawVuln]:
        start_index = 0

        while True:
            payload = await self.client.get_json(
                self.settings.nvd_base_url,
                params={
                    "lastModStartDate": start.strftime(_TIME_FORMAT),
                    "lastModEndDate": end.strftime(_TIME_FORMAT),
                    "startIndex": start_index,
                    "resultsPerPage": _PAGE_SIZE,
                },
                headers=self._headers(),
            )

            items = payload.get("vulnerabilities") or []
            for item in items:
                cve = item.get("cve") if isinstance(item, dict) else None
                if isinstance(cve, dict):
                    parsed = parse_cve(cve)
                    if parsed is not None:
                        yield parsed

            total = int(payload.get("totalResults") or 0)
            page_size = int(payload.get("resultsPerPage") or len(items) or 0)
            if not items or page_size == 0:
                break

            start_index += page_size
            if start_index >= total:
                break

    def _headers(self) -> dict[str, str] | None:
        if not self.settings.nvd_api_key:
            return None
        return {"apiKey": self.settings.nvd_api_key}


def _windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    """Split a date range into windows NVD will accept (<= 120 days)."""
    cursor = start
    while cursor < end:
        window_end = min(cursor + _MAX_WINDOW, end)
        yield cursor, window_end
        cursor = window_end


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def parse_cve(cve: dict[str, Any]) -> RawVuln | None:
    """Map one NVD ``cve`` object to :class:`RawVuln`."""
    cve_id = _text(cve.get("id"))
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    description = next(
        (
            _text(item.get("value"))
            for item in descriptions
            if isinstance(item, dict) and item.get("lang") == "en"
        ),
        None,
    )

    metrics = cve.get("metrics")
    cvss_score, cvss_vector, cvss_version, severity = extract_cvss(
        metrics if isinstance(metrics, dict) else {}
    )

    references = extract_references(cve.get("references") or [])
    products = extract_products(cve.get("configurations") or [])
    cwes = extract_cwes(cve.get("weaknesses") or [])

    return RawVuln(
        source="nvd",
        source_vuln_id=cve_id,
        cve_id=cve_id,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cvss_version=cvss_version,
        published_at=parse_datetime(_text(cve.get("published"))),
        modified_at=parse_datetime(_text(cve.get("lastModified"))),
        vuln_status=_text(cve.get("vulnStatus")),
        references=references,
        products=products,
        cwes=cwes,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        raw=cve,
    )


def extract_cvss(
    metrics: dict[str, Any],
) -> tuple[float | None, str | None, str | None, str | None]:
    """Pick the highest-priority CVSS metric available."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue

        entry = next(
            (
                candidate
                for candidate in entries
                if isinstance(candidate, dict) and candidate.get("type") == "Primary"
            ),
            entries[0],
        )
        if not isinstance(entry, dict):
            continue

        data = entry.get("cvssData")
        if not isinstance(data, dict):
            continue

        score = data.get("baseScore")
        severity = _text(data.get("baseSeverity"))
        return (
            float(score) if isinstance(score, (int, float)) else None,
            _text(data.get("vectorString")),
            _text(data.get("version")),
            severity.lower() if severity else None,
        )

    return None, None, None, None


def extract_cwes(weaknesses: list[Any]) -> list[str]:
    found: set[str] = set()
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get("description") or []:
            if isinstance(description, dict):
                value = _text(description.get("value"))
                if value and value.upper().startswith("CWE-"):
                    found.add(value.upper())
    return sorted(found)


def extract_products(configurations: list[Any]) -> list[RawProduct]:
    found: dict[tuple[str | None, str, str | None, str], RawProduct] = {}

    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict) or not match.get("vulnerable"):
                    continue

                cpe = _text(match.get("criteria"))
                if not cpe:
                    continue

                vendor, product = parse_cpe(cpe)
                if product is None:
                    continue

                version_range = build_version_range(match)
                key = (vendor, product, version_range, cpe)
                found[key] = RawProduct(
                    vendor=vendor,
                    product=product,
                    version_range=version_range,
                    cpe=cpe,
                )

    return list(found.values())


def parse_cpe(cpe: str) -> tuple[str | None, str | None]:
    parts = cpe.split(":")
    if len(parts) < 5:
        return None, None

    vendor = _cpe_component(parts[3])
    product = _cpe_component(parts[4])
    return vendor, product


def _cpe_component(value: str) -> str | None:
    value = value.strip()
    return None if value in ("", "*", "-") else value


def build_version_range(match: dict[str, Any]) -> str | None:
    parts: list[str] = []
    for field, operator in (
        ("versionStartIncluding", ">="),
        ("versionStartExcluding", ">"),
        ("versionEndIncluding", "<="),
        ("versionEndExcluding", "<"),
    ):
        value = _text(match.get(field))
        if value:
            parts.append(f"{operator} {value}")
    return ", ".join(parts) or None


def extract_references(references: list[Any]) -> list[str]:
    urls: list[str] = []
    for reference in references:
        if isinstance(reference, dict):
            url = _text(reference.get("url"))
            if url:
                urls.append(url)
    return list(dict.fromkeys(urls))
