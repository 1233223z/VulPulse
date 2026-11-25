"""HTML routes for the VulPulse dashboard."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.api.deps import get_session
from vulpulse.db.repositories import SourceRepository, VulnerabilityRepository

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def safe_url(value: str | None) -> str:
    """Only allow http(s) links in templates."""
    if not value:
        return "#"
    parsed = urlparse(value)
    return value if parsed.scheme in {"http", "https"} else "#"


templates.env.filters["safe_url"] = safe_url

router = APIRouter(tags=["web"])

_SEVERITIES = ["critical", "high", "medium", "low", "none", "unknown"]


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    repository = VulnerabilityRepository(session)
    trend = await repository.published_trend(30)
    latest_critical, _ = await repository.search(
        severity="critical",
        sort="published_at",
        limit=50,
    )
    latest_critical = [vuln for vuln in latest_critical if vuln.title or vuln.description][:5]
    latest_kev, _ = await repository.search(
        in_kev=True,
        sort="published_at",
        limit=5,
    )

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "total": await repository.count(),
            "in_kev": await repository.count_in_kev(),
            "exploit_available": await repository.count_with_exploit(),
            "epss_scored": await repository.count_with_epss(),
            "severity": await repository.severity_counts(),
            "trend": [{"date": day, "count": count} for day, count in trend],
            "latest_critical": latest_critical,
            "latest_kev": latest_kev,
            "active": "dashboard",
        },
    )


@router.get("/vulns", response_class=HTMLResponse)
async def vuln_list(
    request: Request,
    q: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    vendor: str | None = None,
    kev: str | None = None,
    exploit: str | None = None,
    page: int = Query(default=1, ge=1),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    page_size = 20
    kev_checked = kev in {"on", "true", "1"}
    exploit_checked = exploit in {"on", "true", "1"}
    filters: dict[str, object] = {
        "q": q or None,
        "severity": severity or None,
        "source": source or None,
        "vendor": vendor or None,
        "in_kev": True if kev_checked else None,
        "exploit_available": True if exploit_checked else None,
    }

    repository = VulnerabilityRepository(session)
    items, total = await repository.search(
        **filters,
        sort="published_at",
        order="desc",
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    pages = (total + page_size - 1) // page_size
    if pages and page > pages:
        page = pages
        items, total = await repository.search(
            **filters,
            sort="published_at",
            order="desc",
            limit=page_size,
            offset=(page - 1) * page_size,
        )

    sources = await SourceRepository(session).list_all()

    return templates.TemplateResponse(
        request=request,
        name="vulns.html",
        context={
            "items": items,
            "total": total,
            "page": page,
            "pages": pages,
            "page_size": page_size,
            "q": q or "",
            "severity": severity or "",
            "source": source or "",
            "vendor": vendor or "",
            "kev_checked": kev_checked,
            "exploit_checked": exploit_checked,
            "sources": sources,
            "severities": _SEVERITIES,
            "active": "vulns",
        },
    )


@router.get("/vulns/{identifier}", response_class=HTMLResponse)
async def vuln_detail(
    request: Request,
    identifier: str,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    vuln = await VulnerabilityRepository(session).get_detail(identifier)
    if vuln is None:
        return templates.TemplateResponse(
            request=request,
            name="404.html",
            context={"identifier": identifier, "active": "vulns"},
            status_code=404,
        )

    return templates.TemplateResponse(
        request=request,
        name="vuln_detail.html",
        context={"vuln": vuln, "active": "vulns"},
    )


@router.get("/sources", response_class=HTMLResponse)
async def sources_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    repository = SourceRepository(session)
    items = []
    for source in await repository.list_all():
        items.append(
            {
                "source": source,
                "records": await repository.count_records(source.id),
                "last_run": await repository.latest_run(source.id),
            }
        )

    return templates.TemplateResponse(
        request=request,
        name="sources.html",
        context={"sources": items, "active": "sources"},
    )
