"""FastAPI application factory."""

from __future__ import annotations

import mimetypes
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger
from starlette.middleware.sessions import SessionMiddleware

from vulpulse import __version__
from vulpulse.api.rate_limit import (
    SlidingWindowRateLimiter,
    client_ip,
    parse_trusted_proxies,
)
from vulpulse.api.routers import (
    admin,
    export,
    health,
    sources,
    stats,
    vendors,
    vulns,
)
from vulpulse.config import get_settings
from vulpulse.logging import setup_logging
from vulpulse.web.admin import router as admin_web_router
from vulpulse.web.routes import STATIC_DIR
from vulpulse.web.routes import router as web_router

# Windows can map .js to text/plain in the registry; with nosniff the browser
# then refuses to execute it. Register the correct types for every platform.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    settings.ensure_dirs()
    setup_logging(settings.log_level, settings.log_dir)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    docs_enabled = settings.docs_enabled
    if docs_enabled is None:
        docs_enabled = settings.env != "prod"

    application = FastAPI(
        title="VulPulse API",
        version=__version__,
        description=(
            "Query normalized, deduplicated vulnerability intelligence "
            "collected from public sources."
        ),
        license_info={"name": "MIT"},
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    if settings.env == "prod":
        if not settings.session_secret:
            logger.warning("VULPULSE_SESSION_SECRET is not set; admin sessions reset on restart")
        if not settings.session_https_only:
            logger.warning("VULPULSE_SESSION_HTTPS_ONLY is false; set it when serving over HTTPS")
        if settings.api_rate_limit_per_minute == 0:
            logger.warning("VULPULSE_API_RATE_LIMIT_PER_MINUTE is 0; API rate limiting is disabled")
    application.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret or secrets.token_urlsafe(32),
        same_site="lax",
        https_only=settings.session_https_only,
        max_age=settings.session_max_age_hours * 3600,
    )

    rate_limiter = SlidingWindowRateLimiter(settings.api_rate_limit_per_minute)
    trusted_proxies = parse_trusted_proxies(settings.trusted_proxies)
    application.state.api_rate_limiter = rate_limiter
    application.state.docs_enabled = docs_enabled

    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    application.include_router(health.router)
    application.include_router(vulns.router, prefix="/api/v1")
    application.include_router(stats.router, prefix="/api/v1")
    application.include_router(sources.router, prefix="/api/v1")
    application.include_router(vendors.router, prefix="/api/v1")
    application.include_router(export.router, prefix="/api/v1")
    application.include_router(admin.router, prefix="/api/v1")
    application.include_router(web_router)
    application.include_router(admin_web_router)

    def apply_security_headers(request: Request, response: Response) -> None:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        if request.url.path.startswith(("/admin", "/api/v1/admin")):
            response.headers.setdefault("Cache-Control", "no-store")

    @application.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        is_api = request.url.path == "/api" or request.url.path.startswith("/api/")
        rate_headers: dict[str, str] = {}

        if is_api and rate_limiter.enabled:
            result = rate_limiter.check(client_ip(request, trusted_proxies))
            rate_headers = {
                "X-RateLimit-Limit": str(rate_limiter.limit),
                "X-RateLimit-Remaining": str(result.remaining),
            }
            if not result.allowed:
                response = JSONResponse(
                    {"detail": "Rate limit exceeded"},
                    status_code=429,
                    headers={
                        **rate_headers,
                        "Retry-After": str(result.retry_after),
                    },
                )
                apply_security_headers(request, response)
                return response

        response = await call_next(request)
        for name, value in rate_headers.items():
            response.headers.setdefault(name, value)
        apply_security_headers(request, response)
        return response

    @application.get("/api", include_in_schema=False)
    async def api_index() -> dict[str, str | None]:
        return {
            "name": "VulPulse",
            "version": __version__,
            "docs": "/docs" if docs_enabled else None,
            "v1": "/api/v1",
        }

    return application


app = create_app()
