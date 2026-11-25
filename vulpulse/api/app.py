"""FastAPI application factory."""

from __future__ import annotations

import mimetypes
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from loguru import logger
from starlette.middleware.sessions import SessionMiddleware

from vulpulse import __version__
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
    application = FastAPI(
        title="VulPulse API",
        version=__version__,
        description=(
            "Query normalized, deduplicated vulnerability intelligence "
            "collected from public sources."
        ),
        license_info={"name": "MIT"},
        lifespan=lifespan,
    )

    if not settings.session_secret:
        logger.warning("VULPULSE_SESSION_SECRET is not set; admin sessions reset on restart")
    application.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret or secrets.token_urlsafe(32),
        same_site="lax",
        https_only=settings.session_https_only,
    )

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

    @application.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        if request.url.path.startswith("/admin"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @application.get("/api", include_in_schema=False)
    async def api_index() -> dict[str, str]:
        return {
            "name": "VulPulse",
            "version": __version__,
            "docs": "/docs",
            "v1": "/api/v1",
        }

    return application


app = create_app()
