"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from vulpulse import __version__
from vulpulse.api.routers import admin, health, sources, stats, vulns
from vulpulse.config import get_settings
from vulpulse.logging import setup_logging


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    settings.ensure_dirs()
    setup_logging(settings.log_level, settings.log_dir)
    yield


def create_app() -> FastAPI:
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

    application.include_router(health.router)
    application.include_router(vulns.router, prefix="/api/v1")
    application.include_router(stats.router, prefix="/api/v1")
    application.include_router(sources.router, prefix="/api/v1")
    application.include_router(admin.router, prefix="/api/v1")

    @application.get("/", include_in_schema=False)
    async def index() -> dict[str, str]:
        return {
            "name": "VulPulse",
            "version": __version__,
            "docs": "/docs",
        }

    return application


app = create_app()
