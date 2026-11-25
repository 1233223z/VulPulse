"""Command-line entry point for VulPulse."""

from __future__ import annotations

import contextlib
from pathlib import Path

import typer

from vulpulse import __version__
from vulpulse.config import get_settings
from vulpulse.logging import setup_logging

app = typer.Typer(
    name="vulpulse",
    help="VulPulse — open-source vulnerability intelligence platform.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Initialize settings and logging for every command."""
    settings = get_settings()
    settings.ensure_dirs()
    setup_logging(settings.log_level, settings.log_dir)


@app.command()
def version() -> None:
    """Print the VulPulse version."""
    typer.echo(f"VulPulse {__version__}")


@app.command("init-db")
def init_db() -> None:
    """Apply all database migrations up to the latest revision."""
    from alembic import command
    from alembic.config import Config

    config = Config()
    config.set_main_option(
        "script_location",
        str(Path(__file__).resolve().parent / "db" / "migrations"),
    )
    command.upgrade(config, "head")
    typer.echo("Database is up to date.")


@app.command("sources")
def list_sources() -> None:
    """List registered crawler sources."""
    from vulpulse.crawler import available_sources

    for name in available_sources():
        typer.echo(name)


@app.command()
def crawl(
    source: str = typer.Option(
        ...,
        "--source",
        "-s",
        help="Source name, for example `nvd` or `cisa_kev`.",
    ),
    since_days: int = typer.Option(
        7,
        "--since-days",
        min=1,
        help="Incremental window in days.",
    ),
) -> None:
    """Run one crawl against a source and persist the results."""
    import asyncio
    from datetime import timedelta

    from vulpulse.crawler import create_source
    from vulpulse.ingest import IngestService
    from vulpulse.timeutils import utcnow

    settings = get_settings()

    async def _run():
        crawler = create_source(source, settings)
        try:
            return await IngestService().ingest(
                crawler,
                since=utcnow() - timedelta(days=since_days),
            )
        finally:
            await crawler.close()

    stats = asyncio.run(_run())
    typer.echo(
        f"fetched={stats.fetched} created={stats.created} updated={stats.updated} "
        f"products={stats.products} cwes={stats.cwes} references={stats.references}"
    )


@app.command()
def enrich(
    source: str = typer.Option(
        "epss",
        "--source",
        "-s",
        help="Enricher name. Supported: epss.",
    ),
) -> None:
    """Enrich existing vulnerabilities in place."""
    import asyncio

    from vulpulse.enrich.epss import EpssEnricher

    if source != "epss":
        typer.echo(f"Unsupported enricher: {source}", err=True)
        raise typer.Exit(code=2)

    async def _run():
        enricher = EpssEnricher()
        try:
            return await enricher.enrich()
        finally:
            await enricher.close()

    stats = asyncio.run(_run())
    typer.echo(f"matched={stats.matched} updated={stats.updated}")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host"),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
    reload: bool = typer.Option(
        False,
        "--reload",
        help="Enable auto-reload (development only).",
    ),
) -> None:
    """Run the FastAPI application."""
    import uvicorn

    uvicorn.run(
        "vulpulse.api.app:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def worker(
    once: bool = typer.Option(
        False,
        "--once",
        help="Run every scheduled job once and exit.",
    ),
) -> None:
    """Start the standalone scheduler worker."""
    import asyncio

    from vulpulse.scheduler.worker import SchedulerWorker

    scheduler_worker = SchedulerWorker()

    if once:
        asyncio.run(scheduler_worker.run_all_once())
        return

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(scheduler_worker.run_forever())


if __name__ == "__main__":
    app()
