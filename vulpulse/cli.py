"""Command-line entry point for VulPulse."""

from __future__ import annotations

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


if __name__ == "__main__":
    app()
