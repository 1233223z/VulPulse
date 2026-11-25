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


if __name__ == "__main__":
    app()
