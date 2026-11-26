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

channel_app = typer.Typer(help="Manage notification channels.", no_args_is_help=True)
subscription_app = typer.Typer(help="Manage alert subscriptions.", no_args_is_help=True)
app.add_typer(channel_app, name="channel")
app.add_typer(subscription_app, name="subscription")


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
    """List registered crawler source names."""
    from vulpulse.plugins import plugin_infos

    for plugin in plugin_infos(get_settings()):
        typer.echo(plugin.name)


@app.command("plugins")
def list_plugins(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """List source plugins, schedules and load failures."""
    import json

    from vulpulse.plugins import plugin_failures, plugin_infos

    infos = plugin_infos(get_settings())
    failures = plugin_failures()

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "plugins": [
                        {
                            "name": info.name,
                            "description": info.description,
                            "kind": info.kind,
                            "interval_seconds": info.interval_seconds,
                            "lookback_days": info.lookback_days,
                            "run_on_start": info.run_on_start,
                            "api_version": info.api_version,
                            "module": info.module,
                            "entry_point": info.entry_point,
                            "builtin": info.builtin,
                        }
                        for info in infos
                    ],
                    "failures": [
                        {"entry_point": failure.entry_point, "error": failure.error}
                        for failure in failures
                    ],
                },
                indent=2,
            )
        )
        return

    typer.echo("NAME\tKIND\tINTERVAL\tBUILTIN\tDESCRIPTION")
    for info in infos:
        typer.echo(
            f"{info.name}\t{info.kind}\t{info.interval_seconds}s\t"
            f"{info.builtin}\t{info.description}"
        )
    for failure in failures:
        typer.echo(
            f"FAILED\t{failure.entry_point}\t{failure.error}",
            err=True,
        )


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
    from vulpulse.plugins import load_plugins
    from vulpulse.timeutils import utcnow

    settings = get_settings()
    load_plugins(settings)

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
def summarize(
    cve: str = typer.Option(..., "--cve", "-c", help="CVE or vulnerability ID."),
    refresh: bool = typer.Option(False, "--refresh", help="Regenerate an existing summary."),
) -> None:
    """Generate and cache an optional AI summary for one vulnerability."""
    import asyncio

    from vulpulse.ai.service import SummaryService
    from vulpulse.ai.summarizer import SummaryError
    from vulpulse.db.session import get_database

    settings = get_settings()
    if not settings.llm_enabled:
        typer.echo("AI summaries are disabled. Set VULPULSE_LLM_ENABLED=true.", err=True)
        raise typer.Exit(code=2)
    if not settings.llm_api_key:
        typer.echo("VULPULSE_LLM_API_KEY is not configured.", err=True)
        raise typer.Exit(code=2)

    async def _run():
        async with get_database().session() as session:
            return await SummaryService(session, settings=settings).generate(
                cve,
                refresh=refresh,
            )

    try:
        outcome = asyncio.run(_run())
    except SummaryError as exc:
        typer.echo(f"Summary generation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if outcome is None:
        typer.echo(f"Vulnerability not found: {cve}", err=True)
        raise typer.Exit(code=1)
    if outcome.cached:
        typer.echo(f"Using cached summary from {outcome.generated_at}.")
    typer.echo(outcome.text)


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
    host: str = typer.Option("127.0.0.1", "--host"),
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


@channel_app.command("add")
def channel_add(
    name: str = typer.Option(..., "--name"),
    channel_type: str = typer.Option(..., "--type", help="wecom or email"),
    config: str = typer.Option("{}", "--config", help="Advanced config as JSON"),
    webhook_url: str | None = typer.Option(
        None,
        "--webhook-url",
        help="WeCom robot webhook URL.",
    ),
    email_to: str | None = typer.Option(
        None,
        "--email-to",
        help="Email recipient address.",
    ),
) -> None:
    """Create a notification channel."""
    import asyncio
    import json

    from vulpulse.db.repositories import ChannelRepository
    from vulpulse.db.session import get_database

    if channel_type not in {"wecom", "email"}:
        typer.echo("Unsupported channel type. Use wecom or email.", err=True)
        raise typer.Exit(code=2)

    try:
        parsed = json.loads(config or "{}")
    except json.JSONDecodeError as exc:
        typer.echo(f"Invalid JSON config: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if not isinstance(parsed, dict):
        typer.echo("Channel config must be a JSON object.", err=True)
        raise typer.Exit(code=2)

    if webhook_url:
        parsed["webhook_url"] = webhook_url
    if email_to:
        parsed["to"] = [email_to]

    if channel_type == "wecom" and not (
        parsed.get("webhook_url") or get_settings().wecom_webhook_url
    ):
        typer.echo("WeCom requires --webhook-url or VULPULSE_WECOM_WEBHOOK_URL.", err=True)
        raise typer.Exit(code=2)
    if channel_type == "email" and not parsed.get("to"):
        typer.echo("Email requires --email-to or config.to.", err=True)
        raise typer.Exit(code=2)

    async def _run():
        async with get_database().session() as session:
            repository = ChannelRepository(session)
            if await repository.get_by_name(name) is not None:
                return False
            await repository.create(name, channel_type, parsed)
            await session.commit()
            return True

    if not asyncio.run(_run()):
        typer.echo(f"Channel already exists: {name}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Created channel {name} ({channel_type})")


@channel_app.command("list")
def channel_list() -> None:
    """List notification channels."""
    import asyncio

    from vulpulse.db.repositories import ChannelRepository
    from vulpulse.db.session import get_database

    async def _run():
        async with get_database().session() as session:
            return await ChannelRepository(session).list_all()

    channels = asyncio.run(_run())
    if not channels:
        typer.echo("No channels configured.")
        return
    for channel in channels:
        typer.echo(f"{channel.name}\t{channel.type}\tenabled={channel.enabled}")


@subscription_app.command("add")
def subscription_add(
    name: str = typer.Option(..., "--name"),
    channel: str = typer.Option(..., "--channel"),
    rule: str = typer.Option("{}", "--rule", help="Advanced rule as JSON"),
    severity: list[str] | None = typer.Option(None, "--severity"),
    keyword: list[str] | None = typer.Option(None, "--keyword"),
    vendor: list[str] | None = typer.Option(None, "--vendor"),
    product: list[str] | None = typer.Option(None, "--product"),
    source: list[str] | None = typer.Option(None, "--source"),
    kev: bool | None = typer.Option(None, "--kev/--no-kev"),
    exploit: bool | None = typer.Option(None, "--exploit/--no-exploit"),
    cvss_min: float | None = typer.Option(None, "--cvss-min"),
    epss_min: float | None = typer.Option(None, "--epss-min"),
    within_days: int | None = typer.Option(None, "--within-days"),
) -> None:
    """Create an alert subscription."""
    import asyncio
    import json

    from pydantic import ValidationError

    from vulpulse.db.repositories import ChannelRepository, SubscriptionRepository
    from vulpulse.db.session import get_database
    from vulpulse.notifier.rules import SubscriptionRule

    try:
        rule_data = json.loads(rule or "{}")
    except json.JSONDecodeError as exc:
        typer.echo(f"Invalid rule JSON: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if not isinstance(rule_data, dict):
        typer.echo("Rule must be a JSON object.", err=True)
        raise typer.Exit(code=2)

    if severity:
        rule_data["severities"] = severity
    if keyword:
        rule_data["keywords"] = keyword
    if vendor:
        rule_data["vendors"] = vendor
    if product:
        rule_data["products"] = product
    if source:
        rule_data["sources"] = source
    if kev is not None:
        rule_data["in_kev"] = kev
    if exploit is not None:
        rule_data["exploit_available"] = exploit
    if cvss_min is not None:
        rule_data["cvss_min"] = cvss_min
    if epss_min is not None:
        rule_data["epss_min"] = epss_min
    if within_days is not None:
        rule_data["published_within_days"] = within_days

    try:
        parsed = SubscriptionRule.model_validate(rule_data).model_dump()
    except ValidationError as exc:
        typer.echo(f"Invalid rule: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    async def _run():
        async with get_database().session() as session:
            channel_model = await ChannelRepository(session).get_by_name(channel)
            if channel_model is None:
                return "channel_missing"
            repository = SubscriptionRepository(session)
            if await repository.get_by_name(name) is not None:
                return "exists"
            await repository.create(name, channel_model.id, parsed)
            await session.commit()
            return "ok"

    result = asyncio.run(_run())
    if result == "channel_missing":
        typer.echo(f"Channel not found: {channel}", err=True)
        raise typer.Exit(code=1)
    if result == "exists":
        typer.echo(f"Subscription already exists: {name}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Created subscription {name} on channel {channel}")


@subscription_app.command("list")
def subscription_list() -> None:
    """List alert subscriptions."""
    import asyncio

    from vulpulse.db.repositories import SubscriptionRepository
    from vulpulse.db.session import get_database

    async def _run():
        async with get_database().session() as session:
            return await SubscriptionRepository(session).list_all()

    subscriptions = asyncio.run(_run())
    if not subscriptions:
        typer.echo("No subscriptions configured.")
        return
    for subscription in subscriptions:
        channel_name = subscription.channel.name if subscription.channel else "?"
        typer.echo(
            f"{subscription.name}\tchannel={channel_name}\t"
            f"enabled={subscription.enabled}\trule={subscription.rule_json}"
        )


@app.command()
def export(
    report_format: str = typer.Option("md", "--format", "-f", help="md, html or csv"),
    output: str = typer.Option("-", "--output", "-o", help="File path, or - for stdout"),
    q: str | None = typer.Option(None, "--q"),
    severity: str | None = typer.Option(None, "--severity"),
    source: str | None = typer.Option(None, "--source"),
    vendor: str | None = typer.Option(None, "--vendor"),
    product: str | None = typer.Option(None, "--product"),
    kev: bool = typer.Option(False, "--kev", help="Only CISA KEV entries"),
    exploit: bool = typer.Option(False, "--exploit", help="Only entries with public exploits"),
    cvss_min: float | None = typer.Option(None, "--cvss-min"),
    epss_min: float | None = typer.Option(None, "--epss-min"),
    risk_min: float | None = typer.Option(None, "--risk-min"),
    since_days: int | None = typer.Option(None, "--since-days", min=1),
    sort: str = typer.Option("risk_score", "--sort"),
    order: str = typer.Option("desc", "--order"),
    limit: int = typer.Option(500, "--limit", min=1, max=2000),
) -> None:
    """Export a filtered vulnerability report as Markdown or HTML."""
    import asyncio
    from datetime import timedelta
    from pathlib import Path

    from vulpulse.db.session import get_database
    from vulpulse.report.service import ReportFilters, generate_report
    from vulpulse.timeutils import utcnow

    if report_format not in {"md", "html", "csv"}:
        typer.echo("Format must be md or html.", err=True)
        raise typer.Exit(code=2)

    filters = ReportFilters(
        q=q,
        severity=severity,
        source=source,
        vendor=vendor,
        product=product,
        kev=True if kev else None,
        exploit=True if exploit else None,
        cvss_min=cvss_min,
        epss_min=epss_min,
        risk_min=risk_min,
        published_from=(utcnow() - timedelta(days=since_days) if since_days is not None else None),
        sort=sort,
        order=order,
        limit=limit,
    )

    async def _run():
        async with get_database().session() as session:
            return await generate_report(session, filters, report_format)

    result = asyncio.run(_run())

    if output == "-":
        typer.echo(result.content)
        return

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(result.content, encoding="utf-8")
    typer.echo(f"Wrote {result.included}/{result.total} vulnerabilities to {destination}")


@app.command()
def score() -> None:
    """Recompute risk scores for every vulnerability."""
    import asyncio

    from vulpulse.analyzer.scoring_service import RiskService

    stats = asyncio.run(RiskService().score_all())
    typer.echo(f"scored={stats.total} average={stats.average:.2f}")


@app.command()
def notify(
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Match subscriptions without creating deliveries or sending.",
    ),
) -> None:
    """Run one notification cycle."""
    import asyncio

    from vulpulse.notifier.service import NotificationService

    async def _run():
        return await NotificationService().run_cycle(dry_run=dry_run)

    stats = asyncio.run(_run())
    typer.echo(
        f"subscriptions={stats.subscriptions} matched={stats.matched} "
        f"created={stats.created} sent={stats.sent} failed={stats.failed} "
        f"dry_run={stats.dry_run}"
    )


@app.command("notify-test")
def notify_test(
    channel: str = typer.Option(..., "--channel", "-c"),
) -> None:
    """Send a test message through a configured channel."""
    import asyncio

    from vulpulse.db.repositories import ChannelRepository
    from vulpulse.db.session import get_database
    from vulpulse.notifier.base import NotificationMessage
    from vulpulse.notifier.factory import build_channel

    settings = get_settings()

    async def _run():
        async with get_database().session() as session:
            model = await ChannelRepository(session).get_by_name(channel)
            if model is None:
                return "missing"
            sender = build_channel(model, settings)
            try:
                await sender.send(
                    NotificationMessage(
                        subject="[VulPulse] test notification",
                        text="VulPulse test notification. If you see this, the channel works.",
                        markdown=(
                            "## VulPulse test\n"
                            "If you see this, the channel works.\n\n"
                            f"[Open VulPulse]({settings.public_base_url})"
                        ),
                        url=settings.public_base_url,
                    )
                )
            finally:
                await sender.close()
            return "ok"

    try:
        result = asyncio.run(_run())
    except Exception as exc:
        typer.echo(f"Failed to send test notification: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if result == "missing":
        typer.echo(f"Channel not found: {channel}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Test notification sent through {channel}")


if __name__ == "__main__":
    app()
