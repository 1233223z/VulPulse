from __future__ import annotations

import asyncio
import contextlib
import json
import sqlite3
from types import SimpleNamespace

from typer.testing import CliRunner

from vulpulse import __version__
from vulpulse.ai.summarizer import SummaryError
from vulpulse.cli import app
from vulpulse.db.repositories import VulnerabilityRepository
from vulpulse.db.session import Database


def test_version_command(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))

    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert f"VulPulse {__version__}" in result.output


def test_plugins_command_lists_builtins(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))

    result = CliRunner().invoke(app, ["plugins"])

    assert result.exit_code == 0
    assert "nvd" in result.output
    assert "cisa_kev" in result.output
    assert "exploitdb" in result.output
    assert "NAME" in result.output


def test_sources_command(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))

    result = CliRunner().invoke(app, ["sources"])

    assert result.exit_code == 0
    assert "nvd" in result.output


def test_plugins_json_output(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))

    result = CliRunner().invoke(app, ["plugins", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert {"nvd", "cisa_kev", "exploitdb"} <= {plugin["name"] for plugin in data["plugins"]}
    assert data["failures"] == []


def test_summarize_disabled(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("VULPULSE_LLM_ENABLED", "false")

    result = CliRunner().invoke(app, ["summarize", "--cve", "CVE-2024-0001"])

    assert result.exit_code == 2
    assert "disabled" in result.output


def test_export_rejects_unknown_format(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))

    result = CliRunner().invoke(app, ["export", "--format", "pdf"])

    assert result.exit_code == 2
    assert "format" in result.output.lower()


def test_backup_and_restore_commands(monkeypatch, tmp_path) -> None:
    database = tmp_path / "cli.db"
    with contextlib.closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE sample (value TEXT NOT NULL)")
        connection.execute("INSERT INTO sample (value) VALUES ('original')")
        connection.commit()

    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv(
        "VULPULSE_DATABASE_URL",
        f"sqlite+aiosqlite:///{database.as_posix()}",
    )
    backup = tmp_path / "backup.db"

    result = CliRunner().invoke(app, ["backup", "--output", str(backup)])

    assert result.exit_code == 0
    assert backup.is_file()

    result = CliRunner().invoke(
        app,
        ["restore", "--input", str(backup), "--force"],
    )

    assert result.exit_code == 0
    with contextlib.closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT value FROM sample").fetchone() == ("original",)


def cli_env(monkeypatch, tmp_path) -> tuple[str, str]:
    database = tmp_path / "cli-commands.db"
    database_url = f"sqlite+aiosqlite:///{database.as_posix()}"
    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("VULPULSE_DATABASE_URL", database_url)
    return str(database), database_url


def test_init_db_and_channel_subscription_commands(monkeypatch, tmp_path) -> None:
    database, _ = cli_env(monkeypatch, tmp_path)
    runner = CliRunner()

    assert runner.invoke(app, ["init-db"]).exit_code == 0

    added = runner.invoke(
        app,
        [
            "channel",
            "add",
            "--name",
            "wecom-cli",
            "--type",
            "wecom",
            "--webhook-url",
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        ],
    )
    assert added.exit_code == 0
    assert "wecom-cli" in runner.invoke(app, ["channel", "list"]).output

    invalid_type = runner.invoke(
        app,
        ["channel", "add", "--name", "bad", "--type", "slack"],
    )
    assert invalid_type.exit_code == 2

    duplicate = runner.invoke(
        app,
        [
            "channel",
            "add",
            "--name",
            "wecom-cli",
            "--type",
            "wecom",
            "--webhook-url",
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        ],
    )
    assert duplicate.exit_code == 1

    missing_email = runner.invoke(
        app,
        ["channel", "add", "--name", "mail", "--type", "email"],
    )
    assert missing_email.exit_code == 2

    subscription = runner.invoke(
        app,
        [
            "subscription",
            "add",
            "--name",
            "critical-cli",
            "--channel",
            "wecom-cli",
            "--severity",
            "critical",
        ],
    )
    assert subscription.exit_code == 0
    assert "critical-cli" in runner.invoke(app, ["subscription", "list"]).output

    missing_channel = runner.invoke(
        app,
        [
            "subscription",
            "add",
            "--name",
            "missing",
            "--channel",
            "does-not-exist",
        ],
    )
    assert missing_channel.exit_code == 1

    duplicate_subscription = runner.invoke(
        app,
        [
            "subscription",
            "add",
            "--name",
            "critical-cli",
            "--channel",
            "wecom-cli",
        ],
    )
    assert duplicate_subscription.exit_code == 1

    with contextlib.closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT count(*) FROM channels").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM subscriptions").fetchone() == (1,)


def test_export_command_writes_report(monkeypatch, tmp_path) -> None:
    _, database_url = cli_env(monkeypatch, tmp_path)
    output = tmp_path / "report.csv"

    async def seed() -> None:
        database = Database(database_url)
        await database.create_schema()
        async with database.session() as session:
            repository = VulnerabilityRepository(session)
            await repository.upsert(
                "cve:CVE-2024-CLI",
                cve_id="CVE-2024-CLI",
                title="CLI export",
                severity="high",
                risk_score=70.0,
                risk_level="high",
            )
            await session.commit()
        await database.dispose()

    asyncio.run(seed())

    result = CliRunner().invoke(
        app,
        ["export", "--format", "csv", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert output.is_file()
    assert "cve_id,title,severity" in output.read_text(encoding="utf-8")
    assert "CVE-2024-CLI" in output.read_text(encoding="utf-8")


def _create_schema(database_url: str) -> None:
    async def run() -> None:
        database = Database(database_url)
        await database.create_schema()
        await database.dispose()

    asyncio.run(run())


def _seed_vuln(database_url: str) -> None:
    async def seed() -> None:
        database = Database(database_url)
        async with database.session() as session:
            await VulnerabilityRepository(session).upsert(
                "cve:CVE-2024-CLI",
                cve_id="CVE-2024-CLI",
                title="CLI export",
                severity="high",
                risk_score=70.0,
                risk_level="high",
            )
            await session.commit()
        await database.dispose()

    asyncio.run(seed())


def test_backup_and_restore_report_non_sqlite_urls(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv(
        "VULPULSE_DATABASE_URL",
        "postgresql+asyncpg://vulpulse:secret@localhost/vulpulse",
    )
    runner = CliRunner()

    backed_up = runner.invoke(app, ["backup", "--output", str(tmp_path / "backup.db")])
    assert backed_up.exit_code == 1
    assert "SQLite" in backed_up.output

    restored = runner.invoke(app, ["restore", "--input", str(tmp_path / "backup.db")])
    assert restored.exit_code == 1
    assert "SQLite" in restored.output


def test_plugins_reports_load_failures(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VULPULSE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VULPULSE_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setattr(
        "vulpulse.plugins.plugin_failures",
        lambda: [SimpleNamespace(entry_point="bad-plugin", error="import boom")],
    )

    result = CliRunner().invoke(app, ["plugins"])

    assert result.exit_code == 0
    assert "FAILED" in result.output
    assert "bad-plugin" in result.output
    assert "import boom" in result.output


def test_crawl_command_ingests_one_source(monkeypatch, tmp_path) -> None:
    cli_env(monkeypatch, tmp_path)
    state = {"closed": False, "since": None}

    class FakeSource:
        async def close(self) -> None:
            state["closed"] = True

    class FakeIngest:
        async def ingest(self, source, *, since):
            state["since"] = since
            return SimpleNamespace(
                fetched=3,
                created=2,
                updated=1,
                products=1,
                cwes=1,
                references=1,
            )

    monkeypatch.setattr(
        "vulpulse.crawler.create_source",
        lambda name, settings: FakeSource(),
    )
    monkeypatch.setattr("vulpulse.ingest.IngestService", FakeIngest)

    result = CliRunner().invoke(app, ["crawl", "--source", "nvd", "--since-days", "2"])

    assert result.exit_code == 0
    assert state["closed"] is True
    assert state["since"] is not None
    assert "fetched=3 created=2 updated=1" in result.output


def _summarize_env(monkeypatch, tmp_path) -> None:
    cli_env(monkeypatch, tmp_path)
    monkeypatch.setenv("VULPULSE_LLM_ENABLED", "true")
    monkeypatch.setenv("VULPULSE_LLM_API_KEY", "test-key")


def test_summarize_requires_api_key(monkeypatch, tmp_path) -> None:
    cli_env(monkeypatch, tmp_path)
    monkeypatch.setenv("VULPULSE_LLM_ENABLED", "true")

    result = CliRunner().invoke(app, ["summarize", "--cve", "CVE-2024-0001"])

    assert result.exit_code == 2
    assert "VULPULSE_LLM_API_KEY" in result.output


def test_summarize_prints_cached_summary(monkeypatch, tmp_path) -> None:
    _summarize_env(monkeypatch, tmp_path)

    class FakeSummaryService:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def generate(self, cve, *, refresh=False):
            assert cve == "CVE-2024-0001"
            return SimpleNamespace(
                cached=True,
                generated_at="2026-01-01T00:00:00",
                text="Summary text.",
            )

    monkeypatch.setattr("vulpulse.ai.service.SummaryService", FakeSummaryService)

    result = CliRunner().invoke(app, ["summarize", "--cve", "CVE-2024-0001"])

    assert result.exit_code == 0
    assert "Using cached summary" in result.output
    assert "Summary text." in result.output


def test_summarize_missing_vulnerability(monkeypatch, tmp_path) -> None:
    _summarize_env(monkeypatch, tmp_path)

    class FakeSummaryService:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def generate(self, cve, *, refresh=False):
            return None

    monkeypatch.setattr("vulpulse.ai.service.SummaryService", FakeSummaryService)

    result = CliRunner().invoke(app, ["summarize", "--cve", "CVE-2024-9999"])

    assert result.exit_code == 1
    assert "not found" in result.output


def test_summarize_reports_provider_error(monkeypatch, tmp_path) -> None:
    _summarize_env(monkeypatch, tmp_path)

    class FakeSummaryService:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def generate(self, cve, *, refresh=False):
            raise SummaryError("provider down")

    monkeypatch.setattr("vulpulse.ai.service.SummaryService", FakeSummaryService)

    result = CliRunner().invoke(app, ["summarize", "--cve", "CVE-2024-0001"])

    assert result.exit_code == 1
    assert "provider down" in result.output


def test_enrich_commands(monkeypatch, tmp_path) -> None:
    cli_env(monkeypatch, tmp_path)

    unsupported = CliRunner().invoke(app, ["enrich", "--source", "other"])
    assert unsupported.exit_code == 2
    assert "Unsupported enricher" in unsupported.output

    class FakeEpss:
        async def enrich(self):
            return SimpleNamespace(matched=5, updated=4)

        async def close(self) -> None:
            pass

    monkeypatch.setattr("vulpulse.enrich.epss.EpssEnricher", FakeEpss)

    result = CliRunner().invoke(app, ["enrich"])

    assert result.exit_code == 0
    assert "matched=5 updated=4" in result.output


def test_serve_command_invokes_uvicorn(monkeypatch, tmp_path) -> None:
    cli_env(monkeypatch, tmp_path)
    captured: dict[str, object] = {}

    def fake_run(target, **kwargs) -> None:
        captured["target"] = target
        captured.update(kwargs)

    monkeypatch.setattr("uvicorn.run", fake_run)

    result = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0", "--port", "9001"])

    assert result.exit_code == 0
    assert captured == {
        "target": "vulpulse.api.app:app",
        "host": "0.0.0.0",
        "port": 9001,
        "reload": False,
    }


def test_worker_commands(monkeypatch, tmp_path) -> None:
    cli_env(monkeypatch, tmp_path)
    state = {"once": False, "forever": False}

    class FakeWorker:
        async def run_all_once(self) -> None:
            state["once"] = True

        async def run_forever(self) -> None:
            state["forever"] = True

    monkeypatch.setattr("vulpulse.scheduler.worker.SchedulerWorker", FakeWorker)
    runner = CliRunner()

    assert runner.invoke(app, ["worker", "--once"]).exit_code == 0
    assert state["once"] is True

    assert runner.invoke(app, ["worker"]).exit_code == 0
    assert state["forever"] is True


def test_worker_forever_suppresses_keyboard_interrupt(monkeypatch, tmp_path) -> None:
    cli_env(monkeypatch, tmp_path)

    class InterruptedWorker:
        async def run_forever(self) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr("vulpulse.scheduler.worker.SchedulerWorker", InterruptedWorker)

    result = CliRunner().invoke(app, ["worker"])

    assert result.exit_code == 0


def test_score_and_notify_commands(monkeypatch, tmp_path) -> None:
    _, database_url = cli_env(monkeypatch, tmp_path)
    _create_schema(database_url)
    runner = CliRunner()

    scored = runner.invoke(app, ["score"])
    assert scored.exit_code == 0
    assert "scored=0" in scored.output

    dry_run = runner.invoke(app, ["notify", "--dry-run"])
    assert dry_run.exit_code == 0
    assert "subscriptions=0" in dry_run.output
    assert "dry_run=True" in dry_run.output


def test_notify_test_command(monkeypatch, tmp_path) -> None:
    _, database_url = cli_env(monkeypatch, tmp_path)
    _create_schema(database_url)
    runner = CliRunner()

    assert (
        runner.invoke(
            app,
            [
                "channel",
                "add",
                "--name",
                "wecom-cli",
                "--type",
                "wecom",
                "--webhook-url",
                "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
            ],
        ).exit_code
        == 0
    )

    state: dict[str, object] = {}

    class FakeChannel:
        async def send(self, message) -> None:
            state["subject"] = message.subject

        async def close(self) -> None:
            state["closed"] = True

    monkeypatch.setattr(
        "vulpulse.notifier.factory.build_channel",
        lambda model, settings: FakeChannel(),
    )

    sent = runner.invoke(app, ["notify-test", "--channel", "wecom-cli"])
    assert sent.exit_code == 0
    assert "Test notification sent" in sent.output
    assert state["closed"] is True

    missing = runner.invoke(app, ["notify-test", "--channel", "missing"])
    assert missing.exit_code == 1
    assert "Channel not found" in missing.output


def test_notify_test_reports_send_failure(monkeypatch, tmp_path) -> None:
    _, database_url = cli_env(monkeypatch, tmp_path)
    _create_schema(database_url)
    runner = CliRunner()
    runner.invoke(
        app,
        [
            "channel",
            "add",
            "--name",
            "wecom-cli",
            "--type",
            "wecom",
            "--webhook-url",
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        ],
    )

    class FailingChannel:
        async def send(self, message) -> None:
            raise RuntimeError("webhook rejected")

        async def close(self) -> None:
            pass

    monkeypatch.setattr(
        "vulpulse.notifier.factory.build_channel",
        lambda model, settings: FailingChannel(),
    )

    result = runner.invoke(app, ["notify-test", "--channel", "wecom-cli"])

    assert result.exit_code == 1
    assert "Failed to send test notification" in result.output


def test_channel_add_validation(monkeypatch, tmp_path) -> None:
    _, database_url = cli_env(monkeypatch, tmp_path)
    _create_schema(database_url)
    runner = CliRunner()

    empty = runner.invoke(app, ["channel", "list"])
    assert "No channels configured." in empty.output

    bad_json = runner.invoke(
        app,
        ["channel", "add", "--name", "bad", "--type", "wecom", "--config", "{oops"],
    )
    assert bad_json.exit_code == 2
    assert "Invalid JSON config" in bad_json.output

    not_object = runner.invoke(
        app,
        ["channel", "add", "--name", "bad", "--type", "wecom", "--config", "[]"],
    )
    assert not_object.exit_code == 2
    assert "JSON object" in not_object.output

    missing_url = runner.invoke(app, ["channel", "add", "--name", "bad", "--type", "wecom"])
    assert missing_url.exit_code == 2
    assert "requires --webhook-url" in missing_url.output

    email = runner.invoke(
        app,
        ["channel", "add", "--name", "mail", "--type", "email", "--email-to", "soc@example.com"],
    )
    assert email.exit_code == 0
    listing = runner.invoke(app, ["channel", "list"])
    assert "mail" in listing.output
    assert "enabled=True" in listing.output


def test_subscription_add_advanced_rule_and_validation(monkeypatch, tmp_path) -> None:
    _, database_url = cli_env(monkeypatch, tmp_path)
    _create_schema(database_url)
    runner = CliRunner()

    empty = runner.invoke(app, ["subscription", "list"])
    assert "No subscriptions configured." in empty.output

    runner.invoke(
        app,
        [
            "channel",
            "add",
            "--name",
            "wecom-cli",
            "--type",
            "wecom",
            "--webhook-url",
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
        ],
    )

    added = runner.invoke(
        app,
        [
            "subscription",
            "add",
            "--name",
            "advanced",
            "--channel",
            "wecom-cli",
            "--rule",
            '{"keywords": ["apache"]}',
            "--severity",
            "high",
            "--vendor",
            "apache",
            "--product",
            "struts",
            "--source",
            "nvd",
            "--kev",
            "--exploit",
            "--cvss-min",
            "7.5",
            "--epss-min",
            "0.2",
            "--within-days",
            "30",
        ],
    )
    assert added.exit_code == 0
    listing = runner.invoke(app, ["subscription", "list"]).output
    assert "advanced" in listing
    assert "channel=wecom-cli" in listing
    assert "apache" in listing

    bad_json = runner.invoke(
        app,
        ["subscription", "add", "--name", "bad", "--channel", "wecom-cli", "--rule", "{bad"],
    )
    assert bad_json.exit_code == 2
    assert "Invalid rule JSON" in bad_json.output

    not_object = runner.invoke(
        app,
        ["subscription", "add", "--name", "bad", "--channel", "wecom-cli", "--rule", "[]"],
    )
    assert not_object.exit_code == 2
    assert "Rule must be a JSON object" in not_object.output

    invalid = runner.invoke(
        app,
        ["subscription", "add", "--name", "bad", "--channel", "wecom-cli", "--cvss-min", "11"],
    )
    assert invalid.exit_code == 2
    assert "Invalid rule" in invalid.output


def test_export_to_stdout(monkeypatch, tmp_path) -> None:
    _, database_url = cli_env(monkeypatch, tmp_path)
    _create_schema(database_url)
    _seed_vuln(database_url)

    result = CliRunner().invoke(app, ["export", "--format", "md"])

    assert result.exit_code == 0
    assert "CVE-2024-CLI" in result.output
