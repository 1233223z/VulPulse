from __future__ import annotations

import asyncio
import contextlib
import json
import sqlite3

from typer.testing import CliRunner

from vulpulse import __version__
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
