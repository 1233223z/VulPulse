from __future__ import annotations

import contextlib
import json
import sqlite3

from typer.testing import CliRunner

from vulpulse import __version__
from vulpulse.cli import app


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
