from __future__ import annotations

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
