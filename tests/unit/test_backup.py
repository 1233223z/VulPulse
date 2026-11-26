from __future__ import annotations

import contextlib
import sqlite3

import pytest

from vulpulse.db.backup import (
    BackupError,
    backup_sqlite,
    restore_sqlite,
    sqlite_database_path,
)


def create_database(path) -> None:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE sample (value TEXT NOT NULL)")
        connection.execute("INSERT INTO sample (value) VALUES ('original')")
        connection.commit()


def read_value(path) -> str:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        return str(connection.execute("SELECT value FROM sample").fetchone()[0])


def test_backup_and_restore_roundtrip(tmp_path) -> None:
    source = tmp_path / "vulpulse.db"
    backup = tmp_path / "backup.db"
    create_database(source)

    size = backup_sqlite(source, backup)

    assert size > 0
    assert read_value(backup) == "original"

    with contextlib.closing(sqlite3.connect(source)) as connection:
        connection.execute("UPDATE sample SET value = 'changed'")
        connection.commit()
    assert read_value(source) == "changed"

    restore_sqlite(backup, source, overwrite=True)

    assert read_value(source) == "original"


def test_backup_refuses_to_overwrite_without_force(tmp_path) -> None:
    source = tmp_path / "vulpulse.db"
    backup = tmp_path / "backup.db"
    create_database(source)
    backup.write_text("existing")

    with pytest.raises(BackupError, match="already exists"):
        backup_sqlite(source, backup)

    backup_sqlite(source, backup, overwrite=True)
    assert read_value(backup) == "original"


def test_backup_rejects_same_path_and_non_sqlite(tmp_path) -> None:
    source = tmp_path / "vulpulse.db"
    create_database(source)

    with pytest.raises(BackupError, match="differ"):
        backup_sqlite(source, source)

    with pytest.raises(BackupError, match="SQLite"):
        sqlite_database_path("postgresql+asyncpg://user:pass@example.test/db")


def test_restore_refuses_existing_target_without_force(tmp_path) -> None:
    source = tmp_path / "vulpulse.db"
    backup = tmp_path / "backup.db"
    create_database(source)
    backup_sqlite(source, backup)
    source.write_text("existing")

    with pytest.raises(BackupError, match="already exists"):
        restore_sqlite(backup, source)

    restore_sqlite(backup, source, overwrite=True)
    assert read_value(source) == "original"
