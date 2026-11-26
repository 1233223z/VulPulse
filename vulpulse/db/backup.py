"""Safe SQLite backup and restore using the online backup API."""

from __future__ import annotations

import contextlib
import os
import sqlite3
from pathlib import Path

from sqlalchemy.engine import make_url


class BackupError(RuntimeError):
    """A backup or restore operation could not be completed."""


def sqlite_database_path(database_url: str) -> Path:
    """Resolve a SQLite SQLAlchemy URL to a filesystem path."""
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database:
        raise BackupError("Backup commands currently support SQLite databases only")
    if url.database == ":memory:":
        raise BackupError("Cannot back up an in-memory SQLite database")
    return Path(url.database).expanduser().resolve()


def _integrity_check(path: Path) -> None:
    try:
        with contextlib.closing(sqlite3.connect(path)) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.DatabaseError as exc:
        raise BackupError(f"Could not read SQLite database: {path}") from exc
    if not result or result[0] != "ok":
        raise BackupError(f"SQLite integrity check failed for {path}")


def _copy_database(source: Path, target: Path) -> None:
    temporary = target.with_name(f".{target.name}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        with (
            contextlib.closing(sqlite3.connect(source)) as source_connection,
            contextlib.closing(sqlite3.connect(temporary)) as target_connection,
        ):
            source_connection.backup(target_connection)
        _integrity_check(temporary)
        try:
            os.replace(temporary, target)
        except OSError as exc:
            raise BackupError(
                "Could not replace the database file; stop the API and worker first"
            ) from exc
        with contextlib.suppress(OSError):
            target.chmod(0o600)
    except sqlite3.DatabaseError as exc:
        temporary.unlink(missing_ok=True)
        raise BackupError(f"Could not read SQLite database: {source}") from exc
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def backup_sqlite(
    source: Path,
    output: Path,
    *,
    overwrite: bool = False,
) -> int:
    """Copy a live SQLite database to ``output`` and return its size."""
    source = source.expanduser().resolve()
    output = output.expanduser().resolve()
    if not source.is_file():
        raise BackupError(f"Database does not exist: {source}")
    if output == source:
        raise BackupError("Backup output must differ from the database path")
    if output.exists() and not overwrite:
        raise BackupError(f"Output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    _copy_database(source, output)
    return output.stat().st_size


def restore_sqlite(
    backup: Path,
    target: Path,
    *,
    overwrite: bool = False,
) -> int:
    """Restore a SQLite backup into ``target`` and return its size."""
    backup = backup.expanduser().resolve()
    target = target.expanduser().resolve()
    if not backup.is_file():
        raise BackupError(f"Backup does not exist: {backup}")
    if target == backup:
        raise BackupError("Restore target must differ from the backup path")
    if target.exists() and not overwrite:
        raise BackupError(f"Target already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    _integrity_check(backup)
    _copy_database(backup, target)
    return target.stat().st_size
