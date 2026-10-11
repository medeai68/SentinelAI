"""SQLite connection handling for SentinelAI (Part 8).

Project-relative database path, a context manager with guaranteed
closing, configurable timeout, safe exception handling, and schema
initialization that is safe to run repeatedly (never drops tables).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "database" / "sentinelai.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
CONNECTION_TIMEOUT = 5.0  # seconds; configurable per connect() call

REQUIRED_TABLES = {"detection_events", "models"}

# Part 7 (response) columns added to detection_events. Existing databases
# are upgraded with ALTER TABLE ADD COLUMN — additive only, never dropping
# data. Column names/types are code constants, not user input.
_RESPONSE_COLUMNS = {
    "response_action": "TEXT",
    "response_mode": "TEXT",
    "response_status": "TEXT",
    "response_reason": "TEXT",
    "response_timestamp": "TEXT",
}


def _migrate_schema(connection: sqlite3.Connection) -> None:
    """Additive-only migration: add any missing response columns.

    The response indexes are created HERE (after the columns exist) rather
    than in schema.sql, so databases created before Part 7 migrate without
    referencing missing columns. IF NOT EXISTS keeps the whole step
    idempotent.
    """
    existing = {
        row[1] for row in connection.execute("PRAGMA table_info(detection_events)")
    }
    for column, column_type in _RESPONSE_COLUMNS.items():
        if column not in existing:
            connection.execute(
                f"ALTER TABLE detection_events ADD COLUMN {column} {column_type}"
            )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_detection_response_action "
        "ON detection_events(response_action)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_detection_response_status "
        "ON detection_events(response_status)"
    )


class DatabaseError(Exception):
    """Raised when a database operation fails."""


def get_database_path() -> Path:
    """Return the project-relative SQLite database path."""
    return DATABASE_PATH


@contextmanager
def connect(db_path=None, *, timeout: float = CONNECTION_TIMEOUT):
    """Context manager returning a sqlite3.Connection.

    - commits on successful exit,
    - rolls back on exception,
    - always closes the connection,
    - sets sqlite3.Row as the row factory,
    - enables foreign keys.
    """
    path = Path(db_path) if db_path is not None else DATABASE_PATH
    connection = sqlite3.connect(str(path), timeout=timeout)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(db_path=None, *, schema_path: Path = SCHEMA_PATH) -> Path:
    """Create the database directory, execute schema.sql and verify tables.

    Safe to call repeatedly: the schema uses CREATE ... IF NOT EXISTS
    only, and the additive migration (ALTER TABLE ADD COLUMN) upgrades
    older databases in place — existing tables and data are never
    dropped.
    """
    path = Path(db_path) if db_path is not None else DATABASE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    if not schema_path.exists():
        raise DatabaseError(f"Schema file not found: {schema_path}")
    schema_sql = schema_path.read_text(encoding="utf-8")

    connection = sqlite3.connect(str(path), timeout=CONNECTION_TIMEOUT)
    try:
        connection.executescript(schema_sql)
        _migrate_schema(connection)
        connection.commit()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        missing = REQUIRED_TABLES - tables
        if missing:
            raise DatabaseError(
                f"Schema verification failed - missing tables: {sorted(missing)}"
            )
    finally:
        connection.close()
    return path
