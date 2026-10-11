"""Tests for Part 8 database initialization and connection handling.

All tests use temporary databases — the real database/sentinelai.db is
never touched by unit tests.
"""

import sqlite3

import pytest

from database.connection import DatabaseError, connect, initialize_database


def test_initialize_database_creates_dir_tables_and_indexes(tmp_path):
    db_path = tmp_path / "nested" / "test.db"
    path = initialize_database(db_path)
    assert path == db_path
    assert db_path.exists()
    conn = sqlite3.connect(str(db_path))
    try:
        tables = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {"detection_events", "models"} <= tables
        indexes = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
        expected = {
            "idx_detection_timestamp",
            "idx_detection_label",
            "idx_detection_severity",
            "idx_detection_is_attack",
            "idx_detection_model_id",
        }
        assert expected <= indexes
    finally:
        conn.close()


def test_repeated_initialization_is_safe(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute("INSERT INTO models (name) VALUES ('keep_me')")
    conn.commit()
    conn.close()

    initialize_database(db_path)  # must not drop anything

    conn = sqlite3.connect(str(db_path))
    try:
        assert conn.execute("SELECT COUNT(*) FROM models").fetchone()[0] == 1
    finally:
        conn.close()


def test_initialize_database_missing_schema(tmp_path):
    with pytest.raises(DatabaseError, match="Schema file not found"):
        initialize_database(tmp_path / "test.db", schema_path=tmp_path / "missing.sql")


def test_migration_from_old_schema_is_idempotent(tmp_path):
    """Old schema -> migrate -> migrate again: response columns appear
    exactly once and existing rows/models are preserved throughout."""
    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE models (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, "
        "version TEXT, algorithm TEXT, file_path TEXT, feature_count INTEGER, "
        "created_at TEXT NOT NULL DEFAULT (datetime('now')), is_active INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute(
        "CREATE TABLE detection_events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp TEXT NOT NULL, flow_id TEXT, prediction INTEGER, label TEXT, "
        "is_attack INTEGER, attack_probability REAL, severity TEXT, model_id INTEGER, "
        "status TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))"
    )
    conn.execute("INSERT INTO models (name, is_active) VALUES ('legacy_model', 1)")
    conn.execute(
        "INSERT INTO detection_events (timestamp, status, flow_id, model_id) "
        "VALUES ('2026-10-01T00:00:00', 'success', 'legacy_row', 1)"
    )
    conn.commit()
    conn.close()

    initialize_database(db_path)
    initialize_database(db_path)  # idempotent: must be safe a second time

    conn = sqlite3.connect(str(db_path))
    try:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(detection_events)")]
        for column in ("response_action", "response_mode", "response_status",
                       "response_reason", "response_timestamp"):
            assert columns.count(column) == 1  # added exactly once
        assert conn.execute("SELECT COUNT(*) FROM models").fetchone()[0] == 1
        row = conn.execute(
            "SELECT flow_id, model_id, response_action FROM detection_events"
        ).fetchone()
        assert row == ("legacy_row", 1, None)  # rows and FKs preserved
        indexes = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
        assert {"idx_detection_response_action", "idx_detection_response_status"} <= indexes
    finally:
        conn.close()


def test_connect_commits_on_success(tmp_path):
    initialize_database(tmp_path / "test.db")
    with connect(tmp_path / "test.db") as conn:
        conn.execute("INSERT INTO models (name) VALUES ('a')")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    try:
        assert conn.execute("SELECT COUNT(*) FROM models").fetchone()[0] == 1
    finally:
        conn.close()


def test_connect_rolls_back_on_error(tmp_path):
    initialize_database(tmp_path / "test.db")
    with pytest.raises(RuntimeError):
        with connect(tmp_path / "test.db") as conn:
            conn.execute("INSERT INTO models (name) VALUES ('a')")
            raise RuntimeError("boom")
    conn = sqlite3.connect(str(tmp_path / "test.db"))
    try:
        assert conn.execute("SELECT COUNT(*) FROM models").fetchone()[0] == 0
    finally:
        conn.close()


def test_foreign_keys_enforced(tmp_path):
    initialize_database(tmp_path / "test.db")
    with pytest.raises(sqlite3.IntegrityError):
        with connect(tmp_path / "test.db") as conn:
            conn.execute(
                "INSERT INTO detection_events (timestamp, status, model_id) "
                "VALUES ('t', 'success', 999)"
            )
