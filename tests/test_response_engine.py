"""Tests for the Part 7 response engine: fail-closed configuration,
DRY_RUN safety, authorized-adapter isolation, database integration,
schema migration and the orchestration CLI.

All fixtures are deterministic; no real firewall/network action exists
anywhere in the project.
"""

import json
import sqlite3

import pandas as pd
import pytest

from database.connection import initialize_database
from database.models import DetectionRecord, ModelRecord
from database.repository import Repository
from src.detection.schemas import DetectionResult
from src.response.actions import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_REQUESTED,
    ACTION_DRY_RUN_BLOCK,
    ACTION_NO_ACTION,
    MODE_AUTHORIZED,
    MODE_DRY_RUN,
    STATUS_AUTHORIZED,
    STATUS_FAILED,
    STATUS_LOGGED,
    STATUS_NONE,
    STATUS_SIMULATED,
    STATUS_SKIPPED,
)
from src.response.policies import DEFAULT_POLICY, ResponsePolicy
from src.response.response_engine import (
    ResponseConfigurationError,
    ResponseEngine,
    main,
    summarize,
)


def detection(prediction, probability, *, status="success", flow_id="flow_1"):
    return DetectionResult(
        timestamp="2026-10-07T12:00:00",
        flow_id=flow_id,
        prediction=prediction,
        label="ATTACK" if prediction == 1 else "BENIGN",
        is_attack=prediction == 1,
        attack_probability=probability,
        confidence=probability,
        severity="HIGH" if prediction == 1 else "LOW",
        model_name="fixture",
        model_version="test",
        feature_count=5,
        status=status,
        errors=[],
    )


class RecordingExecutor:
    """In-memory test adapter — records calls, changes nothing."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def block(self, *, flow_id, reason):
        self.calls.append({"flow_id": flow_id, "reason": reason})
        if self.fail:
            raise RuntimeError("adapter exploded")


# --- fail-closed configuration -------------------------------------------

def test_default_engine_is_dry_run():
    engine = ResponseEngine()
    assert engine.policy.mode == MODE_DRY_RUN


def test_authorized_without_adapter_refuses_to_construct():
    with pytest.raises(ResponseConfigurationError, match="fail closed"):
        ResponseEngine(policy=ResponsePolicy(mode=MODE_AUTHORIZED), executor=None)


# --- DRY_RUN safety --------------------------------------------------------

def test_dry_run_never_calls_executor_even_if_provided():
    executor = RecordingExecutor()
    engine = ResponseEngine(executor=executor)  # default DRY_RUN policy
    result = engine.respond(detection(1, 0.99))
    assert result.action == ACTION_DRY_RUN_BLOCK
    assert result.status == STATUS_SIMULATED
    assert result.mode == MODE_DRY_RUN
    assert executor.calls == []  # nothing was executed


def test_dry_run_actions_and_statuses():
    engine = ResponseEngine()
    assert engine.respond(detection(0, 0.01)).action == ACTION_NO_ACTION
    assert engine.respond(detection(0, 0.01)).status == STATUS_NONE
    assert engine.respond(detection(1, 0.6)).action == ACTION_ALERT_ONLY
    assert engine.respond(detection(1, 0.6)).status == STATUS_LOGGED
    high = engine.respond(detection(1, 0.99))
    assert (high.action, high.status) == (ACTION_DRY_RUN_BLOCK, STATUS_SIMULATED)


def test_invalid_detection_is_skipped():
    engine = ResponseEngine()
    result = engine.respond(detection(None, None, status="validation_error"))
    assert result.action == ACTION_NO_ACTION
    assert result.status == STATUS_SKIPPED
    assert "not applicable" in result.reason


# --- AUTHORIZED mode (isolated adapter only) --------------------------------

def test_authorized_executor_called_once_with_reason():
    executor = RecordingExecutor()
    engine = ResponseEngine(policy=ResponsePolicy(mode=MODE_AUTHORIZED), executor=executor)
    result = engine.respond(detection(1, 0.99))
    assert result.action == ACTION_BLOCK_REQUESTED
    assert result.status == STATUS_AUTHORIZED
    assert len(executor.calls) == 1
    assert executor.calls[0]["flow_id"] == "flow_1"
    assert "high-confidence attack" in executor.calls[0]["reason"]


def test_authorized_executor_not_called_for_alert_only():
    executor = RecordingExecutor()
    engine = ResponseEngine(policy=ResponsePolicy(mode=MODE_AUTHORIZED), executor=executor)
    result = engine.respond(detection(1, 0.6))
    assert result.action == ACTION_ALERT_ONLY
    assert executor.calls == []


def test_adapter_failure_reported_not_escalated():
    executor = RecordingExecutor(fail=True)
    engine = ResponseEngine(policy=ResponsePolicy(mode=MODE_AUTHORIZED), executor=executor)
    result = engine.respond(detection(1, 0.99))
    assert result.status == STATUS_FAILED
    assert "adapter failed" in result.reason


# --- summarize ------------------------------------------------------------------

def test_summarize_actual_counts():
    engine = ResponseEngine()
    results = engine.respond_batch(
        [detection(0, 0.01), detection(1, 0.6), detection(1, 0.99),
         detection(None, None, status="validation_error")]
    )
    stats = summarize(results)
    # the skipped detection also carries NO_ACTION (2 = benign + skipped)
    assert stats == {
        "total": 4, "no_action": 2, "alerts": 1, "dry_run_blocks": 1,
        "block_requests": 0, "skipped": 1, "failed": 0,
    }


# --- database integration (detector -> engine -> repository -> SQLite) -------

def test_full_chain_detector_response_database(tmp_path, detector_factory):
    from src.response.response_engine import ResponseEngine as Engine

    detector, X = detector_factory
    frame = X.iloc[:6].copy()
    frame.insert(0, "flow_id", [f"f{i}" for i in range(6)])

    detections = detector.predict_batch(frame)
    responses = Engine().respond_batch(detections)
    assert len(responses) == len(detections)

    db_path = tmp_path / "chain.db"
    initialize_database(db_path)
    repo = Repository(db_path)
    model_id = repo.insert_model(ModelRecord(name="fixture_model", is_active=True))
    records = [
        DetectionRecord.from_detection_and_response(d, r, model_id)
        for d, r in zip(detections, responses)
    ]
    assert repo.insert_detections(records) == 6

    stored = repo.get_recent_detections(limit=10)
    assert len(stored) == 6
    for response, row in zip(responses, reversed(stored)):
        assert row["response_action"] == response.action
        assert row["response_mode"] == MODE_DRY_RUN
        assert row["response_status"] == response.status
        assert row["response_reason"] == response.reason
        assert row["response_timestamp"] == response.timestamp

    stats = repo.get_response_statistics()
    assert stats["total_detections"] == 6
    assert stats["no_action_count"] + stats["alert_count"] + stats["dry_run_block_count"] == 6
    assert stats["block_requested_count"] == 0  # DRY_RUN never requests a real block
    assert stats["failed_response_count"] == 0


def test_response_statistics_empty_database_returns_zeros(tmp_path):
    db_path = tmp_path / "empty.db"
    initialize_database(db_path)
    stats = Repository(db_path).get_response_statistics()
    assert stats == {
        "total_detections": 0, "no_action_count": 0, "alert_count": 0,
        "dry_run_block_count": 0, "block_requested_count": 0,
        "simulated_count": 0, "authorized_count": 0,
        "failed_response_count": 0, "skipped_count": 0,
    }


# --- schema migration ---------------------------------------------------------

def test_migration_upgrades_old_schema_and_preserves_data(tmp_path):
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
    conn.execute(
        "INSERT INTO detection_events (timestamp, status, flow_id) VALUES ('t1', 'success', 'old_row')"
    )
    conn.commit()
    conn.close()

    initialize_database(db_path)  # must add the response columns in place

    conn = sqlite3.connect(str(db_path))
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(detection_events)")}
        assert {"response_action", "response_mode", "response_status",
                "response_reason", "response_timestamp"} <= columns
        row = conn.execute("SELECT flow_id, response_action FROM detection_events").fetchone()
        assert row[0] == "old_row" and row[1] is None  # existing data preserved
    finally:
        conn.close()


# --- CLI -------------------------------------------------------------------------

def test_cli_refuses_authorized_mode(capsys):
    code = main(["--input", "whatever.csv", "--mode", MODE_AUTHORIZED])
    assert code == 1
    assert "REFUSED" in capsys.readouterr().out


def test_cli_end_to_end_with_store(tmp_path, detector_factory, capsys):
    detector, X = detector_factory
    input_csv = tmp_path / "flows.csv"
    sample = X.iloc[:5].copy()
    sample["Label"] = ["BENIGN", "BENIGN", "ATTACK", "ATTACK", "BENIGN"]
    sample.to_csv(input_csv, index=False)

    out_csv = tmp_path / "responses.csv"
    db_path = tmp_path / "cli.db"
    code = main(
        [
            "--input", str(input_csv),
            "--output", str(out_csv),
            "--store",
            "--db-path", str(db_path),
            "--model", str(detector.model_path),
            "--preprocessor", str(detector.preprocessor_path),
            "--features", str(detector.features_path),
            "--mapping", str(detector.mapping_path),
        ]
    )
    assert code == 0
    captured = capsys.readouterr().out
    assert "Detection + response finished: 5 flow(s)" in captured
    assert "response mode: DRY_RUN" in captured
    assert "vs actual labels:" in captured

    frame = pd.read_csv(out_csv)
    assert len(frame) == 5
    for col in ("response_action", "response_mode", "response_status",
                "response_reason", "response_timestamp", "actual_label"):
        assert col in frame.columns
    assert set(frame["response_mode"]) == {MODE_DRY_RUN}

    conn = sqlite3.connect(str(db_path))
    try:
        assert conn.execute("SELECT COUNT(*) FROM detection_events").fetchone()[0] == 5
    finally:
        conn.close()
