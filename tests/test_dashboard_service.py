"""Tests for the Part 9 dashboard service (data layer only — no browser).

All tests use temporary databases and temp report directories; the real
database and real reports are never touched.
"""

import json

import pandas as pd
import pytest

from dashboard.services.dashboard_service import DashboardService
from database.connection import initialize_database
from database.models import DetectionRecord, ModelRecord
from database.repository import Repository


@pytest.fixture
def service(tmp_path):
    """DashboardService backed by a fresh temp database + temp reports dir."""
    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    return DashboardService(
        db_path,
        reports_dir=reports_dir,
        models_dir=tmp_path / "models",
        preprocessor_path=tmp_path / "preprocessor.joblib",
    )


def _model(active=True):
    return ModelRecord(
        name="fixture_model",
        version="test",
        algorithm="RandomForest",
        file_path="models/fixture.joblib",
        feature_count=5,
        is_active=active,
    )


def _detection(**overrides):
    base = dict(
        timestamp="2026-10-06T12:00:00",
        status="success",
        flow_id="f1",
        prediction=1,
        label="ATTACK",
        is_attack=True,
        attack_probability=0.95,
        severity="HIGH",
        model_id=None,
    )
    base.update(overrides)
    return DetectionRecord(**base)


def _populate(repo, model_id):
    repo.insert_detections(
        [
            _detection(flow_id="a", model_id=model_id),
            _detection(
                flow_id="b",
                model_id=model_id,
                prediction=0,
                label="BENIGN",
                is_attack=False,
                attack_probability=0.05,
                severity="LOW",
            ),
            _detection(flow_id="c", model_id=model_id, attack_probability=0.5, severity="MEDIUM"),
        ]
    )


# --- empty database ---------------------------------------------------------

def test_empty_database_statistics(service):
    stats = service.overview_statistics()
    assert stats["total_detections"] == 0
    assert stats["total_attacks"] == 0
    assert stats["active_model"] is None
    assert stats["database_error"] is False
    assert service.has_detection_data() is False


def test_empty_database_detections_frame(service):
    assert service.detections_frame().empty


def test_empty_database_system_status(service):
    status = service.system_status()
    assert status["database_available"] is True  # initialized fixture db exists
    assert status["active_model"] is None
    assert status["model_artifacts"] == []


# --- populated database ------------------------------------------------------

def test_populated_statistics(service):
    repo = service.repository
    model_id = repo.insert_model(_model())
    _populate(repo, model_id)
    stats = service.overview_statistics()
    assert stats["total_detections"] == 3
    assert stats["total_attacks"] == 2
    assert stats["total_benign"] == 1
    assert stats["high_severity_count"] == 1
    assert stats["active_model"] == "fixture_model"
    assert service.has_detection_data() is True


def test_detections_frame_with_model_name(service):
    repo = service.repository
    model_id = repo.insert_model(_model())
    _populate(repo, model_id)
    frame = service.detections_frame()
    assert len(frame) == 3
    assert set(frame["model_name"]) == {"fixture_model"}


# --- filters --------------------------------------------------------------------

def test_detections_frame_filters(service):
    repo = service.repository
    model_id = repo.insert_model(_model())
    _populate(repo, model_id)

    by_label = service.detections_frame(label="ATTACK")
    assert len(by_label) == 2
    by_severity = service.detections_frame(severity="LOW")
    assert len(by_severity) == 1 and by_severity.iloc[0]["flow_id"] == "b"
    both = service.detections_frame(label="ATTACK", severity="HIGH")
    assert len(both) == 1 and both.iloc[0]["flow_id"] == "a"


def test_detection_details(service):
    repo = service.repository
    model_id = repo.insert_model(_model())
    event_id = repo.insert_detection(_detection(flow_id="x", model_id=model_id))
    details = service.detection_details(event_id)
    assert details["flow_id"] == "x"
    assert details["model_name"] == "fixture_model"
    assert service.detection_details(999999) is None


# --- model results / feature importance -------------------------------------------

def test_model_results_missing_returns_empty(service):
    assert service.model_results("optimized_model_results.json") == []
    assert service.available_result_files() == []


def test_model_results_loads_valid_json(service):
    path = service.reports_dir / "optimized_model_results.json"
    path.write_text(
        json.dumps([{"model": "x", "accuracy": 0.9}]), encoding="utf-8"
    )
    assert service.model_results("optimized_model_results.json") == [
        {"model": "x", "accuracy": 0.9}
    ]
    assert service.available_result_files() == ["optimized_model_results.json"]


def test_model_results_malformed_returns_empty(service):
    path = service.reports_dir / "model_results.json"
    path.write_text("{not json", encoding="utf-8")
    assert service.model_results("model_results.json") == []


def test_feature_importance_missing_returns_none(service):
    assert service.feature_importance("random_forest") is None


def test_feature_importance_loads_csv(service):
    path = service.reports_dir / "feature_importance_random_forest.csv"
    pd.DataFrame({"feature": ["a", "b"], "importance": [0.6, 0.4]}).to_csv(path, index=False)
    frame = service.feature_importance("random_forest")
    assert frame is not None and len(frame) == 2


def test_feature_importance_wrong_columns_returns_none(service):
    path = service.reports_dir / "feature_importance_xgboost.csv"
    pd.DataFrame({"foo": [1]}).to_csv(path, index=False)
    assert service.feature_importance("xgboost") is None


# --- missing / broken database ---------------------------------------------------

def test_missing_database_does_not_crash(tmp_path):
    svc = DashboardService(
        tmp_path / "nonexistent" / "no.db",
        reports_dir=tmp_path / "reports2",
        models_dir=tmp_path / "models2",
        preprocessor_path=tmp_path / "pre.joblib",
    )
    stats = svc.overview_statistics()
    assert stats["total_detections"] == 0
    assert stats["database_error"] is True  # no tables -> sqlite error caught
    assert svc.detections_frame().empty
    status = svc.system_status()
    assert status["database_available"] is False


# --- Part 9: richer filters, response counts, registry, system info ---------

def _response_detection(flow_id, action, status, *, label="ATTACK", is_attack=True):
    return DetectionRecord(
        timestamp="2026-10-07T12:00:00",
        status="success",
        flow_id=flow_id,
        prediction=1 if is_attack else 0,
        label=label,
        is_attack=is_attack,
        attack_probability=0.9 if is_attack else 0.01,
        severity="HIGH" if is_attack else "LOW",
        model_id=None,
        response_action=action,
        response_mode="DRY_RUN",
        response_status=status,
        response_reason="fixture",
        response_timestamp="2026-10-07T12:00:01",
    )


def test_detections_frame_filters_by_attack_response_and_range(service):
    from src.response.actions import (
        ACTION_ALERT_ONLY,
        ACTION_DRY_RUN_BLOCK,
        ACTION_NO_ACTION,
        STATUS_LOGGED,
        STATUS_NONE,
        STATUS_SIMULATED,
    )

    repo = service.repository
    repo.insert_detections(
        [
            _response_detection("a", ACTION_DRY_RUN_BLOCK, STATUS_SIMULATED),
            _response_detection("b", ACTION_ALERT_ONLY, STATUS_LOGGED),
            _response_detection("c", ACTION_NO_ACTION, STATUS_NONE,
                                label="BENIGN", is_attack=False),
        ]
    )
    assert service.detections_frame(is_attack=True)["flow_id"].tolist() == ["b", "a"]
    assert service.detections_frame(is_attack=False)["flow_id"].tolist() == ["c"]
    assert service.detections_frame(response_action=ACTION_DRY_RUN_BLOCK)["flow_id"].tolist() == ["a"]
    assert service.detections_frame(response_status=STATUS_LOGGED)["flow_id"].tolist() == ["b"]
    in_range = service.detections_frame(start="2026-10-07T11:00:00", end="2026-10-07T13:00:00")
    assert len(in_range) == 3
    out_of_range = service.detections_frame(start="2026-10-08T00:00:00", end="2026-10-08T23:59:59")
    assert out_of_range.empty


def test_response_status_counts_and_rows(service):
    from src.response.actions import (
        ACTION_ALERT_ONLY,
        ACTION_DRY_RUN_BLOCK,
        STATUS_LOGGED,
        STATUS_SIMULATED,
    )

    repo = service.repository
    repo.insert_detections(
        [
            _response_detection("a", ACTION_DRY_RUN_BLOCK, STATUS_SIMULATED),
            _response_detection("b", ACTION_DRY_RUN_BLOCK, STATUS_SIMULATED),
            _response_detection("c", ACTION_ALERT_ONLY, STATUS_LOGGED),
        ]
    )
    counts = service.response_status_counts()
    assert counts == {STATUS_SIMULATED: 2, STATUS_LOGGED: 1}

    rows = service.response_status_rows()
    # stable order: NONE, LOGGED, SIMULATED, AUTHORIZED, FAILED, SKIPPED
    assert [r["Response status"] for r in rows] == [STATUS_LOGGED, STATUS_SIMULATED]
    simulated_row = next(r for r in rows if r["Response status"] == STATUS_SIMULATED)
    assert simulated_row["Count"] == 2
    assert "simulated" in simulated_row["Meaning"].lower()


def test_response_status_counts_empty_db(service):
    assert service.response_status_counts() == {}
    assert service.response_status_rows() == []


def test_models_registry(service):
    repo = service.repository
    assert service.models_registry() == []
    repo.insert_model(_model())
    registry = service.models_registry()
    assert len(registry) == 1 and registry[0]["name"] == "fixture_model"


def test_system_status_extended_fields(service):
    status = service.system_status()
    assert status["project_name"] == "SentinelAI"
    assert status["python_version"]
    assert status["response_mode"] == "DRY_RUN"
    assert "simulation-only" in status["safety_mode"]
    # the relative path must not leak the local filesystem layout
    assert ":" not in status["database_path_relative"]
    assert status["detection_records"] == 0
    assert status["model_records"] == 0


def test_system_status_counts_populated(service):
    repo = service.repository
    model_id = repo.insert_model(_model())
    _populate(repo, model_id)
    status = service.system_status()
    assert status["detection_records"] == 3
    assert status["model_records"] == 1
    assert status["active_model"] == "fixture_model"


def test_real_database_read_only_and_consistent():
    """Read the ACTUAL project database (Part 8 state) without modifying it.

    Skipped when the database does not exist (e.g. fresh clone). Assertions
    are durable invariants, not snapshot numbers: read consistency and
    read-only behavior. The exact Part 8 counts are validated in the
    Part 9 validation run, not hard-coded here.
    """
    from pathlib import Path as _Path

    db = _Path(__file__).resolve().parent.parent / "database" / "sentinelai.db"
    if not db.exists():
        import pytest as _pytest

        _pytest.skip("real database not present")

    repo = Repository(db)
    before = repo.get_detection_statistics()["total_detections"]

    svc = DashboardService(db)
    stats = svc.overview_statistics()
    response = svc.response_statistics()
    frame = svc.detections_frame(10)
    svc.system_status()

    after = repo.get_detection_statistics()["total_detections"]
    assert before == after  # dashboard reads never modify the database

    assert stats["total_detections"] == response["total_detections"]
    assert stats["total_attacks"] + stats["total_benign"] <= stats["total_detections"]
    # honesty invariant: when no real blocks were requested, every
    # simulated count must equal the dry-run block count
    if response["block_requested_count"] == 0:
        assert response["authorized_count"] == 0
        assert response["simulated_count"] == response["dry_run_block_count"]
    if stats["total_detections"] > 0:
        assert not frame.empty
        assert "response_action" in frame.columns
