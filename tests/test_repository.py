"""Tests for the Part 8 repository: insertion, retrieval, filtering,
statistics, transactions and the detector->database integration.

All tests use temporary databases — never the real sentinelai.db.
"""

import pytest

from database.connection import initialize_database
from database.models import DetectionRecord, ModelRecord
from database.repository import Repository, results_to_records


@pytest.fixture
def repo(tmp_path):
    db_path = tmp_path / "test.db"
    initialize_database(db_path)
    return Repository(db_path)


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


# --- models ---------------------------------------------------------------

def test_model_insert_and_retrieve(repo):
    model_id = repo.insert_model(_model())
    row = repo.get_model(model_id)
    assert row["name"] == "fixture_model"
    assert row["is_active"] == 1


def test_get_active_model_returns_latest_active(repo):
    repo.insert_model(_model(active=False))
    repo.insert_model(_model())
    row = repo.get_active_model()
    assert row is not None and row["name"] == "fixture_model"


def test_get_active_model_none_when_empty(repo):
    assert repo.get_active_model() is None


# --- detection insertion / retrieval ---------------------------------------

def test_detection_insert_and_retrieve(repo):
    event_id = repo.insert_detection(_detection())
    row = repo.get_detection(event_id)
    assert row["flow_id"] == "f1"
    assert row["prediction"] == 1
    assert row["label"] == "ATTACK"
    assert row["is_attack"] == 1
    assert row["attack_probability"] == pytest.approx(0.95)
    assert row["severity"] == "HIGH"
    assert row["status"] == "success"


def test_batch_insertion_all_or_nothing(repo):
    good = [_detection(flow_id=f"f{i}") for i in range(3)]
    bad = _detection(timestamp=None)  # NOT NULL violation
    with pytest.raises(Exception):
        repo.insert_detections(good + [bad])
    # the whole batch was rolled back — no partial saves
    assert repo.get_recent_detections(limit=10) == []


def test_batch_insertion_success(repo):
    records = [_detection(flow_id=f"f{i}") for i in range(3)]
    assert repo.insert_detections(records) == 3
    assert len(repo.get_recent_detections(limit=10)) == 3


def test_empty_batch_is_noop(repo):
    assert repo.insert_detections([]) == 0


# --- filtering ----------------------------------------------------------------

def test_filter_by_label_and_severity(repo):
    repo.insert_detections(
        [
            _detection(flow_id="a", label="ATTACK", severity="HIGH"),
            _detection(flow_id="b", label="BENIGN", severity="LOW"),
            _detection(flow_id="c", label="ATTACK", severity="MEDIUM", attack_probability=0.5),
        ]
    )
    assert [r["flow_id"] for r in repo.get_detections_by_label("ATTACK")] == ["c", "a"]
    assert [r["flow_id"] for r in repo.get_detections_by_severity("HIGH")] == ["a"]


def test_filter_by_attack_status(repo):
    repo.insert_detections(
        [
            _detection(flow_id="a", is_attack=True),
            _detection(flow_id="b", is_attack=False, prediction=0, label="BENIGN"),
            _detection(flow_id="c", is_attack=True),
        ]
    )
    assert [r["flow_id"] for r in repo.get_detections_by_attack(True)] == ["c", "a"]
    assert [r["flow_id"] for r in repo.get_detections_by_attack(False)] == ["b"]


def test_filter_by_response_action_and_status(repo):
    from src.response.actions import ACTION_ALERT_ONLY, ACTION_DRY_RUN_BLOCK, STATUS_LOGGED, STATUS_SIMULATED

    repo.insert_detections(
        [
            _detection(flow_id="a", response_action=ACTION_DRY_RUN_BLOCK, response_mode="DRY_RUN",
                       response_status=STATUS_SIMULATED, response_reason="r"),
            _detection(flow_id="b", response_action=ACTION_ALERT_ONLY, response_mode="DRY_RUN",
                       response_status=STATUS_LOGGED, response_reason="r"),
            _detection(flow_id="c", response_action=ACTION_DRY_RUN_BLOCK, response_mode="DRY_RUN",
                       response_status=STATUS_SIMULATED, response_reason="r"),
        ]
    )
    assert [r["flow_id"] for r in repo.get_detections_by_response_action(ACTION_DRY_RUN_BLOCK)] == ["c", "a"]
    assert [r["flow_id"] for r in repo.get_detections_by_response_status(STATUS_LOGGED)] == ["b"]
    assert repo.get_detections_by_response_action("BLOCK_REQUESTED") == []


def test_detections_in_time_range(repo):
    repo.insert_detections(
        [
            _detection(flow_id="a", timestamp="2026-10-07T10:00:00"),
            _detection(flow_id="b", timestamp="2026-10-07T11:00:00"),
            _detection(flow_id="c", timestamp="2026-10-07T12:00:00"),
        ]
    )
    in_range = repo.get_detections_in_range("2026-10-07T10:30:00", "2026-10-07T11:30:00")
    assert [r["flow_id"] for r in in_range] == ["b"]
    # inclusive boundaries
    assert len(repo.get_detections_in_range("2026-10-07T10:00:00", "2026-10-07T12:00:00")) == 3
    assert repo.get_detections_in_range("2026-10-08T00:00:00", "2026-10-09T00:00:00") == []


def test_attack_probability_statistics(repo):
    repo.insert_detections(
        [
            _detection(flow_id="a", attack_probability=0.9),
            _detection(flow_id="b", attack_probability=0.3),
            _detection(flow_id="c", attack_probability=None, prediction=0, label="BENIGN", is_attack=False),
        ]
    )
    stats = repo.get_attack_probability_statistics()
    assert stats["probability_count"] == 2
    assert stats["min_probability"] == 0.3
    assert stats["max_probability"] == 0.9
    assert stats["average_probability"] == pytest.approx(0.6)


def test_attack_probability_statistics_empty(repo):
    stats = repo.get_attack_probability_statistics()
    assert stats == {
        "probability_count": 0,
        "min_probability": None,
        "max_probability": None,
        "average_probability": None,
    }


def test_legacy_rows_with_null_response_fields(repo):
    """Pre-Part-7 rows (no response fields) remain readable and are only
    counted in the total — never in an action/status category."""
    repo.insert_detection(_detection(flow_id="legacy"))  # response fields default None
    row = repo.get_recent_detections(1)[0]
    assert row["response_action"] is None and row["response_status"] is None
    stats = repo.get_response_statistics()
    assert stats["total_detections"] == 1
    assert stats["no_action_count"] == 0 and stats["alert_count"] == 0
    assert stats["dry_run_block_count"] == 0 and stats["block_requested_count"] == 0


# --- integrity validation ---------------------------------------------------

def test_probability_out_of_range_rejected(repo):
    with pytest.raises(ValueError, match="between 0 and 1"):
        repo.insert_detection(_detection(attack_probability=1.5))
    with pytest.raises(ValueError, match="between 0 and 1"):
        repo.insert_detection(_detection(attack_probability=-0.1))


def test_invalid_prediction_rejected(repo):
    with pytest.raises(ValueError, match="prediction must be"):
        repo.insert_detection(_detection(prediction=7))


def test_invalid_timestamp_rejected(repo):
    with pytest.raises(ValueError, match="ISO datetime"):
        repo.insert_detection(_detection(timestamp="not-a-date"))


def test_invalid_response_action_rejected(repo):
    with pytest.raises(ValueError, match="unknown response_action"):
        repo.insert_detection(_detection(response_action="AUTO_BLOCK_EVERYTHING"))


def test_mismatched_response_status_rejected(repo):
    # DRY_RUN_BLOCK may only carry SIMULATED — never AUTHORIZED
    with pytest.raises(ValueError, match="does not match"):
        repo.insert_detection(
            _detection(response_action="DRY_RUN_BLOCK", response_mode="DRY_RUN",
                       response_status="AUTHORIZED", response_reason="r")
        )


def test_invalid_model_id_rejected(repo):
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):  # foreign key enforced by SQLite
        repo.insert_detection(_detection(model_id=999))


def test_empty_model_name_rejected(repo):
    with pytest.raises(ValueError, match="non-empty"):
        repo.insert_model(ModelRecord(name=""))


def test_recent_detections_limit_and_order(repo):
    repo.insert_detections([_detection(flow_id=f"f{i}") for i in range(5)])
    recent = repo.get_recent_detections(limit=3)
    assert len(recent) == 3
    assert recent[0]["id"] > recent[1]["id"] > recent[2]["id"]


# --- statistics ------------------------------------------------------------------

def test_statistics_empty_database_returns_zeros(repo):
    stats = repo.get_detection_statistics()
    assert stats["total_detections"] == 0
    assert stats["total_attacks"] == 0
    assert stats["total_benign"] == 0
    assert stats["attack_percentage"] == 0.0
    assert stats["status_counts"] == {}


def test_statistics_actual_counts(repo):
    repo.insert_detections(
        [
            _detection(flow_id="a"),  # ATTACK HIGH
            _detection(
                flow_id="b",
                prediction=0,
                label="BENIGN",
                is_attack=False,
                attack_probability=0.05,
                severity="LOW",
            ),
            _detection(flow_id="c", attack_probability=0.5, severity="MEDIUM"),
            _detection(
                flow_id="d",
                status="validation_error",
                prediction=None,
                label=None,
                is_attack=None,
                attack_probability=None,
                severity=None,
            ),
        ]
    )
    stats = repo.get_detection_statistics()
    assert stats["total_detections"] == 4
    assert stats["total_attacks"] == 2
    assert stats["total_benign"] == 1
    assert stats["attack_percentage"] == 50.0
    assert stats["high_severity_count"] == 1
    assert stats["medium_severity_count"] == 1
    assert stats["low_severity_count"] == 1
    assert stats["status_counts"] == {"success": 3, "validation_error": 1}


def test_detections_over_time_groups(repo):
    repo.insert_detections(
        [
            _detection(flow_id="a", timestamp="2026-10-06T10:00:00"),
            _detection(flow_id="b", timestamp="2026-10-06T10:00:00"),
            _detection(flow_id="c", timestamp="2026-10-06T11:00:00"),
        ]
    )
    assert repo.get_detections_over_time() == [
        {"timestamp": "2026-10-06T11:00:00", "count": 1},
        {"timestamp": "2026-10-06T10:00:00", "count": 2},
    ]


def test_model_usage_join(repo):
    model_id = repo.insert_model(_model())
    repo.insert_detections(
        [_detection(model_id=model_id, flow_id="x") for _ in range(2)]
    )
    assert repo.get_model_usage() == [
        {"model_id": model_id, "model_name": "fixture_model", "detections": 2}
    ]


# --- parameterized queries --------------------------------------------------------

def test_sql_injection_attempts_are_stored_literally(repo):
    evil = "'; DROP TABLE detection_events; --"
    repo.insert_detection(_detection(flow_id=evil, label="ATTACK"))
    rows = repo.get_detections_by_label("ATTACK")
    assert len(rows) == 1
    assert rows[0]["flow_id"] == evil
    # the table still exists — nothing was executed
    assert len(repo.get_recent_detections(limit=10)) == 1


# --- integration: Part 7 detector -> repository -> SQLite ---------------------------

def test_detector_to_database_roundtrip(tmp_path, detector_factory):
    """Store REAL DetectionResults produced by the Part 7 engine and read
    them back; the stored record must match the actual result."""
    detector, X = detector_factory
    db_path = tmp_path / "sentinelai.db"
    initialize_database(db_path)
    repo = Repository(db_path)

    model_id = repo.insert_model(_model())

    results = detector.predict_batch(X.iloc[:5])
    assert all(r.status == "success" for r in results)
    repo.insert_detections(results_to_records(results, model_id))

    stored = repo.get_recent_detections(limit=5)
    assert len(stored) == 5
    for result, row in zip(results, reversed(stored)):
        assert row["flow_id"] == result.flow_id
        assert row["prediction"] == result.prediction
        assert row["label"] == result.label
        assert row["severity"] == result.severity
        assert row["status"] == result.status
        assert row["is_attack"] == (1 if result.is_attack else 0)
        if result.attack_probability is None:
            assert row["attack_probability"] is None
        else:
            assert row["attack_probability"] == pytest.approx(result.attack_probability)

    assert repo.get_detection_statistics()["total_detections"] == 5
