"""Tests for Part 7 result formatting, severity rules and statistics."""

import pytest

from src.detection.result_formatter import (
    compute_severity,
    detection_statistics,
    format_detection_result,
    results_to_frame,
)
from src.detection.schemas import make_error_result

LABEL_MAP = {0: "BENIGN", 1: "ATTACK"}


def make_result(**overrides):
    base = dict(
        timestamp="2026-10-06T12:00:00",
        flow_id="flow_1",
        prediction=1,
        attack_probability=0.97,
        label_map=LABEL_MAP,
        model_name="fixture_model",
        model_version="test",
        feature_count=5,
    )
    base.update(overrides)
    return format_detection_result(**base)


def test_format_attack_result():
    r = make_result()
    assert r.label == "ATTACK"
    assert r.is_attack is True
    assert r.status == "success"
    assert r.confidence == 0.97


def test_format_benign_confidence_is_inverse():
    r = make_result(prediction=0, attack_probability=0.05)
    assert r.label == "BENIGN"
    assert r.is_attack is False
    assert r.confidence == pytest.approx(0.95)


def test_probability_none_gives_none_confidence():
    r = make_result(attack_probability=None)
    assert r.attack_probability is None
    assert r.confidence is None


def test_severity_rules():
    assert compute_severity("BENIGN", 0.99) == "LOW"
    assert compute_severity("ATTACK", 0.9) == "HIGH"
    assert compute_severity("ATTACK", 0.5) == "MEDIUM"
    assert compute_severity("ATTACK", None) == "MEDIUM"
    assert compute_severity(None, None) is None


def test_severity_high_threshold_boundary():
    assert compute_severity("ATTACK", 0.8) == "HIGH"  # threshold is inclusive


def test_results_to_frame_columns_and_row_count():
    results = [make_result(), make_result(prediction=0, attack_probability=0.1)]
    frame = results_to_frame(results)
    assert list(frame.columns) == [
        "timestamp",
        "flow_id",
        "prediction",
        "label",
        "is_attack",
        "attack_probability",
        "severity",
        "model_name",
        "status",
    ]
    assert len(frame) == 2
    assert frame.loc[0, "severity"] == "HIGH"
    assert frame.loc[1, "severity"] == "LOW"


def test_detection_statistics_actual_counts():
    results = [
        make_result(),  # ATTACK, HIGH
        make_result(prediction=0, attack_probability=0.1),  # BENIGN, LOW
        make_result(attack_probability=0.5),  # ATTACK, MEDIUM
        make_error_result(
            timestamp="t", flow_id="bad", status="validation_error", errors=["x"]
        ),
    ]
    stats = detection_statistics(results)
    assert stats["total_flows"] == 4
    assert stats["benign_count"] == 1
    assert stats["attack_count"] == 2
    assert stats["attack_percentage"] == 50.0
    assert stats["high_severity_count"] == 1
    assert stats["medium_severity_count"] == 1
    assert stats["low_severity_count"] == 1
    assert stats["validation_error_count"] == 1

