"""Tests for the Part 7 response policy (pure decision logic)."""

import pytest

from src.response.actions import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_REQUESTED,
    ACTION_DRY_RUN_BLOCK,
    ACTION_NO_ACTION,
    MODE_AUTHORIZED,
    MODE_DRY_RUN,
)
from src.response.policies import (
    DEFAULT_POLICY,
    XGBOOST_VALIDATED_THRESHOLD,
    ResponsePolicy,
)
from src.detection.schemas import DetectionResult


def detection(prediction, probability, *, status="success"):
    return DetectionResult(
        timestamp="2026-10-07T12:00:00",
        flow_id="flow_1",
        prediction=prediction,
        label="ATTACK" if prediction == 1 else "BENIGN",
        is_attack=prediction == 1,
        attack_probability=probability,
        confidence=probability,
        severity="HIGH",
        model_name="fixture",
        model_version="test",
        feature_count=5,
        status=status,
        errors=[],
    )


# --- defaults -----------------------------------------------------------

def test_default_policy_is_dry_run_with_validated_threshold():
    assert DEFAULT_POLICY.mode == MODE_DRY_RUN
    assert DEFAULT_POLICY.detection_threshold == XGBOOST_VALIDATED_THRESHOLD == 0.50
    assert DEFAULT_POLICY.high_confidence_threshold == 0.8


# --- core decision branches ----------------------------------------------

def test_benign_gives_no_action():
    action, reason = DEFAULT_POLICY.recommend(detection(0, 0.02))
    assert action == ACTION_NO_ACTION
    assert "below the detection threshold" in reason


def test_low_confidence_attack_gives_alert_only():
    action, reason = DEFAULT_POLICY.recommend(detection(1, 0.60))
    assert action == ACTION_ALERT_ONLY
    assert "alert only" in reason


def test_high_confidence_attack_gives_dry_run_block_in_default_mode():
    action, reason = DEFAULT_POLICY.recommend(detection(1, 0.98))
    assert action == ACTION_DRY_RUN_BLOCK
    assert "simulated block" in reason
    assert "DRY_RUN" in reason


def test_authorized_mode_high_confidence_gives_block_requested():
    policy = ResponsePolicy(mode=MODE_AUTHORIZED)
    action, reason = policy.recommend(detection(1, 0.98))
    assert action == ACTION_BLOCK_REQUESTED
    assert "authorized adapter" in reason


# --- boundaries --------------------------------------------------------------

def test_boundary_high_confidence_is_inclusive():
    assert DEFAULT_POLICY.recommend(detection(1, 0.80))[0] == ACTION_DRY_RUN_BLOCK
    assert DEFAULT_POLICY.recommend(detection(1, 0.7999))[0] == ACTION_ALERT_ONLY


def test_boundary_detection_threshold_is_inclusive():
    assert DEFAULT_POLICY.recommend(detection(1, 0.50))[0] == ACTION_ALERT_ONLY
    assert DEFAULT_POLICY.recommend(detection(0, 0.4999))[0] == ACTION_NO_ACTION


def test_probability_none_with_attack_prediction_gives_alert_only():
    action, reason = DEFAULT_POLICY.recommend(detection(1, None))
    assert action == ACTION_ALERT_ONLY
    assert "probability unavailable" in reason


def test_probability_none_with_benign_prediction_gives_no_action():
    action, _ = DEFAULT_POLICY.recommend(detection(0, None))
    assert action == ACTION_NO_ACTION


# --- configurability ------------------------------------------------------------

def test_custom_thresholds_are_respected():
    policy = ResponsePolicy(detection_threshold=0.90, high_confidence_threshold=0.95)
    assert policy.recommend(detection(1, 0.92))[0] == ACTION_ALERT_ONLY
    assert policy.recommend(detection(1, 0.96))[0] == ACTION_DRY_RUN_BLOCK
    assert policy.recommend(detection(1, 0.85))[0] == ACTION_NO_ACTION


def test_invalid_policy_configuration_raises():
    with pytest.raises(ValueError, match="Unknown response mode"):
        ResponsePolicy(mode="AUTO_BLOCK_EVERYTHING")
    with pytest.raises(ValueError, match="between 0 and 1"):
        ResponsePolicy(detection_threshold=1.5)
    with pytest.raises(ValueError, match="high_confidence_threshold"):
        ResponsePolicy(detection_threshold=0.9, high_confidence_threshold=0.5)
