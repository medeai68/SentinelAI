"""Tests for Part 7 input feature validation."""

import numpy as np
import pandas as pd
import pytest

from src.detection.feature_validator import FeatureValidationError, validate_features

FEATURES = ["f0", "f1", "f2"]


def make_frame(**overrides):
    base = pd.DataFrame({"f0": [1.0, 2.0], "f1": [3.0, 4.0], "f2": [5.0, 6.0]})
    for key, value in overrides.items():
        base[key] = value
    return base


def test_valid_input_returns_prepared_frame():
    prepared, warnings = validate_features(make_frame(), FEATURES)
    assert list(prepared.columns) == FEATURES
    assert warnings == []


def test_feature_order_reordered_deterministically():
    frame = make_frame()[["f2", "f0", "f1"]]
    prepared, _ = validate_features(frame, FEATURES)
    assert list(prepared.columns) == FEATURES


def test_missing_feature_raises():
    frame = make_frame().drop(columns=["f1"])
    with pytest.raises(FeatureValidationError, match="Missing required feature"):
        validate_features(frame, FEATURES)


def test_wrong_feature_count_raises():
    frame = make_frame().drop(columns=["f1", "f2"])  # only 1 of 3 features
    with pytest.raises(FeatureValidationError):
        validate_features(frame, FEATURES)


def test_unexpected_feature_dropped_with_warning():
    frame = make_frame()
    frame["extra"] = [1, 2]
    prepared, warnings = validate_features(frame, FEATURES)
    assert "extra" not in prepared.columns
    assert any("Dropped unexpected" in w for w in warnings)


def test_empty_dataframe_raises():
    with pytest.raises(FeatureValidationError, match="empty"):
        validate_features(pd.DataFrame(), FEATURES)
    with pytest.raises(FeatureValidationError):
        validate_features(None, FEATURES)


def test_nan_values_allowed_with_warning():
    frame = make_frame()
    frame.loc[0, "f0"] = np.nan
    prepared, warnings = validate_features(frame, FEATURES)
    assert prepared["f0"].isna().sum() == 1
    assert any("NaN" in w for w in warnings)


def test_infinite_values_replaced_with_nan():
    frame = make_frame()
    frame.loc[1, "f2"] = np.inf
    prepared, warnings = validate_features(frame, FEATURES)
    assert not np.isinf(prepared.select_dtypes("number")).any().any()
    assert prepared["f2"].isna().sum() == 1
    assert any("infinite" in w for w in warnings)


def test_non_numeric_column_raises():
    frame = make_frame()
    frame["f1"] = ["a", "b"]
    with pytest.raises(FeatureValidationError, match="not numeric"):
        validate_features(frame, FEATURES)


def test_numeric_strings_coerced_with_warning():
    frame = make_frame()
    frame["f0"] = ["1", "2"]
    prepared, warnings = validate_features(frame, FEATURES)
    assert pd.api.types.is_numeric_dtype(prepared["f0"].dtype)
    assert any("coerced" in w for w in warnings)


def test_raw_dataset_column_names_are_normalized():
    """Raw CIC-style names (spaces) must match the Part 4 cleaned schema
    (underscores) — mirrors cleaning.clean_column_names exactly."""
    frame = pd.DataFrame(
        {"Destination Port": [80.0], "Flow Bytes/s": [123.0], "Fwd Header Length.1": [20.0]}
    )
    prepared, warnings = validate_features(
        frame, ["Destination_Port", "Flow_Bytes/s", "Fwd_Header_Length.1"]
    )
    assert list(prepared.columns) == ["Destination_Port", "Flow_Bytes/s", "Fwd_Header_Length.1"]
    assert warnings == []


def test_normalization_is_idempotent_for_cleaned_names():
    frame = make_frame()  # already-underscored feature names
    prepared, warnings = validate_features(frame, FEATURES)
    assert list(prepared.columns) == FEATURES
    assert warnings == []
