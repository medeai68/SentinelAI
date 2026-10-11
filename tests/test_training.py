"""Tests for Part 5 training: data loading, input validation, model
training, and model saving/loading.

All fixtures are small and deterministic (random_state=42) — no
external data and no network access. The real experiment runs via
`python -m src.training.train_binary` once the dataset exists.
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.datasets import make_classification

from src.training.model_utils import (
    ModelArtifactError,
    load_model,
    save_model,
    validate_model_artifact,
)
from src.training.train_binary import (
    load_feature_columns,
    load_test_data,
    load_training_data,
    train_logistic_regression,
    train_random_forest,
    validate_training_inputs,
)

N_FEATURES = 8


@pytest.fixture
def fixture_data():
    """Deterministic binary dataset with 8 features (seed 42)."""
    X, y = make_classification(
        n_samples=300, n_features=N_FEATURES, n_informative=5, random_state=42
    )
    columns = [f"feature_{i}" for i in range(N_FEATURES)]
    return pd.DataFrame(X, columns=columns), pd.Series(y, name="binary_label")


@pytest.fixture
def processed_dir(tmp_path, fixture_data):
    """Tiny fake Part 4 output: train/test CSVs + feature_columns.json."""
    X, y = fixture_data
    processed = tmp_path / "processed"
    processed.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    split = int(len(X) * 0.8)
    train = X.iloc[:split].copy()
    test = X.iloc[split:].copy()
    train["binary_label"] = y.iloc[:split].values
    test["binary_label"] = y.iloc[split:].values
    train.to_csv(processed / "train.csv", index=False)
    test.to_csv(processed / "test.csv", index=False)
    (artifacts / "feature_columns.json").write_text(
        json.dumps({"feature_columns": list(X.columns)}), encoding="utf-8"
    )
    return processed, artifacts


# --- data loading -------------------------------------------------------

def test_load_feature_columns(processed_dir):
    _, artifacts = processed_dir
    cols = load_feature_columns(artifacts)
    assert cols == [f"feature_{i}" for i in range(N_FEATURES)]


def test_load_feature_columns_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="preprocessing.pipeline"):
        load_feature_columns(tmp_path / "nope")


def test_load_training_and_test_data(processed_dir):
    processed, artifacts = processed_dir
    cols = load_feature_columns(artifacts)
    X_train, y_train = load_training_data(processed, cols)
    X_test, y_test = load_test_data(processed, cols)
    assert X_train.shape == (240, N_FEATURES)
    assert X_test.shape == (60, N_FEATURES)
    assert list(X_train.columns) == cols == list(X_test.columns)
    assert set(y_train.unique()) <= {0, 1}
    assert set(y_test.unique()) <= {0, 1}


def test_load_training_data_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="preprocessing.pipeline"):
        load_training_data(tmp_path, [f"feature_{i}" for i in range(N_FEATURES)])


# --- input validation ---------------------------------------------------

def test_validate_training_inputs_ok(fixture_data):
    X, y = fixture_data
    problems = validate_training_inputs(X, y, X, y, list(X.columns))
    assert problems == []


def test_validate_training_inputs_catches_problems(fixture_data):
    X, y = fixture_data

    # invalid binary labels
    bad_y = y.copy()
    bad_y.iloc[0] = 2
    problems = validate_training_inputs(X, y, X, bad_y, list(X.columns))
    assert any("outside {0, 1}" in p for p in problems)

    # NaN labels
    nan_y = y.astype(float)
    nan_y.iloc[0] = np.nan
    problems = validate_training_inputs(X, y, X, nan_y, list(X.columns))
    assert any("NaN" in p for p in problems)

    # NaN in features
    bad_X = X.copy()
    bad_X.iloc[0, 0] = np.nan
    problems = validate_training_inputs(bad_X, y, X, y, list(X.columns))
    assert any("NaN" in p for p in problems)

    # infinite values in features
    inf_X = X.copy()
    inf_X.iloc[0, 0] = np.inf
    problems = validate_training_inputs(inf_X, y, X, y, list(X.columns))
    assert any("infinite" in p for p in problems)

    # mismatched feature order
    shuffled_X = X[list(reversed(X.columns))]
    problems = validate_training_inputs(shuffled_X, y, X, y, list(X.columns))
    assert any("order" in p for p in problems)


# --- model training -----------------------------------------------------

def test_train_logistic_regression(fixture_data):
    X, y = fixture_data
    model = train_logistic_regression(X, y)
    assert set(model.classes_) == {0, 1}
    assert set(np.unique(model.predict(X))) <= {0, 1}


def test_train_random_forest(fixture_data):
    X, y = fixture_data
    model = train_random_forest(X, y, n_estimators=10)
    assert set(model.classes_) == {0, 1}
    assert set(np.unique(model.predict(X))) <= {0, 1}


# --- model saving / loading ---------------------------------------------

def test_save_load_model_roundtrip(tmp_path, fixture_data):
    X, y = fixture_data
    model = train_logistic_regression(X, y)
    path = tmp_path / "models" / "logistic_regression.joblib"
    metadata = {
        "model_name": "logistic_regression",
        "dataset": "fixture",
        "target": "binary_label",
        "random_state": 42,
        "feature_count": N_FEATURES,
        "training_samples": len(X),
    }
    save_model(model, path, metadata=metadata)
    loaded = load_model(path)
    assert np.array_equal(model.predict(X), loaded.predict(X))
    assert validate_model_artifact(path)["model_name"] == "logistic_regression"


def test_load_model_missing_raises(tmp_path):
    with pytest.raises(ModelArtifactError, match="not found"):
        load_model(tmp_path / "missing.joblib")


def test_load_model_corrupt_raises(tmp_path):
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"this is not a joblib file")
    with pytest.raises(ModelArtifactError, match="Failed to load"):
        load_model(bad)


def test_validate_model_artifact_missing_metadata_raises(tmp_path, fixture_data):
    X, y = fixture_data
    model = train_logistic_regression(X, y)
    path = tmp_path / "model.joblib"
    save_model(model, path)  # no metadata
    with pytest.raises(ModelArtifactError, match="[Mm]etadata"):
        validate_model_artifact(path)
