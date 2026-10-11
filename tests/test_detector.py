"""Tests for the Part 7 ThreatDetector: artifact loading, prediction,
batch handling, invalid-input handling and determinism.

Fixtures are tiny REAL artifacts (a fitted preprocessor and a trained
model) built in temp directories from deterministic synthetic data —
standard test practice, not fabricated project results.
"""

import json

import numpy as np
import pandas as pd
import pytest
from sklearn.compose import ColumnTransformer
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

import joblib

from src.detection.detector import ThreatDetector
from src.detection.schemas import STATUS_SUCCESS
from src.training.model_utils import ModelArtifactError, save_model

FEATURES = [f"f{i}" for i in range(5)]


def _build_artifacts(tmp_path, model_has_proba=True):
    """Build a tiny fitted preprocessor + model + metadata in temp dirs."""
    X, y = make_classification(
        n_samples=200, n_features=5, n_informative=3, random_state=42
    )
    X = pd.DataFrame(X, columns=FEATURES)
    y = pd.Series(y, name="binary_label")

    preprocessor = ColumnTransformer(
        [
            (
                "numeric",
                Pipeline(
                    [
                        ("imputer", SimpleImputer(strategy="median")),
                        ("scaler", StandardScaler()),
                    ]
                ),
                FEATURES,
            )
        ],
        remainder="drop",
    )
    X_proc = preprocessor.fit_transform(X)

    if model_has_proba:
        model = RandomForestClassifier(n_estimators=10, random_state=42).fit(X_proc, y)
    else:
        model = SVC(kernel="linear", random_state=42).fit(X_proc, y)  # no predict_proba

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    joblib.dump(preprocessor, artifacts / "preprocessor.joblib")
    (artifacts / "feature_columns.json").write_text(
        json.dumps({"feature_columns": FEATURES}), encoding="utf-8"
    )
    save_model(
        model,
        artifacts / "model.joblib",
        metadata={
            "model_name": "fixture_model",
            "dataset": "fixture",
            "target": "binary_label",
            "random_state": 42,
            "feature_count": 5,
            "training_samples": 200,
            "created": "2026-10-06T12:00:00",
        },
    )
    mapping = tmp_path / "label_mapping.json"
    mapping.write_text(
        json.dumps({"binary": {"BENIGN": 0, "ATTACK": 1}}), encoding="utf-8"
    )
    return X, artifacts, mapping


@pytest.fixture
def detector(detector_factory):
    """Shared detector fixture (see conftest.py) — avoids duplicate artifacts."""
    return detector_factory


def sample_frame(X, n=4):
    return X.iloc[:n].copy()


# --- artifact loading -------------------------------------------------------

def test_artifact_not_found_handling(tmp_path):
    with pytest.raises(ModelArtifactError, match="not found"):
        ThreatDetector.from_artifacts(
            model_path=tmp_path / "missing.joblib",
            preprocessor_path=tmp_path / "missing_preprocessor.joblib",
            features_path=tmp_path / "missing_features.json",
            mapping_path=tmp_path / "missing_mapping.json",
        )


def test_model_and_preprocessor_loaded(detector):
    det, _ = detector
    assert det._loaded
    assert det.model is not None
    assert det.preprocessor is not None
    assert det.feature_cols == FEATURES
    assert det.label_map == {0: "BENIGN", 1: "ATTACK"}
    assert det.model_name == "fixture_model"
    assert det.model_version == "2026-10-06T12:00:00"


# --- prediction --------------------------------------------------------------

def test_valid_input_prediction(detector):
    det, X = detector
    result = det.predict(sample_frame(X, n=1).iloc[0])
    assert result.status == STATUS_SUCCESS
    assert result.prediction in (0, 1)
    assert result.label in ("BENIGN", "ATTACK")
    assert result.is_attack == (result.prediction == 1)
    assert result.attack_probability is not None
    assert 0.0 <= result.attack_probability <= 1.0
    assert result.feature_count == 5
    assert result.model_name == "fixture_model"


def test_dict_input_prediction(detector):
    det, X = detector
    record = {col: float(X.iloc[0][col]) for col in FEATURES}
    result = det.predict(record)
    assert result.status == STATUS_SUCCESS


def test_probability_output(detector):
    det, X = detector
    result = det.predict(sample_frame(X, n=1).iloc[0])
    assert isinstance(result.attack_probability, float)
    assert 0.0 <= result.attack_probability <= 1.0


def test_model_without_proba_gives_none(tmp_path):
    X, artifacts, mapping = _build_artifacts(tmp_path, model_has_proba=False)
    det = ThreatDetector.from_artifacts(
        model_path=artifacts / "model.joblib",
        preprocessor_path=artifacts / "preprocessor.joblib",
        features_path=artifacts / "feature_columns.json",
        mapping_path=mapping,
    )
    result = det.predict(X.iloc[0])
    assert result.status == STATUS_SUCCESS
    assert result.attack_probability is None
    assert result.severity in ("LOW", "MEDIUM")


# --- batch prediction ----------------------------------------------------------

def test_batch_prediction_one_result_per_row(detector):
    det, X = detector
    results = det.predict_batch(sample_frame(X, n=6))
    assert len(results) == 6
    assert all(r.status == STATUS_SUCCESS for r in results)
    assert all(r.prediction in (0, 1) for r in results)


def test_batch_preserves_flow_ids(detector):
    det, X = detector
    frame = sample_frame(X, n=3)
    frame.insert(0, "flow_id", ["a", "b", "c"])
    results = det.predict_batch(frame)
    assert [r.flow_id for r in results] == ["a", "b", "c"]


def test_batch_generates_deterministic_ids_without_flow_id(detector):
    det, X = detector
    results = det.predict_batch(sample_frame(X, n=3))
    assert [r.flow_id for r in results] == ["row_0", "row_1", "row_2"]


def test_deterministic_output(detector):
    det, X = detector
    frame = sample_frame(X, n=8)
    r1 = [r.prediction for r in det.predict_batch(frame)]
    r2 = [r.prediction for r in det.predict_batch(frame)]
    assert r1 == r2


# --- invalid input handling ----------------------------------------------------

def test_missing_feature_returns_error_results(detector):
    det, X = detector
    frame = sample_frame(X, n=2).drop(columns=["f2"])
    results = det.predict_batch(frame)
    assert len(results) == 2
    assert all(r.status == "validation_error" for r in results)
    assert all("Missing required feature" in r.errors[0] for r in results)


def test_wrong_feature_count_returns_error_results(detector):
    det, X = detector
    frame = sample_frame(X, n=2).drop(columns=["f3", "f4"])
    results = det.predict_batch(frame)
    assert all(r.status == "validation_error" for r in results)


def test_unexpected_feature_is_handled(detector):
    det, X = detector
    frame = sample_frame(X, n=2)
    frame["unexpected"] = [1, 2]
    results = det.predict_batch(frame)
    assert all(r.status == STATUS_SUCCESS for r in results)


def test_nan_input_imputed_by_artifact(detector):
    det, X = detector
    frame = sample_frame(X, n=2)
    frame.loc[0, "f0"] = np.nan
    results = det.predict_batch(frame)
    assert all(r.status == STATUS_SUCCESS for r in results)
    for r in results:
        assert r.attack_probability is None or not np.isnan(r.attack_probability)


def test_infinite_input_handled(detector):
    det, X = detector
    frame = sample_frame(X, n=2)
    frame.loc[1, "f1"] = np.inf
    results = det.predict_batch(frame)
    assert all(r.status == STATUS_SUCCESS for r in results)


def test_empty_dataframe_yields_no_results(detector):
    det, _ = detector
    results = det.predict_batch(pd.DataFrame(columns=FEATURES))
    assert results == []


# --- CLI -----------------------------------------------------------------------

def test_cli_end_to_end_with_fixture(tmp_path, capsys):
    X, artifacts, mapping = _build_artifacts(tmp_path)
    input_csv = tmp_path / "flows.csv"
    sample = X.iloc[:5].copy()
    sample.insert(0, "flow_id", [f"f{i}" for i in range(5)])
    sample.to_csv(input_csv, index=False)
    output_csv = tmp_path / "results.csv"

    from src.detection.detector import main

    code = main(
        [
            "--input", str(input_csv),
            "--output", str(output_csv),
            "--model", str(artifacts / "model.joblib"),
            "--preprocessor", str(artifacts / "preprocessor.joblib"),
            "--features", str(artifacts / "feature_columns.json"),
            "--mapping", str(mapping),
        ]
    )
    assert code == 0
    assert output_csv.exists()
    frame = pd.read_csv(output_csv)
    assert len(frame) == 5
    assert {"prediction", "label", "severity", "model_name", "status"} <= set(frame.columns)
    assert "Detection finished" in capsys.readouterr().out


def test_cli_missing_model_reports_clearly(tmp_path, capsys, monkeypatch):
    input_csv = tmp_path / "flows.csv"
    pd.DataFrame({"f0": [1.0]}).to_csv(input_csv, index=False)

    import src.detection.detector as detector_module

    # Force the no-default-model state (the real project now has a Part 6
    # optimized model configured, so this path must be simulated here).
    monkeypatch.setattr(detector_module.dcfg, "DEFAULT_MODEL_FILE", None)

    code = detector_module.main(["--input", str(input_csv)])
    assert code == 1
    assert "no optimized model is available" in capsys.readouterr().out
