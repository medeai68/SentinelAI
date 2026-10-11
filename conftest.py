"""pytest configuration for SentinelAI.

Placing this file at the project root ensures the root directory is on
sys.path when tests run, so `from src.data...` imports work from any
working directory.
"""

import json

import joblib
import pandas as pd
import pytest
from sklearn.compose import ColumnTransformer
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.training.model_utils import save_model


@pytest.fixture
def detector_factory(tmp_path):
    """Build a fully working Part 7 ThreatDetector backed by tiny REAL artifacts.

    The preprocessor and model are trained on deterministic synthetic
    data (standard test practice); the detector is the actual Part 7
    implementation, so its DetectionResults are real engine outputs.
    Returns (detector, X) where X is the synthetic feature frame.
    """
    from src.detection.detector import ThreatDetector

    features = [f"f{i}" for i in range(5)]
    X, y = make_classification(
        n_samples=200, n_features=5, n_informative=3, random_state=42
    )
    X = pd.DataFrame(X, columns=features)
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
                features,
            )
        ],
        remainder="drop",
    )
    X_proc = preprocessor.fit_transform(X)
    model = RandomForestClassifier(n_estimators=10, random_state=42).fit(X_proc, y)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    joblib.dump(preprocessor, artifacts / "preprocessor.joblib")
    (artifacts / "feature_columns.json").write_text(
        json.dumps({"feature_columns": features}), encoding="utf-8"
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

    detector = ThreatDetector.from_artifacts(
        model_path=artifacts / "model.joblib",
        preprocessor_path=artifacts / "preprocessor.joblib",
        features_path=artifacts / "feature_columns.json",
        mapping_path=mapping,
    )
    return detector, X
