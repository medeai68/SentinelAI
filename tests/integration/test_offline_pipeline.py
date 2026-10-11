"""Integration test (Part 11): the full offline pipeline.

    raw CSV -> Part 4 preprocessing -> trained model artifact
    -> Part 7 detector -> Part 8 database -> Part 9 dashboard data layer

Uses one small deterministic synthetic dataset and temp directories
only. No production models are retrained and nothing outside tmp dirs
is touched.
"""

import numpy as np
import pandas as pd
import pytest

from dashboard.services.dashboard_service import DashboardService
from database.connection import initialize_database
from database.models import ModelRecord
from database.repository import Repository, results_to_records
from src.detection.detector import ThreatDetector
from src.preprocessing.pipeline import PreprocessingPipeline
from src.training.model_utils import save_model
from src.training.train_binary import (
    load_feature_columns,
    load_test_data,
    load_training_data,
    train_random_forest,
)

pytestmark = pytest.mark.integration


def test_full_offline_pipeline(tmp_path):
    # --- 1) synthetic raw CSV (CIC-style, with a label column) ------------
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    rng = np.random.default_rng(42)
    n = 800
    columns = [
        "Flow_Duration",
        "Total_Fwd_Packets",
        "Total_Backward_Packets",
        "Flow_Bytes/s",
        "Flow_Packets/s",
        "Source_Port",
        "Destination_Port",
        "Protocol",
    ]
    frame = pd.DataFrame(rng.normal(size=(n, len(columns))), columns=columns)
    frame["Flow_Duration"] = frame["Flow_Duration"].abs() * 1_000_000
    frame["Source_Port"] = rng.integers(1, 65535, n).astype(float)
    frame["Destination_Port"] = rng.integers(1, 65535, n).astype(float)
    frame["Protocol"] = rng.integers(1, 20, n).astype(float)
    labels = np.array(
        ["BENIGN"] * int(n * 0.8) + ["DoS"] * int(n * 0.1) + ["PortScan"] * int(n * 0.1)
    )
    rng.shuffle(labels)
    frame["Label"] = labels
    frame.to_csv(raw_dir / "flows.csv", index=False)

    # --- 2) Part 4 preprocessing (tmp outputs only) ------------------------
    pipeline = PreprocessingPipeline()
    summary = pipeline.run(
        raw_dir=raw_dir,
        processed_dir=tmp_path / "processed",
        artifacts_dir=tmp_path / "artifacts",
        reports_dir=tmp_path / "reports",
    )
    assert summary["validation_problems"] == []

    # --- 3) train a tiny model with the Part 5 functions -------------------
    feature_cols = load_feature_columns(tmp_path / "artifacts")
    X_train, y_train = load_training_data(tmp_path / "processed", feature_cols)
    X_test, y_test = load_test_data(tmp_path / "processed", feature_cols)
    model = train_random_forest(X_train, y_train, n_estimators=10)
    model_path = tmp_path / "models" / "integration_model.joblib"
    model_path.parent.mkdir()
    save_model(
        model,
        model_path,
        metadata={
            "model_name": "integration_model",
            "dataset": "synthetic fixture",
            "target": "binary_label",
            "random_state": 42,
            "feature_count": len(feature_cols),
            "training_samples": len(X_train),
            "created": "2026-10-06T12:00:00",
        },
    )

    # --- 4) Part 7 detector on a slice of the processed test features ------
    detector = ThreatDetector.from_artifacts(
        model_path=model_path,
        preprocessor_path=tmp_path / "artifacts" / "preprocessor.joblib",
        features_path=tmp_path / "artifacts" / "feature_columns.json",
        mapping_path=tmp_path / "reports" / "label_mapping.json",
    )
    # the detection engine consumes RAW flow features (the preprocessor
    # artifact transforms them) — use raw rows, not the processed CSV
    sample = frame.drop(columns=["Label"]).iloc[:20].copy()
    sample.insert(0, "flow_id", [f"flow_{i}" for i in range(20)])
    results = detector.predict_batch(sample)
    assert len(results) == 20
    assert all(r.status == "success" for r in results)

    # --- 5) Part 8 database ------------------------------------------------
    db_path = tmp_path / "integration.db"
    initialize_database(db_path)
    repo = Repository(db_path)
    model_id = repo.insert_model(ModelRecord(name="integration_model", is_active=True))
    repo.insert_detections(results_to_records(results, model_id))
    assert repo.get_detection_statistics()["total_detections"] == 20

    # --- 6) Part 9 dashboard data layer reads the SAME records -------------
    service = DashboardService(
        db_path,
        reports_dir=tmp_path / "reports",
        models_dir=tmp_path / "models",
        preprocessor_path=tmp_path / "artifacts" / "preprocessor.joblib",
    )
    stats = service.overview_statistics()
    assert stats["total_detections"] == 20
    assert stats["active_model"] == "integration_model"

    stored = service.detections_frame()
    assert len(stored) == 20
    assert set(stored["model_name"]) == {"integration_model"}
    # consistency: stored predictions match the detector's actual output
    stored_predictions = stored.sort_values("id")["prediction"].tolist()
    assert stored_predictions == [r.prediction for r in results]

    # dashboard reads must not modify the database
    before = repo.get_detection_statistics()["total_detections"]
    service.detections_frame()
    service.overview_statistics()
    assert repo.get_detection_statistics()["total_detections"] == before
