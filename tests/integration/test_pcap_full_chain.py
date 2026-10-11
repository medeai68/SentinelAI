"""End-to-end offline integration (Part 11, §3):

    Authorized PCAP fixture -> Reader -> Flow Extractor -> Feature
    Extractor -> Compatibility Gate -> ThreatDetector -> ResponseEngine
    -> Repository -> TEMPORARY SQLite -> DashboardService

Both gate outcomes are covered:
  (a) incomplete schema -> honest rejection, no prediction claimed;
  (b) compatible schema -> detection + DRY_RUN response + storage +
      dashboard read-back.

The real production database is never touched.
"""

import json

import joblib
import pandas as pd
import pytest
from scapy.all import Ether, IP, TCP, UDP, wrpcap
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from dashboard.services.dashboard_service import DashboardService
from database.connection import initialize_database
from database.repository import Repository
from src.network.feature_extractor import EXTRACTABLE_FEATURES
from src.network.pcap_pipeline import STATUS_INCOMPLETE, analyze_pcap, _store_results
from src.response.actions import ACTION_DRY_RUN_BLOCK, STATUS_SIMULATED
from src.training.model_utils import save_model

pytestmark = pytest.mark.integration


@pytest.fixture
def authorized_pcap(tmp_path):
    """A tiny benign capture (TCP exchange + UDP exchange)."""
    packets = []
    for i in range(3):
        p = Ether() / IP(src="192.168.0.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        p.time = 1000.0 + i
        packets.append(p)
    for i in range(2):
        p = Ether() / IP(src="10.0.0.1", dst="192.168.0.1") / TCP(sport=80, dport=12345)
        p.time = 1000.5 + i
        packets.append(p)
    u = Ether() / IP(src="192.168.0.2", dst="10.0.0.2") / UDP(sport=53, dport=53)
    u.time = 1010.0
    packets.append(u)
    path = tmp_path / "authorized.pcap"
    wrpcap(str(path), packets)
    return path


def _attack_artifacts(tmp_path):
    """Deterministic artifacts whose model always predicts ATTACK (p=1.0)."""
    columns = sorted(EXTRACTABLE_FEATURES)
    preprocessor = ColumnTransformer(
        [("numeric", Pipeline([("imputer", SimpleImputer(strategy="median")),
                               ("scaler", StandardScaler())]), columns)],
        remainder="drop",
    )
    preprocessor.fit(pd.DataFrame(1.0, index=range(3), columns=columns))
    model = DummyClassifier(strategy="constant", constant=1).fit(
        pd.DataFrame(1.0, index=range(4), columns=columns), [1, 1, 0, 0]
    )
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    joblib.dump(preprocessor, artifacts / "preprocessor.joblib")
    save_model(
        model,
        artifacts / "model.joblib",
        metadata={
            "model_name": "e2e_fixture_model",
            "dataset": "fixture",
            "target": "binary_label",
            "random_state": 42,
            "feature_count": len(columns),
            "training_samples": 4,
            "created": "2026-10-07T12:00:00",
        },
    )
    features_json = tmp_path / "features.json"
    features_json.write_text(json.dumps({"feature_columns": columns}), encoding="utf-8")
    mapping = tmp_path / "mapping.json"
    mapping.write_text(json.dumps({"binary": {"BENIGN": 0, "ATTACK": 1}}), encoding="utf-8")
    return {
        "model_path": artifacts / "model.joblib",
        "preprocessor_path": artifacts / "preprocessor.joblib",
        "features_path": features_json,
        "mapping_path": mapping,
    }


def test_e2e_incomplete_schema_rejects_honestly(authorized_pcap, tmp_path):
    """(a) A 70-name model schema the PCAP subset cannot satisfy."""
    full_schema = sorted(EXTRACTABLE_FEATURES) + [f"Missing_{i}" for i in range(57)]
    features_json = tmp_path / "full_schema.json"
    features_json.write_text(json.dumps({"feature_columns": full_schema}), encoding="utf-8")

    summary = analyze_pcap(authorized_pcap, features_path=features_json)
    assert summary["packets"] == 6
    assert summary["flows"] == 2
    assert summary["compatibility"]["complete"] is False
    assert summary["compatible_flows"] == 0
    assert summary["incompatible_flows"] == 2
    assert summary["analyzed"] == 0                     # no prediction claimed
    assert summary["detection_results"] is None
    assert summary["response_results"] is None
    assert set(summary["frame"]["status"]) == {STATUS_INCOMPLETE}
    # nothing may be stored from an incompatible run
    stored, error = _store_results(summary, db_path=tmp_path / "never.db")
    assert (stored, error) == (0, None)
    assert not (tmp_path / "never.db").exists()


def test_e2e_compatible_full_chain_to_dashboard(authorized_pcap, tmp_path):
    """(b) Compatible schema: PCAP -> detection -> DRY_RUN response ->
    temporary database -> dashboard service read-back."""
    artifacts = _attack_artifacts(tmp_path)

    summary = analyze_pcap(
        authorized_pcap,
        features_path=artifacts["features_path"],
        detector_kwargs=artifacts,
    )
    assert summary["compatibility"]["complete"] is True
    assert summary["analyzed"] == summary["flows"] == 2

    # detection behavior (behavior check, not an accuracy claim)
    detections = summary["detection_results"]
    assert all(d.prediction == 1 and d.is_attack for d in detections)
    assert all(0.0 <= d.attack_probability <= 1.0 for d in detections)
    assert all(d.severity in ("LOW", "MEDIUM", "HIGH") for d in detections)

    # response behavior: DRY_RUN_BLOCK simulated only
    responses = summary["response_results"]
    assert all(r.action == ACTION_DRY_RUN_BLOCK for r in responses)
    assert all(r.status == STATUS_SIMULATED for r in responses)
    assert all(r.mode == "DRY_RUN" for r in responses)

    # storage into a TEMPORARY database
    db_path = tmp_path / "e2e.db"
    stored, error = _store_results(summary, db_path=db_path)
    assert error is None and stored == 2
    initialize_database(db_path)
    repo = Repository(db_path)
    assert repo.get_detection_statistics()["total_detections"] == 2
    stats = repo.get_response_statistics()
    assert stats["dry_run_block_count"] == stats["simulated_count"] == 2
    assert stats["block_requested_count"] == stats["authorized_count"] == 0

    # dashboard service reads the same temporary database
    service = DashboardService(
        db_path, reports_dir=tmp_path / "reports",
        models_dir=tmp_path / "models", preprocessor_path=tmp_path / "pre.joblib",
    )
    overview = service.overview_statistics()
    response_stats = service.response_statistics()
    assert overview["total_detections"] == 2
    assert overview["total_attacks"] == 2
    assert response_stats["dry_run_block_count"] == 2
    frame = service.detections_frame()
    assert len(frame) == 2
    assert set(frame["response_status"]) == {STATUS_SIMULATED}
