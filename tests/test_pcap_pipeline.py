"""Tests for the Part 10 PCAP pipeline: end-to-end analysis, feature
compatibility, detector integration (compatible branch only), CLI and
database storage.

All PCAP fixtures are tiny benign captures built with scapy — no attack
traffic is generated anywhere in this project.
"""

import json
import sqlite3

import joblib
import pandas as pd
import pytest
from scapy.all import Ether, IP, TCP, UDP, wrpcap
from sklearn.compose import ColumnTransformer
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.network.feature_extractor import EXTRACTABLE_FEATURES
from src.network.pcap_pipeline import (
    STATUS_INCOMPLETE,
    STATUS_SUCCESS,
    analyze_pcap,
    main,
    write_feature_compatibility,
)
from src.training.model_utils import save_model

REQUIRED_FULL = sorted(EXTRACTABLE_FEATURES) + [
    "Fwd_IAT_Mean",
    "Bwd_IAT_Std",
    "Fwd_PSH_Flags",
    "Init_Win_bytes_forward",
]


def _benign_pcap(path):
    """A tiny benign capture: one TCP exchange + one UDP exchange."""
    packets = []
    for i in range(3):
        pkt = Ether() / IP(src="192.168.0.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        pkt.time = 1000.0 + i
        packets.append(pkt)
    for i in range(2):
        pkt = Ether() / IP(src="10.0.0.1", dst="192.168.0.1") / TCP(sport=80, dport=12345)
        pkt.time = 1000.5 + i
        packets.append(pkt)
    udp = Ether() / IP(src="192.168.0.2", dst="10.0.0.2") / UDP(sport=53, dport=53)
    udp.time = 1010.0
    packets.append(udp)
    wrpcap(str(path), packets)
    return path


@pytest.fixture
def benign_pcap(tmp_path):
    return _benign_pcap(tmp_path / "benign.pcap")


@pytest.fixture
def full_features_json(tmp_path):
    path = tmp_path / "feature_columns_full.json"
    path.write_text(json.dumps({"feature_columns": REQUIRED_FULL}), encoding="utf-8")
    return path


@pytest.fixture
def compatible_detector(tmp_path):
    """Detector artifacts trained on the EXTRACTABLE_FEATURES columns."""
    columns = sorted(EXTRACTABLE_FEATURES)
    X, y = make_classification(
        n_samples=300, n_features=len(columns), n_informative=8, random_state=42
    )
    X = pd.DataFrame(X, columns=columns)
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
                columns,
            )
        ],
        remainder="drop",
    )
    X_proc = preprocessor.fit_transform(X)
    model = RandomForestClassifier(n_estimators=10, random_state=42).fit(X_proc, y)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    joblib.dump(preprocessor, artifacts / "preprocessor.joblib")
    save_model(
        model,
        artifacts / "model.joblib",
        metadata={
            "model_name": "pcap_fixture_model",
            "dataset": "fixture",
            "target": "binary_label",
            "random_state": 42,
            "feature_count": len(columns),
            "training_samples": len(X),
            "created": "2026-10-06T12:00:00",
        },
    )
    features_json = tmp_path / "feature_columns.json"
    features_json.write_text(
        json.dumps({"feature_columns": columns}), encoding="utf-8"
    )
    mapping = tmp_path / "label_mapping.json"
    mapping.write_text(
        json.dumps({"binary": {"BENIGN": 0, "ATTACK": 1}}), encoding="utf-8"
    )
    return {
        "model_path": artifacts / "model.joblib",
        "preprocessor_path": artifacts / "preprocessor.joblib",
        "features_path": features_json,
        "mapping_path": mapping,
    }


# --- end-to-end analysis -----------------------------------------------------

def test_analyze_incomplete_features(benign_pcap, full_features_json):
    summary = analyze_pcap(benign_pcap, features_path=full_features_json)
    assert summary["packets"] == 6
    assert summary["flows"] == 2
    assert summary["analyzed"] == 0
    assert summary["rejected"] == 2
    comp = summary["compatibility"]
    assert comp["complete"] is False
    assert "Fwd_IAT_Mean" in comp["missing"]
    frame = summary["frame"]
    assert set(frame["status"]) == {STATUS_INCOMPLETE}
    assert frame["predicted_label"].isna().all()
    assert frame["attack_probability"].isna().all()


def test_analyze_without_features_file(benign_pcap, tmp_path):
    summary = analyze_pcap(benign_pcap, features_path=tmp_path / "missing.json")
    assert summary["compatibility"]["complete"] is False
    assert summary["rejected"] == summary["flows"]
    assert set(summary["frame"]["status"]) == {STATUS_INCOMPLETE}


def test_analyze_compatible_runs_detector(benign_pcap, compatible_detector):
    summary = analyze_pcap(
        benign_pcap,
        features_path=compatible_detector["features_path"],
        detector_kwargs=compatible_detector,
    )
    comp = summary["compatibility"]
    assert comp["complete"] is True
    assert summary["analyzed"] == summary["flows"] == 2
    frame = summary["frame"]
    assert set(frame["status"]) == {STATUS_SUCCESS}
    assert set(frame["predicted_label"]) <= {"BENIGN", "ATTACK"}
    assert frame["attack_probability"].between(0, 1).all()
    assert set(frame["severity"]) <= {"LOW", "MEDIUM", "HIGH"}
    assert summary["detection_results"] is not None
    assert len(summary["detection_results"]) == 2
    # Part 10 contract: counts agree and responses exist for every detection
    assert summary["compatible_flows"] == 2
    assert summary["incompatible_flows"] == 0
    assert summary["errors"] == 0
    assert len(summary["response_results"]) == 2
    assert summary["response_mode"] == "DRY_RUN"


def test_analyze_compatible_without_detector_does_not_predict(benign_pcap, tmp_path):
    """Compatible schema but no model artifacts -> no prediction claimed."""
    import json as _json

    features = tmp_path / "subset_features.json"
    features.write_text(
        _json.dumps({"feature_columns": sorted(EXTRACTABLE_FEATURES)}), encoding="utf-8"
    )
    summary = analyze_pcap(benign_pcap, features_path=features, detector_kwargs=None)
    assert summary["compatibility"]["complete"] is True
    assert summary["analyzed"] == 0
    assert summary["detection_results"] is None
    assert summary["response_results"] is None
    assert set(summary["frame"]["status"]) == {STATUS_INCOMPLETE}


def test_model_metadata_feature_count_mismatch_blocks_detection(
    benign_pcap, compatible_detector
):
    """If model metadata's feature count disagrees with the saved feature
    list, detection must be rejected with a clear reason."""
    metadata_path = compatible_detector["model_path"].parent / "metadata" / "model.json"
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    payload["feature_count"] = 99  # deliberate mismatch
    metadata_path.write_text(json.dumps(payload), encoding="utf-8")

    summary = analyze_pcap(
        benign_pcap,
        features_path=compatible_detector["features_path"],
        detector_kwargs=compatible_detector,
    )
    comp = summary["compatibility"]
    assert comp["complete"] is False
    assert comp["model_feature_count"] == 99
    assert any("metadata expects 99" in m for m in comp["missing"])
    assert summary["analyzed"] == 0
    assert summary["detection_results"] is None


# --- Part 10: response integration (simulated only) --------------------------

@pytest.fixture
def attack_detector(tmp_path):
    """Deterministic artifacts whose model ALWAYS predicts ATTACK (p=1.0).

    Uses a fitted preprocessor (real transform path) + DummyClassifier —
    a fixture, not a production model; guarantees the DRY_RUN_BLOCK path
    is exercised deterministically.
    """
    from sklearn.dummy import DummyClassifier

    columns = sorted(EXTRACTABLE_FEATURES)
    X = pd.DataFrame({c: [float(i), float(i + 1)] for i, c in enumerate([0] * len(columns))})
    preprocessor = ColumnTransformer(
        [("numeric", Pipeline([("imputer", SimpleImputer(strategy="median")),
                               ("scaler", StandardScaler())]), columns)],
        remainder="drop",
    )
    preprocessor.fit(pd.DataFrame(1.0, index=range(3), columns=columns))
    # both classes must be present so classes_ = [0, 1] and predict_proba
    # returns a full two-column distribution (constant prediction = 1)
    model = DummyClassifier(strategy="constant", constant=1).fit(
        pd.DataFrame(1.0, index=range(4), columns=columns), [1, 1, 0, 0]
    )
    artifacts = tmp_path / "attack_artifacts"
    artifacts.mkdir()
    joblib.dump(preprocessor, artifacts / "preprocessor.joblib")
    save_model(
        model,
        artifacts / "model.joblib",
        metadata={
            "model_name": "attack_fixture_model",
            "dataset": "fixture",
            "target": "binary_label",
            "random_state": 42,
            "feature_count": len(columns),
            "training_samples": 4,
            "created": "2026-10-07T12:00:00",
        },
    )
    features_json = tmp_path / "attack_features.json"
    features_json.write_text(
        json.dumps({"feature_columns": columns}), encoding="utf-8"
    )
    mapping = tmp_path / "attack_mapping.json"
    mapping.write_text(
        json.dumps({"binary": {"BENIGN": 0, "ATTACK": 1}}), encoding="utf-8"
    )
    return {
        "model_path": artifacts / "model.joblib",
        "preprocessor_path": artifacts / "preprocessor.joblib",
        "features_path": features_json,
        "mapping_path": mapping,
    }


def test_attack_flows_produce_simulated_dry_run_responses(benign_pcap, attack_detector):
    summary = analyze_pcap(
        benign_pcap,
        features_path=attack_detector["features_path"],
        detector_kwargs=attack_detector,
    )
    assert summary["compatibility"]["complete"] is True
    assert summary["detections"] == summary["flows"] == 2  # all predicted ATTACK
    assert summary["simulated_responses"] == 2
    assert summary["response_mode"] == "DRY_RUN"

    responses = summary["response_results"]
    assert responses is not None
    from src.response.actions import ACTION_DRY_RUN_BLOCK, STATUS_SIMULATED

    for response in responses:
        assert response.action == ACTION_DRY_RUN_BLOCK
        assert response.status == STATUS_SIMULATED  # simulated only — no real block
        assert response.mode == "DRY_RUN"
        assert "no firewall/network change" in response.reason.lower() or "simulated" in response.reason.lower()
    frame = summary["frame"]
    assert set(frame["response_status"]) == {STATUS_SIMULATED}
    assert set(frame["response_mode"]) == {"DRY_RUN"}


def test_pcap_store_persists_response_fields(tmp_path, benign_pcap, attack_detector, capsys):
    db_path = tmp_path / "pcap_responses.db"
    out = tmp_path / "pcap_flows.csv"
    code = main(
        [
            "--input", str(benign_pcap),
            "--output", str(out),
            "--store",
            "--db-path", str(db_path),
            "--model", str(attack_detector["model_path"]),
            "--preprocessor", str(attack_detector["preprocessor_path"]),
            "--features", str(attack_detector["features_path"]),
            "--mapping", str(attack_detector["mapping_path"]),
            "--report-dir", str(tmp_path),
        ]
    )
    assert code == 0
    captured = capsys.readouterr().out
    assert "MODE: OFFLINE" in captured
    assert "RESPONSE MODE: DRY_RUN" in captured
    assert "Records stored in SQLite: 2" in captured

    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT response_action, response_mode, response_status FROM detection_events"
        ).fetchall()
        assert len(rows) == 2
        for action, mode, status in rows:
            assert action == "DRY_RUN_BLOCK"
            assert mode == "DRY_RUN"
            assert status == "SIMULATED"  # never AUTHORIZED in DRY_RUN
    finally:
        conn.close()

    from database.repository import Repository

    stats = Repository(db_path).get_response_statistics()
    assert stats["dry_run_block_count"] == stats["simulated_count"] == 2
    assert stats["block_requested_count"] == stats["authorized_count"] == 0
    assert stats["failed_response_count"] == 0

    frame = pd.read_csv(out)
    for column in ("response_action", "response_mode", "response_status", "response_reason"):
        assert column in frame.columns


def test_analyze_invalid_pcap(tmp_path, full_features_json):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap")
    from src.network.pcap_reader import PcapInputError

    with pytest.raises(PcapInputError):
        analyze_pcap(bad, features_path=full_features_json)


def test_write_feature_compatibility(tmp_path, full_features_json):
    from src.network.pcap_pipeline import load_required_features
    from src.network.feature_extractor import compatibility

    comp = compatibility(load_required_features(full_features_json))
    path = write_feature_compatibility(comp, tmp_path / "report.md")
    text = path.read_text(encoding="utf-8")
    assert "INCOMPLETE" in text
    assert "Fwd_IAT_Mean" in text


# --- CLI -----------------------------------------------------------------------

def test_cli_incomplete_branch(benign_pcap, full_features_json, tmp_path, capsys):
    out = tmp_path / "flows.csv"
    code = main(
        [
            "--input", str(benign_pcap),
            "--output", str(out),
            "--features", str(full_features_json),
            "--report-dir", str(tmp_path),
        ]
    )
    assert code == 0
    captured = capsys.readouterr().out
    assert "Packets processed        : 6" in captured
    assert "Flows extracted          : 2" in captured
    assert "INCOMPLETE" in captured
    assert out.exists()
    frame = pd.read_csv(out)
    assert len(frame) == 2
    assert (tmp_path / "pcap_feature_compatibility.md").exists()


def test_cli_missing_input_exits_1(capsys):
    code = main(["--input", "F:/does/not/exist.pcap"])
    assert code == 1
    assert "not found" in capsys.readouterr().out


def test_cli_compatible_with_store(benign_pcap, compatible_detector, tmp_path, capsys):
    db_path = tmp_path / "store.db"
    out = tmp_path / "flows.csv"
    code = main(
        [
            "--input", str(benign_pcap),
            "--output", str(out),
            "--store",
            "--db-path", str(db_path),
            "--model", str(compatible_detector["model_path"]),
            "--preprocessor", str(compatible_detector["preprocessor_path"]),
            "--features", str(compatible_detector["features_path"]),
            "--mapping", str(compatible_detector["mapping_path"]),
            "--report-dir", str(tmp_path),
        ]
    )
    assert code == 0
    captured = capsys.readouterr().out
    assert "Records stored in SQLite: 2" in captured
    conn = sqlite3.connect(str(db_path))
    try:
        assert conn.execute("SELECT COUNT(*) FROM detection_events").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM models").fetchone()[0] == 1
    finally:
        conn.close()
