"""Tests for Part 10 flow feature extraction and compatibility checks."""

import pandas as pd

from src.network.feature_extractor import (
    EXTRACTABLE_FEATURES,
    compatibility,
    features_frame,
    flow_features,
)
from src.network.flow_extractor import FlowRecord


def _record(**overrides):
    base = dict(
        src="192.168.0.1",
        dst="10.0.0.1",
        sport=12345,
        dport=80,
        protocol=6,
        first_seen=1000.0,
        last_seen=1002.0,
        fwd_packets=2,
        bwd_packets=2,
        fwd_bytes=200,
        bwd_bytes=200,
        length_sum=400,
        length_sq_sum=40000,
    )
    base.update(overrides)
    return FlowRecord(**base)


def test_flow_features_hand_computed():
    features = flow_features(_record())
    assert features["Flow_Duration"] == 2_000_000  # microseconds
    assert features["Total_Fwd_Packets"] == 2.0
    assert features["Total_Backward_Packets"] == 2.0
    assert features["Total_Length_of_Fwd_Packets"] == 200.0
    assert features["Total_Length_of_Bwd_Packets"] == 200.0
    assert features["Flow_Bytes/s"] == 200.0   # 400 bytes / 2 s
    assert features["Flow_Packets/s"] == 2.0   # 4 packets / 2 s
    assert features["Source_Port"] == 12345.0
    assert features["Destination_Port"] == 80.0
    assert features["Protocol"] == 6.0
    assert features["Packet_Length_Mean"] == 100.0
    assert features["Packet_Length_Variance"] == 0.0
    assert features["Average_Packet_Size"] == 100.0


def test_flow_features_zero_duration_guards():
    features = flow_features(_record(first_seen=1000.0, last_seen=1000.0))
    assert features["Flow_Bytes/s"] == 0.0
    assert features["Flow_Packets/s"] == 0.0


def test_features_frame_columns():
    frame = features_frame([_record(), _record(src="172.16.0.1", dst="10.0.0.2", sport=53, dport=53, protocol=17)])
    assert len(frame) == 2
    for col in ("flow_id", "src", "dst", "src_port", "dst_port", "protocol",
                "packet_count", "byte_count", "duration"):
        assert col in frame.columns
    for feature in EXTRACTABLE_FEATURES:
        assert feature in frame.columns
    assert frame.iloc[0]["flow_id"] == "flow_000000"


def test_compatibility_incomplete_with_extra_required():
    comp = compatibility(["Flow_Duration", "Fwd_IAT_Mean", "Bwd_Packet_Length_Std"])
    assert comp["complete"] is False
    assert "Flow_Duration" not in comp["missing"]
    assert {"Fwd_IAT_Mean", "Bwd_Packet_Length_Std"} <= set(comp["missing"])


def test_compatibility_complete_when_required_is_subset():
    required = sorted(EXTRACTABLE_FEATURES)[:5]
    comp = compatibility(required)
    assert comp["complete"] is True
    assert comp["missing"] == []
    assert set(comp["unsupported"]) == EXTRACTABLE_FEATURES - set(required)


def test_compatibility_none_required():
    comp = compatibility(None)
    assert comp["complete"] is False
    assert comp["required"] == []
    assert "unavailable" in comp["missing"][0]


def test_compatibility_wrong_feature_count_is_incomplete():
    # a 70-name schema where only the 13 extractable names exist -> incomplete
    required = sorted(EXTRACTABLE_FEATURES) + [f"Fake_Feature_{i}" for i in range(57)]
    comp = compatibility(required)
    assert comp["complete"] is False
    assert len(comp["missing"]) == 57


def test_empty_flow_features_are_guarded():
    """A flow record with zero packets must not divide by zero."""
    empty = FlowRecord(
        src="10.0.0.1", dst="10.0.0.2", sport=None, dport=None, protocol=1,
        first_seen=1000.0, last_seen=1000.0,
    )
    features = flow_features(empty)
    assert features["Flow_Duration"] == 0.0
    assert features["Flow_Bytes/s"] == 0.0
    assert features["Flow_Packets/s"] == 0.0
    assert features["Packet_Length_Mean"] == 0.0
    assert features["Average_Packet_Size"] == 0.0
    assert features["Total_Fwd_Packets"] == 0.0
