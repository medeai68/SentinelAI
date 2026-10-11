"""SentinelAI — flow feature extraction (Part 10).

Only features that can be computed RELIABLY from raw packets are
extracted. The CIC-IDS2017 model expects ~78 CICFlowMeter features;
most of them (inter-arrival-time statistics, TCP flag counts, subflow
statistics, ...) require the full CICFlowMeter implementation and are
deliberately NOT approximated here — fabricating them would corrupt
the model input.

The extractable subset uses the exact CIC-IDS2017 column names, so
compatibility is checked by name against the saved feature list
(models/preprocessing/feature_columns.json).
"""

from __future__ import annotations

import pandas as pd

from src.network.flow_extractor import FlowRecord

# Features this module can compute reliably, under their exact
# CIC-IDS2017 column names.
EXTRACTABLE_FEATURES = {
    "Flow_Duration",
    "Total_Fwd_Packets",
    "Total_Backward_Packets",
    "Total_Length_of_Fwd_Packets",
    "Total_Length_of_Bwd_Packets",
    "Flow_Bytes/s",
    "Flow_Packets/s",
    "Source_Port",
    "Destination_Port",
    "Protocol",
    "Packet_Length_Mean",
    "Packet_Length_Variance",
    "Average_Packet_Size",
}


def flow_features(record: FlowRecord) -> dict:
    """Compute the extractable features for one flow (actual values only)."""
    duration_s = record.duration
    packet_count = record.packet_count
    byte_count = record.byte_count
    if packet_count:
        mean = record.length_sum / packet_count
        variance = max(0.0, record.length_sq_sum / packet_count - mean * mean)
    else:
        mean = 0.0
        variance = 0.0
    return {
        # microseconds, as in CIC-IDS2017
        "Flow_Duration": duration_s * 1_000_000,
        "Total_Fwd_Packets": float(record.fwd_packets),
        "Total_Backward_Packets": float(record.bwd_packets),
        "Total_Length_of_Fwd_Packets": float(record.fwd_bytes),
        "Total_Length_of_Bwd_Packets": float(record.bwd_bytes),
        # guarded divisions: a zero-duration flow gets 0.0 (documented)
        "Flow_Bytes/s": float(byte_count / duration_s) if duration_s > 0 else 0.0,
        "Flow_Packets/s": float(packet_count / duration_s) if duration_s > 0 else 0.0,
        "Source_Port": float(record.sport) if record.sport is not None else 0.0,
        "Destination_Port": float(record.dport) if record.dport is not None else 0.0,
        "Protocol": float(record.protocol),
        "Packet_Length_Mean": float(mean),
        "Packet_Length_Variance": float(variance),
        "Average_Packet_Size": float(byte_count / packet_count) if packet_count else 0.0,
    }


def features_frame(records: list[FlowRecord]) -> pd.DataFrame:
    """One row per flow: flow metadata + the extractable feature values."""
    rows = []
    for i, record in enumerate(records):
        row = {
            "flow_id": record.to_flow_id(i),
            "src": record.src,
            "dst": record.dst,
            "src_port": record.sport,
            "dst_port": record.dport,
            "protocol": record.protocol,
            "packet_count": record.packet_count,
            "byte_count": record.byte_count,
            "duration": record.duration,
        }
        row.update(flow_features(record))
        rows.append(row)
    return pd.DataFrame(rows)


def compatibility(required_features: list[str] | None) -> dict:
    """Compare the model's required features with the extractable subset.

    Returns a dict with `complete` (bool), the required list, the
    extractable list, the missing features, and the extracted features
    the model does not need (unsupported). When the required list is
    unavailable, `complete` is False and the verdict is documented.
    """
    extractable = sorted(EXTRACTABLE_FEATURES)
    if not required_features:
        return {
            "complete": False,
            "required": [],
            "extractable": extractable,
            "missing": ["(model feature list unavailable)"],
            "unsupported": [],
        }
    missing = sorted(set(required_features) - EXTRACTABLE_FEATURES)
    unsupported = sorted(EXTRACTABLE_FEATURES - set(required_features))
    return {
        "complete": not missing,
        "required": list(required_features),
        "extractable": extractable,
        "missing": missing,
        "unsupported": unsupported,
    }
