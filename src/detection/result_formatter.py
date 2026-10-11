"""Convert model outputs into structured detection results (Part 7).

Includes the transparent severity rule, batch tabular output and
detection statistics. All values come from actual model outputs.
"""

from __future__ import annotations

import pandas as pd

from config import detection_config as dcfg
from src.detection.schemas import (
    DetectionResult,
    STATUS_SUCCESS,
    STATUS_VALIDATION_ERROR,
)

# Tabular output column order (Step 13 of the Part 7 spec)
OUTPUT_COLUMNS = [
    "timestamp",
    "flow_id",
    "prediction",
    "label",
    "is_attack",
    "attack_probability",
    "severity",
    "model_name",
    "status",
]


def compute_severity(label: str | None, attack_probability: float | None) -> str | None:
    """Transparent, configurable severity rule (experimental defaults).

    BENIGN -> LOW.
    ATTACK -> HIGH when attack_probability >= dcfg.HIGH_ATTACK_PROBABILITY,
              MEDIUM otherwise (including when probability is unavailable).

    HIGH does NOT mean a confirmed real-world compromise — it only means
    the model assigned a high attack probability under this configured
    rule (see config/detection_config.py).
    """
    if label is None:
        return None
    if label == dcfg.BENIGN_LABEL:
        return "LOW"
    if attack_probability is not None and attack_probability >= dcfg.HIGH_ATTACK_PROBABILITY:
        return "HIGH"
    return "MEDIUM"


def format_detection_result(
    *,
    timestamp: str,
    flow_id: str | None,
    prediction: int,
    attack_probability: float | None,
    label_map: dict[int, str],
    model_name: str | None,
    model_version: str | None,
    feature_count: int | None,
) -> DetectionResult:
    """Build a structured success result from actual model outputs.

    `label_map` maps the encoded class (0/1) to a human-readable label
    and is loaded from the Part 4 label mapping artifacts.

    confidence = the model's probability for the PREDICTED class. This
    is the model's own probability output — no calibration is assumed
    and it is not a mathematically independent confidence measure.
    """
    label = label_map.get(prediction, dcfg.ATTACK_LABEL if prediction == 1 else dcfg.BENIGN_LABEL)
    is_attack = prediction == 1
    if attack_probability is None:
        confidence = None
    else:
        confidence = attack_probability if is_attack else 1.0 - attack_probability
    severity = compute_severity(label, attack_probability)
    return DetectionResult(
        timestamp=timestamp,
        flow_id=flow_id,
        prediction=int(prediction),
        label=label,
        is_attack=is_attack,
        attack_probability=attack_probability,
        confidence=confidence,
        severity=severity,
        model_name=model_name,
        model_version=model_version,
        feature_count=feature_count,
        status=STATUS_SUCCESS,
        errors=[],
    )


def results_to_frame(results: list[DetectionResult]) -> pd.DataFrame:
    """Return the standardized tabular output for a batch of results."""
    rows = [{col: r.to_dict()[col] for col in OUTPUT_COLUMNS} for r in results]
    return pd.DataFrame(rows, columns=OUTPUT_COLUMNS)


def detection_statistics(results: list[DetectionResult]) -> dict:
    """Summarize a batch of detection results (actual counts only).

    Nothing is saved here — callers decide whether to persist.
    """
    total = len(results)
    benign = sum(1 for r in results if r.status == STATUS_SUCCESS and r.is_attack is False)
    attack = sum(1 for r in results if r.status == STATUS_SUCCESS and r.is_attack is True)
    high = sum(1 for r in results if r.severity == "HIGH")
    medium = sum(1 for r in results if r.severity == "MEDIUM")
    low = sum(1 for r in results if r.severity == "LOW")
    errors = sum(1 for r in results if r.status in (STATUS_VALIDATION_ERROR, "prediction_error"))
    return {
        "total_flows": total,
        "benign_count": benign,
        "attack_count": attack,
        "attack_percentage": round(attack / total * 100, 2) if total else 0.0,
        "high_severity_count": high,
        "medium_severity_count": medium,
        "low_severity_count": low,
        "validation_error_count": errors,
    }
