"""Structured detection result definitions (Part 7).

DetectionResult is the single output format of the detection engine,
reused later by the dashboard and other consumers. All field values
come from actual model outputs or documented metadata — nothing is
invented. Fields that cannot be produced (e.g. attack_probability for
a model without predict_proba) are None, with the reason documented.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# status values
STATUS_SUCCESS = "success"
STATUS_VALIDATION_ERROR = "validation_error"
STATUS_PREDICTION_ERROR = "prediction_error"


@dataclass
class DetectionResult:
    """One structured detection result for one network flow."""

    timestamp: str                # ISO timestamp of the detection run
    flow_id: str | None           # input row identity, or a deterministic generated id
    prediction: int | None        # 0 = BENIGN, 1 = ATTACK (binary encoding)
    label: str | None             # human-readable label ("BENIGN" / "ATTACK")
    is_attack: bool | None        # True when prediction == 1
    attack_probability: float | None  # P(ATTACK) from predict_proba, None if unavailable
    confidence: float | None      # model probability for the PREDICTED class
                                  # (documented: model output, no calibration assumed)
    severity: str | None          # LOW / MEDIUM / HIGH per the configurable rule
    model_name: str | None
    model_version: str | None     # metadata "created" timestamp, "unknown" if absent
    feature_count: int | None
    status: str                   # success | validation_error | prediction_error
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return the result as a plain dict (JSON-friendly)."""
        return asdict(self)


def make_error_result(
    *,
    timestamp: str,
    flow_id: str | None,
    status: str,
    errors: list[str],
    model_name: str | None = None,
    model_version: str | None = None,
    feature_count: int | None = None,
) -> DetectionResult:
    """Build a structured error result for an invalid input row.

    Invalid rows are never silently dropped — they become
    DetectionResult objects with an error status and a clear message.
    """
    return DetectionResult(
        timestamp=timestamp,
        flow_id=flow_id,
        prediction=None,
        label=None,
        is_attack=None,
        attack_probability=None,
        confidence=None,
        severity=None,
        model_name=model_name,
        model_version=model_version,
        feature_count=feature_count,
        status=status,
        errors=list(errors),
    )
