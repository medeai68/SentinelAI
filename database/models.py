"""Database record types (Part 8).

Plain containers matching the SQLite schema. The database layer never
redefines the Part 7 detection schema — DetectionRecord is a one-way
mapping FROM a DetectionResult into a storage row.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from src.detection.schemas import DetectionResult


@dataclass
class ModelRecord:
    """One row of the `models` table."""

    name: str
    version: str | None = None
    algorithm: str | None = None
    file_path: str | None = None
    feature_count: int | None = None
    is_active: bool = False
    id: int | None = None
    created_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionRecord:
    """One row of the `detection_events` table."""

    timestamp: str
    status: str
    flow_id: str | None = None
    prediction: int | None = None
    label: str | None = None
    is_attack: bool | None = None
    attack_probability: float | None = None
    severity: str | None = None
    model_id: int | None = None
    id: int | None = None
    created_at: str | None = None
    # Part 7 (response) fields — populated from actual ResponseResults
    response_action: str | None = None
    response_mode: str | None = None
    response_status: str | None = None
    response_reason: str | None = None
    response_timestamp: str | None = None

    @classmethod
    def from_detection_result(
        cls, result: DetectionResult, model_id: int | None
    ) -> "DetectionRecord":
        """Convert a Part 7 DetectionResult into a storage record.

        All values come from the actual detection result — nothing is
        invented or re-encoded. Response fields stay None unless a
        ResponseResult is attached via from_detection_and_response().
        """
        return cls(
            timestamp=result.timestamp,
            flow_id=result.flow_id,
            prediction=result.prediction,
            label=result.label,
            is_attack=result.is_attack,
            attack_probability=result.attack_probability,
            severity=result.severity,
            model_id=model_id,
            status=result.status,
        )

    @classmethod
    def from_detection_and_response(
        cls, detection, response, model_id: int | None
    ) -> "DetectionRecord":
        """Combine an actual DetectionResult with its actual ResponseResult.

        Both objects are duck-typed (their modules are not imported here)
        to keep the database layer free of response logic.
        """
        record = cls.from_detection_result(detection, model_id)
        record.response_action = response.action
        record.response_mode = response.mode
        record.response_status = response.status
        record.response_reason = response.reason
        record.response_timestamp = response.timestamp
        return record

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
