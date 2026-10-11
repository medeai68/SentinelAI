"""Controlled response engine (Part 7).

    DetectionResult -> ResponsePolicy -> ResponseResult
                     -> (DRY_RUN: simulated + logged)
                     -> (AUTHORIZED: only via an explicitly supplied adapter)

Fail-closed guarantees:

  * the default mode is DRY_RUN — nothing is ever blocked;
  * in DRY_RUN, an executor is never called, even if one is provided;
  * AUTHORIZED mode without an explicit adapter refuses to construct;
  * adapter failures are caught, reported as FAILED, and never escalate.

CLI (detect -> respond -> optionally store; DRY_RUN only):

    python -m src.response.response_engine --input <authorized_csv> \
        [--output responses.csv] [--store]
"""

from __future__ import annotations

import argparse
import datetime
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import pandas as pd

from config import detection_config as dcfg
from src.data.dataset_loader import DatasetLoaderError, load_csv, validate_file_exists
from src.detection.schemas import STATUS_SUCCESS, DetectionResult
from src.response.actions import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_REQUESTED,
    ACTION_DRY_RUN_BLOCK,
    ACTION_NO_ACTION,
    DEFAULT_RESPONSE_MODE,
    MODE_AUTHORIZED,
    MODE_DRY_RUN,
    ResponseExecutor,
    STATUS_FAILED,
    STATUS_SKIPPED,
    status_for,
)
from src.response.policies import DEFAULT_POLICY, ResponsePolicy

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class ResponseConfigurationError(Exception):
    """Raised when the engine is configured unsafely (fail closed)."""


@dataclass
class ResponseResult:
    """Structured response outcome for one detection result."""

    timestamp: str
    flow_id: str | None
    prediction: int | None
    attack_probability: float | None
    severity: str | None
    action: str
    mode: str
    status: str
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


class ResponseEngine:
    """Turns DetectionResults into controlled, logged response outcomes."""

    def __init__(
        self,
        policy: ResponsePolicy | None = None,
        executor: ResponseExecutor | None = None,
    ):
        self.policy = policy or DEFAULT_POLICY
        if self.policy.mode == MODE_AUTHORIZED and executor is None:
            raise ResponseConfigurationError(
                "AUTHORIZED mode requires an explicitly supplied, isolated adapter. "
                "No adapter was provided — refusing to run (fail closed). "
                "Use the default DRY_RUN mode, or supply an adapter restricted to a "
                "local, authorized test environment."
            )
        self.executor = executor

    # ---------------------------------------------------------
    #  Response
    # ---------------------------------------------------------

    def respond(self, detection: DetectionResult) -> ResponseResult:
        """Produce the controlled response outcome for one detection."""
        timestamp = datetime.datetime.now().isoformat(timespec="seconds")

        if detection.status != STATUS_SUCCESS or detection.prediction is None:
            return ResponseResult(
                timestamp=timestamp,
                flow_id=detection.flow_id,
                prediction=detection.prediction,
                attack_probability=detection.attack_probability,
                severity=detection.severity,
                action=ACTION_NO_ACTION,
                mode=self.policy.mode,
                status=STATUS_SKIPPED,
                reason=f"detection not successful ({detection.status}) — response not applicable",
            )

        action, reason = self.policy.recommend(detection)
        status = status_for(action)

        # The ONLY path that can touch an adapter: AUTHORIZED + block request.
        if action == ACTION_BLOCK_REQUESTED:
            try:
                self.executor.block(flow_id=detection.flow_id, reason=reason)
            except Exception as exc:  # adapter failure never escalates
                status = STATUS_FAILED
                reason = f"{reason}; adapter failed: {exc}"

        return ResponseResult(
            timestamp=timestamp,
            flow_id=detection.flow_id,
            prediction=detection.prediction,
            attack_probability=detection.attack_probability,
            severity=detection.severity,
            action=action,
            mode=self.policy.mode,
            status=status,
            reason=reason,
        )

    def respond_batch(self, detections: list[DetectionResult]) -> list[ResponseResult]:
        """One ResponseResult per DetectionResult (order preserved)."""
        return [self.respond(detection) for detection in detections]


# ---------------------------------------------------------------
#  Orchestration CLI: detect -> respond -> (optionally store)
# ---------------------------------------------------------------

def _resolve_model_path(model_arg: str | None) -> Path | None:
    if model_arg:
        return Path(model_arg)
    if not dcfg.DEFAULT_MODEL_FILE:
        return None
    candidate = PROJECT_ROOT / "models" / dcfg.DEFAULT_MODEL_FILE
    return candidate if candidate.exists() else None


def _find_label_column(data: pd.DataFrame) -> str | None:
    for col in data.columns:
        if str(col).strip().lower() == "label":
            return col
    return None


def summarize(responses: list[ResponseResult]) -> dict:
    """Actual counts per action/status (zeros for empty input)."""
    return {
        "total": len(responses),
        "no_action": sum(1 for r in responses if r.action == ACTION_NO_ACTION),
        "alerts": sum(1 for r in responses if r.action == ACTION_ALERT_ONLY),
        "dry_run_blocks": sum(1 for r in responses if r.action == ACTION_DRY_RUN_BLOCK),
        "block_requests": sum(1 for r in responses if r.action == ACTION_BLOCK_REQUESTED),
        "skipped": sum(1 for r in responses if r.status == STATUS_SKIPPED),
        "failed": sum(1 for r in responses if r.status == STATUS_FAILED),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "SentinelAI controlled response (Part 7): detect with the optimized model, "
            "apply the response policy, and optionally store the results. DRY_RUN only — "
            "no real firewall/network modification is ever performed."
        )
    )
    parser.add_argument("--input", required=True, help="Authorized CSV of network-flow features.")
    parser.add_argument("--output", default=None, help="Optional CSV path for detections + responses.")
    parser.add_argument("--store", action="store_true", help="Store detections + responses in the SQLite database.")
    parser.add_argument("--db-path", default=None, help="Override the database path (with --store).")
    parser.add_argument("--model", default=None, help="Override the optimized model path (default: config/detection_config.py).")
    parser.add_argument("--preprocessor", default=None)
    parser.add_argument("--features", default=None)
    parser.add_argument("--mapping", default=None)
    parser.add_argument(
        "--mode",
        default=DEFAULT_RESPONSE_MODE,
        choices=[MODE_DRY_RUN, MODE_AUTHORIZED],
        help="Response mode (default DRY_RUN). AUTHORIZED is refused: this build ships no adapter.",
    )
    args = parser.parse_args(argv)

    engine = None
    if args.mode == MODE_AUTHORIZED:
        print(
            "REFUSED: AUTHORIZED mode requires an explicitly supplied, isolated adapter. "
            "This build ships none, so no authorized response can run. Use the default "
            "DRY_RUN mode (no firewall/network change is ever made in this project)."
        )
        return 1

    try:
        input_path = validate_file_exists(args.input)
    except DatasetLoaderError as exc:
        print(f"ERROR: {exc}")
        return 1
    if input_path.suffix.lower() != ".csv":
        print("ERROR: input must be a .csv file.")
        return 1
    try:
        data = load_csv(input_path)  # parsed strictly as data — never executed
    except DatasetLoaderError as exc:
        print(f"ERROR: {exc}")
        return 1

    model_path = _resolve_model_path(args.model)
    if model_path is None:
        print(
            "ERROR: no optimized model available. Set DEFAULT_MODEL_FILE in "
            "config/detection_config.py or pass --model <path>."
        )
        return 1

    from src.detection.detector import (
        DEFAULT_FEATURES_PATH,
        DEFAULT_MAPPING_PATH,
        DEFAULT_PREPROCESSOR_PATH,
        ThreatDetector,
    )
    from src.training.model_utils import ModelArtifactError

    try:
        detector = ThreatDetector.from_artifacts(
            model_path=model_path,
            preprocessor_path=Path(args.preprocessor) if args.preprocessor else DEFAULT_PREPROCESSOR_PATH,
            features_path=Path(args.features) if args.features else DEFAULT_FEATURES_PATH,
            mapping_path=Path(args.mapping) if args.mapping else DEFAULT_MAPPING_PATH,
        )
    except ModelArtifactError as exc:
        print(f"ERROR: {exc}")
        return 1

    label_col = _find_label_column(data)
    actual_labels = data[label_col].astype(str).tolist() if label_col else None
    feature_data = data.drop(columns=[label_col]) if label_col else data

    detections = detector.predict_batch(feature_data)
    engine = ResponseEngine()  # default: DRY_RUN, Part 6-validated thresholds
    responses = engine.respond_batch(detections)

    # combined output frame (detection + response, actual label kept separate)
    rows = []
    for i, (detection, response) in enumerate(zip(detections, responses)):
        row = detection.to_dict()
        row.update(
            {
                "response_action": response.action,
                "response_mode": response.mode,
                "response_status": response.status,
                "response_reason": response.reason,
                "response_timestamp": response.timestamp,
            }
        )
        if actual_labels is not None:
            row["actual_label"] = actual_labels[i]
        rows.append(row)
    frame = pd.DataFrame(rows)

    stats = summarize(responses)
    print(f"Detection + response finished: {stats['total']} flow(s)")
    print(
        f"  no_action={stats['no_action']} alerts={stats['alerts']} "
        f"dry_run_blocks={stats['dry_run_blocks']} block_requests={stats['block_requests']} "
        f"skipped={stats['skipped']} failed={stats['failed']}"
    )
    print(f"  response mode: {DEFAULT_RESPONSE_MODE} (no real firewall/network change)")
    if actual_labels is not None:
        predicted = frame["prediction"].tolist()
        actual_binary = [0 if str(v).strip().upper() == "BENIGN" else 1 for v in actual_labels]
        correct = sum(1 for p, a in zip(predicted, actual_binary) if p == a)
        print(f"  vs actual labels: {correct}/{len(rows)} predictions match the dataset labels")

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        frame.to_csv(out, index=False)
        print(f"Results saved to: {out}")

    if args.store:
        from database.connection import get_database_path, initialize_database
        from database.models import DetectionRecord, ModelRecord
        from database.repository import Repository

        db = Path(args.db_path) if args.db_path else get_database_path()
        initialize_database(db)  # idempotent; safely migrates new response columns
        repo = Repository(db)
        model_id = repo.insert_model(
            ModelRecord(
                name=detector.model_name or model_path.stem,
                version=detector.model_version,
                file_path=str(detector.model_path),
                feature_count=len(detector.feature_cols),
                is_active=True,
            )
        )
        records = [
            DetectionRecord.from_detection_and_response(d, r, model_id)
            for d, r in zip(detections, responses)
        ]
        stored = repo.insert_detections(records)
        print(f"Stored {stored} detection+response record(s) in: {db}")
        print(f"  database response statistics: {repo.get_response_statistics()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
