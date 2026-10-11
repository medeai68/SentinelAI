"""
SentinelAI — Threat Detection Engine (Part 7).

Defensive detection over authorized network-flow data:

    Flow -> Feature validation -> Fitted preprocessing artifact
    -> Optimized ML model -> Prediction -> Probability -> Severity
    -> Structured DetectionResult

Strict rules enforced here:

  * The engine NEVER fits anything at detection time — the Part 4
    preprocessing artifact is loaded and only .transform()ed, and the
    optimized Part 6 model is only .predict()ed (no retraining, no
    refitting, no leakage).
  * Input CSV content is treated strictly as data — it is never
    executed, evaluated, or imported.
  * Invalid input rows are never silently dropped: they become
    DetectionResult objects with an error status.
  * No fabricated values: fields the model cannot produce (e.g.
    probabilities for models without predict_proba) are None.

Run from the project root:

    python -m src.detection.detector --input <authorized_csv> [--output <path>]
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

import joblib
import pandas as pd

from config import detection_config as dcfg
from src.data.dataset_loader import DatasetLoaderError, load_csv, validate_file_exists
from src.detection.feature_validator import FeatureValidationError, validate_features
from src.detection.result_formatter import (
    detection_statistics,
    format_detection_result,
    results_to_frame,
)
from src.detection.schemas import DetectionResult, make_error_result
from src.training.model_utils import ModelArtifactError, load_model, load_model_metadata
from src.utils.logger import get_logger, setup_logging

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_PREPROCESSOR_PATH = PROJECT_ROOT / "models" / "preprocessing" / "preprocessor.joblib"
DEFAULT_FEATURES_PATH = PROJECT_ROOT / "models" / "preprocessing" / "feature_columns.json"
DEFAULT_MAPPING_PATH = PROJECT_ROOT / "reports" / "label_mapping.json"

logger = get_logger("sentinelai.detection")


class ThreatDetector:
    """Loads the detection artifacts once and predicts over flow data.

    Example:

        detector = ThreatDetector.from_artifacts(
            model_path="models/xgboost_optimized.joblib")
        result = detector.predict(flow_dict)
        results = detector.predict_batch(flow_dataframe)
    """

    def __init__(
        self,
        *,
        model_path: str | Path,
        preprocessor_path: str | Path = DEFAULT_PREPROCESSOR_PATH,
        features_path: str | Path = DEFAULT_FEATURES_PATH,
        mapping_path: str | Path = DEFAULT_MAPPING_PATH,
    ):
        self.model_path = Path(model_path)
        self.preprocessor_path = Path(preprocessor_path)
        self.features_path = Path(features_path)
        self.mapping_path = Path(mapping_path)

        self.model = None
        self.preprocessor = None
        self.feature_cols: list[str] = []
        self.label_map: dict[int, str] = {}
        self.model_name: str | None = None
        self.model_version: str | None = None
        self._loaded = False

    # ---------------------------------------------------------
    #  Artifact loading (once per engine instance)
    # ---------------------------------------------------------

    @classmethod
    def from_artifacts(
        cls,
        *,
        model_path: str | Path,
        preprocessor_path: str | Path = DEFAULT_PREPROCESSOR_PATH,
        features_path: str | Path = DEFAULT_FEATURES_PATH,
        mapping_path: str | Path = DEFAULT_MAPPING_PATH,
    ) -> "ThreatDetector":
        """Create a detector and load all artifacts immediately."""
        detector = cls(
            model_path=model_path,
            preprocessor_path=preprocessor_path,
            features_path=features_path,
            mapping_path=mapping_path,
        )
        detector.load_artifacts()
        return detector

    def load_artifacts(self) -> None:
        """Load model, preprocessor, feature list and label mapping (once)."""
        # feature list
        if not self.features_path.exists():
            raise ModelArtifactError(
                f"Feature metadata not found: {self.features_path}. "
                "Run 'python -m src.preprocessing.pipeline' first "
                "(it requires the dataset in data/raw/ — see DEVELOPMENT.md)."
            )
        self.feature_cols = json.loads(self.features_path.read_text(encoding="utf-8"))[
            "feature_columns"
        ]
        logger.info("Loaded feature metadata (%d features) from %s", len(self.feature_cols), self.features_path)

        # preprocessing artifact (transform-only at detection time)
        if not self.preprocessor_path.exists():
            raise ModelArtifactError(
                f"Preprocessing artifact not found: {self.preprocessor_path}. "
                "Run 'python -m src.preprocessing.pipeline' first."
            )
        try:
            self.preprocessor = joblib.load(self.preprocessor_path)
        except Exception as exc:
            raise ModelArtifactError(
                f"Failed to load preprocessing artifact {self.preprocessor_path}: {exc}"
            ) from exc
        logger.info("Loaded preprocessing artifact from %s", self.preprocessor_path)

        # Authoritative input schema: the raw feature names the FITTED
        # preprocessor consumes. (feature_columns.json stores the processed
        # output names, e.g. "numeric__Flow_Duration", which the loaders use;
        # the detector must validate against the preprocessor's INPUT names.)
        if hasattr(self.preprocessor, "feature_names_in_"):
            self.feature_cols = list(self.preprocessor.feature_names_in_)
            logger.info("Using preprocessor input schema (%d features)", len(self.feature_cols))

        # optimized model + metadata
        self.model = load_model(self.model_path)
        metadata = load_model_metadata(self.model_path)
        self.model_name = metadata.get("model_name") or self.model_path.stem
        self.model_version = metadata.get("created") or "unknown"
        logger.info("Loaded model %s (version %s) from %s",
                    self.model_name, self.model_version, self.model_path)

        # label mapping (actual Part 4 artifact; documented fallback only)
        self.label_map = self._load_label_map()

        self._loaded = True

    def _load_label_map(self) -> dict[int, str]:
        if self.mapping_path.exists():
            payload = json.loads(self.mapping_path.read_text(encoding="utf-8"))
            binary = payload.get("binary", {})
            if binary:
                logger.info("Loaded label mapping from %s", self.mapping_path)
                return {int(v): k for k, v in binary.items()}
        logger.warning(
            "Label mapping not found at %s — using the documented fallback "
            "(0 -> %s, 1 -> %s).", self.mapping_path, dcfg.BENIGN_LABEL, dcfg.ATTACK_LABEL
        )
        return {0: dcfg.BENIGN_LABEL, 1: dcfg.ATTACK_LABEL}

    # ---------------------------------------------------------
    #  Prediction
    # ---------------------------------------------------------

    def predict(self, record: dict | pd.Series) -> DetectionResult:
        """Predict one network flow given as a dict or Series."""
        timestamp = datetime.datetime.now().isoformat(timespec="seconds")
        try:
            frame = pd.DataFrame([record])
        except Exception as exc:
            return make_error_result(
                timestamp=timestamp, flow_id=None, status="validation_error",
                errors=[f"Could not interpret input record: {exc}"],
                model_name=self.model_name, model_version=self.model_version,
                feature_count=len(self.feature_cols),
            )
        results = self.predict_batch(frame, timestamp=timestamp)
        return results[0]

    def predict_batch(
        self, df: pd.DataFrame, timestamp: str | None = None
    ) -> list[DetectionResult]:
        """Predict every row; one DetectionResult per input row.

        Invalid rows are never silently dropped — frame-level validation
        failures produce error results for every row, with the reason.
        """
        if not self._loaded:
            raise RuntimeError("Artifacts are not loaded — call load_artifacts() first.")
        if df is None:
            df = pd.DataFrame()
        if timestamp is None:
            timestamp = datetime.datetime.now().isoformat(timespec="seconds")

        # row identity: preserve input flow_id, or generate deterministic ids
        if "flow_id" in df.columns:
            flow_ids = [str(v) for v in df["flow_id"]]
            feature_frame = df.drop(columns=["flow_id"])
        else:
            flow_ids = [f"row_{i}" for i in range(len(df))]  # deterministic, documented
            feature_frame = df

        def error_results(status: str, errors: list[str]) -> list[DetectionResult]:
            return [
                make_error_result(
                    timestamp=timestamp, flow_id=fid, status=status, errors=errors,
                    model_name=self.model_name, model_version=self.model_version,
                    feature_count=len(self.feature_cols),
                )
                for fid in flow_ids
            ]

        try:
            prepared, warnings = validate_features(feature_frame, self.feature_cols)
        except FeatureValidationError as exc:
            logger.warning("Input validation failed: %s", exc)
            return error_results("validation_error", [str(exc)])
        for warning in warnings:
            logger.warning("Input note: %s", warning)

        try:
            transformed = self.preprocessor.transform(prepared)  # transform only — never fit
            X = pd.DataFrame(
                transformed,
                columns=self.preprocessor.get_feature_names_out(),
            )
        except Exception as exc:
            logger.error("Preprocessing transform failed: %s", exc)
            return error_results("prediction_error", [f"Preprocessing failed: {exc}"])

        try:
            predictions = self.model.predict(X)
        except Exception as exc:
            logger.error("Model prediction failed: %s", exc)
            return error_results("prediction_error", [f"Model prediction failed: {exc}"])

        attack_probabilities = None
        if hasattr(self.model, "predict_proba"):
            try:
                attack_probabilities = self.model.predict_proba(X)[:, 1]
            except Exception as exc:
                logger.warning(
                    "predict_proba failed (%s) — probabilities set to None.", exc
                )

        results = []
        for i, fid in enumerate(flow_ids):
            proba = (
                float(attack_probabilities[i])
                if attack_probabilities is not None
                else None
            )
            results.append(
                format_detection_result(
                    timestamp=timestamp,
                    flow_id=fid,
                    prediction=int(predictions[i]),
                    attack_probability=proba,
                    label_map=self.label_map,
                    model_name=self.model_name,
                    model_version=self.model_version,
                    feature_count=len(self.feature_cols),
                )
            )
        logger.info("Batch prediction finished: %d record(s)", len(results))
        return results


# ---------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------

def _resolve_default_model() -> Path | None:
    if not dcfg.DEFAULT_MODEL_FILE:
        return None
    candidate = PROJECT_ROOT / "models" / dcfg.DEFAULT_MODEL_FILE
    return candidate if candidate.exists() else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "SentinelAI threat detection engine (Part 7) — analyze an authorized "
            "network-flow CSV with the optimized model."
        )
    )
    parser.add_argument("--input", required=True, help="Path to an authorized CSV of network-flow features.")
    parser.add_argument("--output", default=None, help="Optional path to save the detection results CSV.")
    parser.add_argument("--model", default=None, help="Override the optimized model path (default: config/detection_config.py).")
    parser.add_argument("--preprocessor", default=None, help="Override the preprocessing artifact path.")
    parser.add_argument("--features", default=None, help="Override the feature-columns metadata path.")
    parser.add_argument("--mapping", default=None, help="Override the label-mapping path.")
    args = parser.parse_args(argv)

    setup_logging()
    logger.info("Starting detection run")

    # safe input handling: path validation first, then plain data parsing
    try:
        input_path = validate_file_exists(args.input)
    except DatasetLoaderError as exc:
        print(f"ERROR: {exc}")
        return 1
    if input_path.suffix.lower() != ".csv":
        print("ERROR: input must be a .csv file.")
        return 1
    try:
        data = load_csv(input_path)  # CSV parsed as data only — never executed
    except DatasetLoaderError as exc:
        print(f"ERROR: {exc}")
        return 1

    model_path = Path(args.model) if args.model else _resolve_default_model()
    if model_path is None:
        print(
            "ERROR: no optimized model is available. After the Part 6 experiment "
            "has run (python -m src.training.model_comparison), set "
            "DEFAULT_MODEL_FILE in config/detection_config.py or pass --model <path>."
        )
        return 1

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

    results = detector.predict_batch(data)
    frame = results_to_frame(results)
    stats = detection_statistics(results)

    print(f"Detection finished: {stats['total_flows']} flow(s) analyzed.")
    print(
        f"  benign={stats['benign_count']} attack={stats['attack_count']} "
        f"({stats['attack_percentage']}%) | severity: low={stats['low_severity_count']} "
        f"medium={stats['medium_severity_count']} high={stats['high_severity_count']} | "
        f"validation errors={stats['validation_error_count']}"
    )

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        frame.to_csv(output_path, index=False)
        print(f"Results saved to: {output_path}")
    else:
        print(frame.to_string(index=False))

    logger.info("Detection run finished (%d records)", stats["total_flows"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
