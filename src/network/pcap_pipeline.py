"""SentinelAI — authorized PCAP analysis pipeline (Part 10).

    Authorized PCAP -> Packet parser -> Flow extraction
    -> Feature extraction -> Feature validation -> Detection engine
    -> Detection results -> Optional SQLite storage

Run from the project root:

    python -m src.network.pcap_pipeline --input <authorized.pcap> [--output <csv>] [--store]

Honesty rule: the CIC-IDS2017 model requires ~78 CICFlowMeter features;
only a documented subset can be computed reliably from raw packets.
When the required set is not fully extractable, predictions are NOT
forced — flows are reported with status "feature set incomplete" and a
compatibility report is written (reports/pcap_feature_compatibility.md).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from database.models import ModelRecord
from database.repository import Repository
from src.network.feature_extractor import compatibility, features_frame
from src.network.flow_extractor import extract_flows
from src.network.pcap_reader import PcapInputError, read_packets
from src.response.actions import DEFAULT_RESPONSE_MODE, STATUS_SIMULATED
from src.response.response_engine import ResponseEngine, summarize

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
DEFAULT_FEATURES_PATH = PROJECT_ROOT / "models" / "preprocessing" / "feature_columns.json"

STATUS_INCOMPLETE = "feature set incomplete"
STATUS_SUCCESS = "success"
STATUS_ERROR = "prediction_error"


def _model_feature_count(model_path) -> int | None:
    """Feature count recorded in the model's metadata, or None."""
    try:
        from src.training.model_utils import load_model_metadata

        metadata = load_model_metadata(model_path)
        return int(metadata.get("feature_count"))
    except Exception:
        return None


def load_required_features(features_path: Path = DEFAULT_FEATURES_PATH) -> list[str] | None:
    """Load the model's required RAW feature list, or None when unavailable.

    Prefers "input_feature_columns" (the raw names the fitted preprocessor
    consumes); falls back to "feature_columns" (the processed output names)
    for artifacts written by earlier versions of the Part 4 pipeline.
    """
    if not features_path.exists():
        return None
    payload = json.loads(features_path.read_text(encoding="utf-8"))
    return payload.get("input_feature_columns") or payload.get("feature_columns")


def analyze_pcap(
    path,
    *,
    max_bytes: int | None = None,
    features_path: Path = DEFAULT_FEATURES_PATH,
    detector_kwargs: dict | None = None,
) -> dict:
    """Parse an authorized PCAP, extract flows and features, and — only
    when the feature set is fully compatible with the optimized model —
    run the Part 7 detector followed by the Part 7 response engine.

    Result contract (all counts are actual; a flow is only reported as
    'analyzed' when the model actually produced a prediction for it):

        packets            packets processed
        flows              flows extracted
        compatible_flows   flows whose feature schema matched the model
        incompatible_flows flows rejected for missing/unsupported features
        analyzed           flows with an actual model prediction
        errors             flows that failed validation/prediction
        detections         flows predicted as ATTACK (when executed)
        simulated_responses    DRY_RUN_BLOCK responses (simulated only)
        response_results   ResponseResult list (or None)
        response_mode      DRY_RUN
        compatibility, frame, detection_results, detector
    """
    packet_count = 0

    def packet_stream():
        nonlocal packet_count
        packets = read_packets(path) if max_bytes is None else read_packets(path, max_bytes=max_bytes)
        for packet in packets:
            packet_count += 1
            yield packet

    flows = extract_flows(packet_stream())
    frame = features_frame(flows)

    required = load_required_features(features_path)
    comp = compatibility(required)

    # model-metadata cross-check (feature count must agree with the artifact)
    if detector_kwargs and required:
        metadata_count = _model_feature_count(detector_kwargs.get("model_path"))
        comp["model_feature_count"] = metadata_count
        if metadata_count is not None and metadata_count != len(required):
            comp["complete"] = False
            comp["missing"] = list(comp["missing"]) + [
                f"(model metadata expects {metadata_count} features but the saved "
                f"artifact list has {len(required)})"
            ]

    # detection + response columns (None until predictions actually run)
    frame["status"] = STATUS_INCOMPLETE
    frame["predicted_label"] = None
    frame["attack_probability"] = None
    frame["severity"] = None
    frame["response_action"] = None
    frame["response_mode"] = None
    frame["response_status"] = None
    frame["response_reason"] = None

    results = None
    response_results = None
    analyzed = 0
    errors = 0
    detections = 0
    simulated_responses = 0
    detector = None

    if comp["complete"] and detector_kwargs:
        from src.detection.detector import ThreatDetector

        try:
            detector = ThreatDetector.from_artifacts(**detector_kwargs)
            feature_frame = frame[comp["required"]].copy()
            feature_frame.insert(0, "flow_id", frame["flow_id"])
            results = detector.predict_batch(feature_frame)
            if len(results) == len(frame):
                frame["predicted_label"] = [r.label for r in results]
                frame["attack_probability"] = [r.attack_probability for r in results]
                frame["severity"] = [r.severity for r in results]
                frame["status"] = [
                    r.status if r.status == STATUS_SUCCESS else STATUS_ERROR for r in results
                ]
                analyzed = int(sum(1 for r in results if r.status == STATUS_SUCCESS))
                errors = len(results) - analyzed
                detections = int(sum(1 for r in results if r.is_attack is True))

                # Part 7 response engine (reused — DRY_RUN default, simulated only)
                response_results = ResponseEngine().respond_batch(results)
                frame["response_action"] = [r.action for r in response_results]
                frame["response_mode"] = [r.mode for r in response_results]
                frame["response_status"] = [r.status for r in response_results]
                frame["response_reason"] = [r.reason for r in response_results]
                simulated_responses = int(
                    sum(1 for r in response_results if r.status == STATUS_SIMULATED)
                )
            else:
                frame["status"] = STATUS_ERROR
                errors = len(frame)
        except Exception as exc:  # artifact problems -> documented error status
            frame["status"] = STATUS_ERROR
            frame["predicted_label"] = [f"error: {exc}"] * len(frame)
            errors = len(frame)
    elif comp["complete"] and not detector_kwargs:
        # features are compatible but no model artifacts were provided
        errors = 0

    compatible_flows = len(flows) if comp["complete"] else 0
    incompatible_flows = len(flows) - compatible_flows if not comp["complete"] else 0

    return {
        "packets": packet_count,
        "flows": len(flows),
        "compatible_flows": compatible_flows,
        "incompatible_flows": incompatible_flows,
        "analyzed": analyzed,
        "rejected": len(flows) - analyzed,
        "errors": errors,
        "detections": detections,
        "simulated_responses": simulated_responses,
        "response_mode": DEFAULT_RESPONSE_MODE,
        "response_results": response_results,
        "compatibility": comp,
        "frame": frame,
        "detection_results": results,
        "detector": detector,
    }


def write_feature_compatibility(comp: dict, path: Path) -> Path:
    """Write the compatibility report with actual values."""
    lines = [
        "# PCAP Feature Compatibility",
        "",
        "Comparison between the features the CIC-IDS2017 model requires and the",
        "features the Part 10 PCAP pipeline can compute reliably from raw packets.",
        "",
        f"- Verdict: **{'COMPATIBLE — predictions possible' if comp['complete'] else 'INCOMPLETE — predictions are NOT forced'}**",
        f"- Model-required features: {len(comp['required'])}",
        f"- PCAP-extractable features: {len(comp['extractable'])}",
        "",
        "## Extractable features (exact CIC-IDS2017 names)",
        "",
        ", ".join(comp["extractable"]) or "none",
        "",
        "## Missing features (cannot be reconstructed reliably from raw packets)",
        "",
    ]
    lines.extend(f"- {name}" for name in comp["missing"])
    lines += [
        "",
        "Most missing features are CICFlowMeter statistics (inter-arrival-time",
        "means/std, TCP flag counts, subflow and idle statistics, ...) that require",
        "the full CICFlowMeter implementation. They are deliberately not",
        "approximated with fake values — fabricating them would corrupt the model",
        "input. Flows are therefore reported with status 'feature set incomplete'.",
        "",
        "## Unsupported extracted features (not needed by the model)",
        "",
        ", ".join(comp["unsupported"]) or "none",
        "",
        "## How to provide an authorized PCAP",
        "",
        "Place a locally captured (authorized) PCAP file anywhere on this machine",
        "and run:",
        "",
        "    python -m src.network.pcap_pipeline --input <authorized.pcap>",
        "",
        "Live capture is intentionally NOT implemented in this phase.",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _store_results(summary: dict, db_path=None) -> tuple[int, str | None]:
    """Store detection + response pairs via the Part 8 repository.

    Returns (stored_count, error_message_or_None). No database logic is
    duplicated here — everything goes through the Repository, and any
    database failure is reported instead of crashing the analysis.
    """
    results = summary.get("detection_results") or []
    responses = summary.get("response_results") or []
    if not results or not responses:
        return 0, None
    detector = summary["detector"]
    try:
        from database.connection import get_database_path, initialize_database
        from database.models import DetectionRecord

        db = Path(db_path) if db_path else get_database_path()
        initialize_database(db)  # idempotent — never drops existing tables
        repo = Repository(db)
        model_id = repo.insert_model(
            ModelRecord(
                name=detector.model_name or "pcap_model",
                version=detector.model_version,
                file_path=str(detector.model_path),
                feature_count=len(detector.feature_cols),
                is_active=True,
            )
        )
        records = [
            DetectionRecord.from_detection_and_response(d, r, model_id)
            for d, r in zip(results, responses)
        ]
        repo.insert_detections(records)
        return len(records), None
    except Exception as exc:  # database problems must not crash the analysis
        return 0, f"{type(exc).__name__}: {exc}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "SentinelAI authorized PCAP analysis (Part 10) — extract flows and "
            "features from a local PCAP and run detection when the feature set "
            "is fully compatible."
        )
    )
    parser.add_argument("--input", required=True, help="Path to an authorized local PCAP file.")
    parser.add_argument("--output", default=None, help="Optional CSV path for the flow results.")
    parser.add_argument("--store", action="store_true", help="Store successful detection results in the Part 8 SQLite database.")
    parser.add_argument("--db-path", default=None, help="Override the database path (with --store).")
    parser.add_argument("--model", default=None, help="Override the optimized model path.")
    parser.add_argument("--preprocessor", default=None, help="Override the preprocessing artifact path.")
    parser.add_argument("--features", default=None, help="Override the feature-columns metadata path.")
    parser.add_argument("--mapping", default=None, help="Override the label-mapping path.")
    parser.add_argument("--max-bytes", type=int, default=None, help="Override the maximum accepted PCAP size in bytes.")
    parser.add_argument("--report-dir", default=None, help="Override the directory for the compatibility report.")
    args = parser.parse_args(argv)

    features_path = Path(args.features) if args.features else DEFAULT_FEATURES_PATH
    detector_kwargs = None
    if args.model:
        from src.detection.detector import DEFAULT_MAPPING_PATH, DEFAULT_PREPROCESSOR_PATH

        detector_kwargs = {
            "model_path": args.model,
            "preprocessor_path": args.preprocessor or DEFAULT_PREPROCESSOR_PATH,
            "features_path": features_path,
            "mapping_path": args.mapping or DEFAULT_MAPPING_PATH,
        }

    try:
        summary = analyze_pcap(
            args.input,
            max_bytes=args.max_bytes,
            features_path=features_path,
            detector_kwargs=detector_kwargs,
        )
    except PcapInputError as exc:
        print(f"ERROR: {exc}")
        return 1

    comp = summary["compatibility"]
    print(f"MODE: OFFLINE            | RESPONSE MODE: {DEFAULT_RESPONSE_MODE} "
          "(analysis of a local file; no live capture, no real blocking)")
    print(f"Packets processed        : {summary['packets']}")
    print(f"Flows extracted          : {summary['flows']}")
    print(f"Flows compatible         : {summary['compatible_flows']}")
    print(f"Flows incompatible (feature schema): {summary['incompatible_flows']}")
    print(f"Flows successfully analyzed: {summary['analyzed']}")
    print(f"Flow errors              : {summary['errors']}")
    if comp["required"]:
        print(f"Feature compatibility    : {'COMPATIBLE' if comp['complete'] else 'INCOMPLETE'} "
              f"({len(comp['missing'])} of {len(comp['required'])} required features missing)")
    else:
        print("Feature compatibility    : INCOMPLETE (model feature list unavailable)")
    if comp.get("model_feature_count") is not None:
        print(f"Model feature count (metadata): {comp['model_feature_count']}")
    labels = summary["frame"]["predicted_label"]
    if labels.notna().any():
        print(f"Detection counts (BENIGN/ATTACK): {labels.value_counts(dropna=False).to_dict()}")
    else:
        print("Detection counts         : none (feature set incomplete - no predictions forced)")
    if summary["response_results"]:
        response_stats = summarize(summary["response_results"])
        print(f"Responses (DRY_RUN simulation): alerts={response_stats['alerts']} "
              f"dry_run_blocks={response_stats['dry_run_blocks']} "
              f"simulated={response_stats['dry_run_blocks']} "
              f"block_requests={response_stats['block_requests']} "
              f"failed={response_stats['failed']}")
    else:
        print("Responses                : none (detection not executed)")

    report_dir = Path(args.report_dir) if args.report_dir else REPORTS_DIR
    report_path = write_feature_compatibility(comp, report_dir / "pcap_feature_compatibility.md")
    print(f"Compatibility report     : {report_path}")

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        summary["frame"].to_csv(out, index=False)
        print(f"Results saved to        : {out}")

    if args.store:
        stored, store_error = _store_results(summary, db_path=args.db_path)
        if store_error:
            print(f"ERROR: could not store results: {store_error}")
            return 1
        print(f"Records stored in SQLite: {stored}")
        if stored == 0:
            print("(nothing to store — no detection results in this run)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
