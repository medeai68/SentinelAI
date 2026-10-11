"""Dashboard data layer (Part 9).

A thin wrapper over the Part 8 Repository plus readers for saved model
reports. No SQL is duplicated here — every database access goes through
Repository methods. This module deliberately does NOT import Streamlit,
so it stays fully unit-testable.

Every value returned is an actual stored/measured value; missing data
yields empty/zero results, never invented numbers.
"""

from __future__ import annotations

import json
import platform
import sqlite3
from pathlib import Path

import pandas as pd

from config import settings
from database.repository import Repository
from src.response.actions import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_REQUESTED,
    ACTION_DRY_RUN_BLOCK,
    ACTION_NO_ACTION,
    DEFAULT_RESPONSE_MODE,
    STATUS_AUTHORIZED,
    STATUS_FAILED,
    STATUS_LOGGED,
    STATUS_NONE,
    STATUS_SIMULATED,
    STATUS_SKIPPED,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
MODELS_DIR = PROJECT_ROOT / "models"
PREPROCESSOR_PATH = MODELS_DIR / "preprocessing" / "preprocessor.joblib"

#: Human-readable meaning per response status (dashboard display).
RESPONSE_STATUS_MEANINGS = {
    STATUS_NONE: "No action was warranted (benign / below threshold)",
    STATUS_LOGGED: "Alert recorded — nothing else performed",
    STATUS_SIMULATED: "Dry-run block simulated — no real change was made",
    STATUS_AUTHORIZED: "Authorized adapter executed (real request)",
    STATUS_FAILED: "Adapter was attempted and failed",
    STATUS_SKIPPED: "Detection not applicable — no response",
    "UNKNOWN": "Legacy row without response information",
}

#: Ordered action labels for the response monitoring section.
RESPONSE_ACTION_LABELS = {
    ACTION_NO_ACTION: "NO_ACTION",
    ACTION_ALERT_ONLY: "ALERT_ONLY",
    ACTION_DRY_RUN_BLOCK: "DRY_RUN_BLOCK (simulated)",
    ACTION_BLOCK_REQUESTED: "BLOCK_REQUESTED (real request)",
}


class DashboardService:
    """Reads detection data and model reports for the dashboard pages."""

    def __init__(
        self,
        db_path=None,
        *,
        reports_dir: Path = REPORTS_DIR,
        models_dir: Path = MODELS_DIR,
        preprocessor_path: Path = PREPROCESSOR_PATH,
    ):
        self.repository = Repository(db_path)
        self.reports_dir = Path(reports_dir)
        self.models_dir = Path(models_dir)
        self.preprocessor_path = Path(preprocessor_path)

    # ---------------------------------------------------------
    #  Database + overview
    # ---------------------------------------------------------

    def database_status(self) -> dict:
        db_path = Path(self.repository.db_path)
        return {"available": self._database_usable(), "path": str(db_path)}

    def _database_usable(self) -> bool:
        """True when the database file exists AND the expected tables exist."""
        db_path = Path(self.repository.db_path)
        if not db_path.exists():
            return False
        try:
            conn = sqlite3.connect(str(db_path))
            try:
                tables = {
                    r[0]
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                return {"detection_events", "models"} <= tables
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    def overview_statistics(self) -> dict:
        """Actual database statistics; zeros (with database_error=True) when
        the database is missing or unreadable."""
        empty = {
            "total_detections": 0,
            "total_attacks": 0,
            "total_benign": 0,
            "attack_percentage": 0.0,
            "high_severity_count": 0,
            "medium_severity_count": 0,
            "low_severity_count": 0,
            "status_counts": {},
            "active_model": None,
            "database_error": False,
        }
        try:
            stats = self.repository.get_detection_statistics()
            active = self.repository.get_active_model()
        except sqlite3.Error:
            empty["database_error"] = True
            return empty
        return {
            **stats,
            "active_model": active["name"] if active else None,
            "database_error": False,
        }

    def has_detection_data(self) -> bool:
        return self.overview_statistics()["total_detections"] > 0

    def response_statistics(self) -> dict:
        """Actual response counts; zeros (with database_error) on failure."""
        zeros = {
            "total_detections": 0,
            "no_action_count": 0,
            "alert_count": 0,
            "dry_run_block_count": 0,
            "block_requested_count": 0,
            "simulated_count": 0,
            "authorized_count": 0,
            "failed_response_count": 0,
            "skipped_count": 0,
            "database_error": False,
        }
        try:
            stats = self.repository.get_response_statistics()
        except sqlite3.Error:
            zeros["database_error"] = True
            return zeros
        return {**stats, "database_error": False}

    def response_status_counts(self) -> dict:
        """Per-status counts plus meaning text (empty dict on error/empty)."""
        try:
            counts = self.repository.get_response_status_counts()
        except sqlite3.Error:
            return {}
        return counts

    def response_status_rows(self) -> list[dict]:
        """Status table rows (status, meaning, count), stable order."""
        counts = self.response_status_counts()
        order = [STATUS_NONE, STATUS_LOGGED, STATUS_SIMULATED, STATUS_AUTHORIZED,
                 STATUS_FAILED, STATUS_SKIPPED, "UNKNOWN"]
        rows = []
        for status in order:
            if status in counts:
                rows.append(
                    {
                        "Response status": status,
                        "Meaning": RESPONSE_STATUS_MEANINGS.get(status, ""),
                        "Count": counts[status],
                    }
                )
        return rows

    def models_registry(self) -> list[dict]:
        """Registered models for the registry view (empty list on error)."""
        try:
            return self.repository.get_models()
        except sqlite3.Error:
            return []

    # ---------------------------------------------------------
    #  Detection table / details
    # ---------------------------------------------------------

    def detections_frame(
        self,
        limit: int = 500,
        label: str | None = None,
        severity: str | None = None,
        *,
        is_attack: bool | None = None,
        response_action: str | None = None,
        response_status: str | None = None,
        start: str | None = None,
        end: str | None = None,
    ) -> pd.DataFrame:
        """Joined detection rows (with model_name); empty frame on error."""
        try:
            rows = self.repository.get_detections_with_model(
                limit,
                label=label,
                severity=severity,
                is_attack=is_attack,
                response_action=response_action,
                response_status=response_status,
                start=start,
                end=end,
            )
        except sqlite3.Error:
            return pd.DataFrame()
        return pd.DataFrame(rows)

    def detection_details(self, detection_id: int) -> dict | None:
        """One detection event with its model name, or None."""
        try:
            row = self.repository.get_detection(detection_id)
        except sqlite3.Error:
            return None
        if row is None:
            return None
        model_name = None
        if row.get("model_id"):
            model = self.repository.get_model(row["model_id"])
            model_name = model["name"] if model else None
        return {**row, "model_name": model_name}

    # ---------------------------------------------------------
    #  Model reports (actual saved files only)
    # ---------------------------------------------------------

    def available_result_files(self) -> list[str]:
        """Existing evaluation result files (Part 5/6 outputs)."""
        candidates = [
            "optimized_model_results.json",
            "baseline_model_results.json",
            "model_results.json",
        ]
        return [name for name in candidates if (self.reports_dir / name).exists()]

    def model_results(self, results_file: str) -> list[dict]:
        """Load actual saved model metrics; [] when missing or malformed."""
        path = self.reports_dir / results_file
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def feature_importance(self, model: str) -> pd.DataFrame | None:
        """Actual Part 6 feature-importance CSV for a model, or None."""
        path = self.reports_dir / f"feature_importance_{model}.csv"
        if not path.exists():
            return None
        try:
            frame = pd.read_csv(path)
        except Exception:
            return None
        if {"feature", "importance"} <= set(frame.columns):
            return frame
        return None

    # ---------------------------------------------------------
    #  System status
    # ---------------------------------------------------------

    def system_status(self) -> dict:
        db_path = Path(self.repository.db_path)
        try:
            active = self.repository.get_active_model()
        except sqlite3.Error:
            active = None
        detections = None
        models = None
        if self._database_usable():
            try:
                detections = self.repository.get_detection_statistics()["total_detections"]
                models = len(self.repository.get_models())
            except sqlite3.Error:
                detections = models = None
        # sanitized/relative database path (avoid exposing local filesystem layout)
        try:
            relative_db_path = str(db_path.relative_to(PROJECT_ROOT))
        except ValueError:
            relative_db_path = db_path.name
        return {
            "database_available": self._database_usable(),
            "database_path": str(db_path),
            "database_path_relative": relative_db_path,
            "active_model": active["name"] if active else None,
            "model_artifacts": sorted(p.name for p in self.models_dir.glob("*.joblib")),
            "preprocessing_artifact_available": self.preprocessor_path.exists(),
            "project_name": settings.PROJECT_NAME,
            "project_version": settings.PROJECT_VERSION,
            "python_version": platform.python_version(),
            "detection_records": detections,
            "model_records": models,
            "response_mode": DEFAULT_RESPONSE_MODE,
            "safety_mode": "Defensive, read-only dashboard; response simulation-only (no real firewall/network changes)",
        }
