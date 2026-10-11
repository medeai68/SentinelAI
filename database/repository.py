"""SQLite repository for detection results and models (Part 8).

Every statement is parameterized — values from detection results or
callers are never concatenated into SQL strings. Batch insertion runs
in a single transaction and rolls back completely on error (no partial
batches).

The detector (src/detection/) contains no SQL: it produces
DetectionResult objects, and this repository (or the
results_to_records() helper) maps them into storage rows.

Part 8 additions: insert-time integrity validation (probability range,
binary labels, validated response states — the database layer never
assumes a response succeeded merely because one was requested),
response/attack/time-range query methods, and attack-probability
statistics.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from database.connection import connect, get_database_path
from database.models import DetectionRecord, ModelRecord
from src.detection.schemas import DetectionResult
from src.response.actions import RESPONSE_ACTIONS, RESPONSE_MODES

_DETECTION_COLUMNS = (
    "timestamp, flow_id, prediction, label, is_attack, attack_probability, "
    "severity, model_id, status, response_action, response_mode, "
    "response_status, response_reason, response_timestamp"
)
_DETECTION_PLACEHOLDERS = ", ".join("?" * 14)

# statuses allowed per response action. FAILED may follow any requested
# action; SKIPPED pairs with NO_ACTION (detection not applicable).
_ALLOWED_STATUS_BY_ACTION = {
    "NO_ACTION": {"NONE", "SKIPPED"},
    "ALERT_ONLY": {"LOGGED"},
    "DRY_RUN_BLOCK": {"SIMULATED"},
    "BLOCK_REQUESTED": {"AUTHORIZED", "FAILED"},
}
_ALL_RESPONSE_STATUSES = {
    "NONE", "LOGGED", "SIMULATED", "AUTHORIZED", "FAILED", "SKIPPED",
}


def _valid_timestamp(value) -> bool:
    try:
        datetime.fromisoformat(str(value))
        return True
    except (TypeError, ValueError):
        return False


def validate_detection_record(record: DetectionRecord) -> None:
    """Raise ValueError when a detection record violates integrity rules.

    Rules (never over-constraining legacy data — NULLs are allowed for
    optional fields): probability in [0, 1]; binary prediction/is_attack;
    ISO timestamps; response fields from the validated action/mode/status
    sets; action and status must agree (DRY_RUN_BLOCK + SIMULATED means
    simulated only — never an actual block).
    """
    problems: list[str] = []

    if not record.timestamp or not str(record.timestamp).strip():
        problems.append("timestamp must be a non-empty string")
    elif not _valid_timestamp(record.timestamp):
        problems.append(f"timestamp is not a valid ISO datetime: {record.timestamp!r}")

    if record.attack_probability is not None:
        try:
            probability = float(record.attack_probability)
        except (TypeError, ValueError):
            problems.append(f"attack_probability is not numeric: {record.attack_probability!r}")
        else:
            if not 0.0 <= probability <= 1.0:
                problems.append(
                    f"attack_probability must be between 0 and 1, got {record.attack_probability}"
                )

    if record.prediction is not None and int(record.prediction) not in (0, 1):
        problems.append(f"prediction must be 0, 1 or None, got {record.prediction!r}")
    if record.is_attack is not None and int(record.is_attack) not in (0, 1):
        problems.append(f"is_attack must be True, False or None, got {record.is_attack!r}")

    if record.response_action is not None and record.response_action not in RESPONSE_ACTIONS:
        problems.append(f"unknown response_action: {record.response_action!r}")
    if record.response_mode is not None and record.response_mode not in RESPONSE_MODES:
        problems.append(f"unknown response_mode: {record.response_mode!r}")
    if record.response_status is not None and record.response_status not in _ALL_RESPONSE_STATUSES:
        problems.append(f"unknown response_status: {record.response_status!r}")
    if record.response_timestamp is not None and not _valid_timestamp(record.response_timestamp):
        problems.append(
            f"response_timestamp is not a valid ISO datetime: {record.response_timestamp!r}"
        )
    if record.response_action is not None and record.response_status is not None:
        allowed = _ALLOWED_STATUS_BY_ACTION.get(record.response_action, set())
        if record.response_status not in allowed:
            problems.append(
                f"response_status {record.response_status!r} does not match "
                f"response_action {record.response_action!r} (allowed: {sorted(allowed)})"
            )

    if problems:
        raise ValueError("Invalid detection record: " + "; ".join(problems))


def validate_model_record(record: ModelRecord) -> None:
    """Raise ValueError when a model record is invalid."""
    problems: list[str] = []
    if not record.name or not str(record.name).strip():
        problems.append("model name must be a non-empty string")
    if record.feature_count is not None:
        try:
            if int(record.feature_count) < 0:
                problems.append(f"feature_count cannot be negative: {record.feature_count}")
        except (TypeError, ValueError):
            problems.append(f"feature_count is not an integer: {record.feature_count!r}")
    if problems:
        raise ValueError("Invalid model record: " + "; ".join(problems))


def results_to_records(
    results: list[DetectionResult], model_id: int | None
) -> list[DetectionRecord]:
    """Map Part 7 DetectionResults into storage records (one-way)."""
    return [DetectionRecord.from_detection_result(r, model_id) for r in results]


class Repository:
    """Stores and queries SentinelAI records in SQLite."""

    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path is not None else get_database_path()

    # ---------------------------------------------------------
    #  Models
    # ---------------------------------------------------------

    def insert_model(self, record: ModelRecord) -> int:
        """Insert a model record; returns the new model id."""
        validate_model_record(record)
        with connect(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO models (name, version, algorithm, file_path, feature_count, is_active) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    record.name,
                    record.version,
                    record.algorithm,
                    record.file_path,
                    record.feature_count,
                    int(record.is_active),
                ),
            )
            return int(cursor.lastrowid)

    def get_model(self, model_id: int) -> dict | None:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM models WHERE id = ?", (model_id,)).fetchone()
        return dict(row) if row else None

    def get_active_model(self) -> dict | None:
        """Return the most recently inserted active model, if any."""
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM models WHERE is_active = 1 ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def get_models(self) -> list[dict]:
        """All registered models, newest first (for the dashboard registry view)."""
        with connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM models ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------
    #  Detections
    # ---------------------------------------------------------

    def insert_detection(self, record: DetectionRecord) -> int:
        """Insert one detection record; returns the new event id."""
        validate_detection_record(record)
        with connect(self.db_path) as conn:
            cursor = conn.execute(
                f"INSERT INTO detection_events ({_DETECTION_COLUMNS}) "
                f"VALUES ({_DETECTION_PLACEHOLDERS})",
                self._row_values(record),
            )
            return int(cursor.lastrowid)

    def insert_detections(self, records: list[DetectionRecord]) -> int:
        """Insert a batch in ONE transaction; returns the number inserted.

        On any error the whole batch is rolled back — no partial saves.
        """
        if not records:
            return 0
        for record in records:
            validate_detection_record(record)  # whole batch validated first
        with connect(self.db_path) as conn:
            conn.executemany(
                f"INSERT INTO detection_events ({_DETECTION_COLUMNS}) "
                f"VALUES ({_DETECTION_PLACEHOLDERS})",
                [self._row_values(r) for r in records],
            )
        return len(records)

    @staticmethod
    def _row_values(record: DetectionRecord) -> tuple:
        return (
            record.timestamp,
            record.flow_id,
            record.prediction,
            record.label,
            int(record.is_attack) if record.is_attack is not None else None,
            record.attack_probability,
            record.severity,
            record.model_id,
            record.status,
            record.response_action,
            record.response_mode,
            record.response_status,
            record.response_reason,
            record.response_timestamp,
        )

    def get_detection(self, detection_id: int) -> dict | None:
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM detection_events WHERE id = ?", (detection_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_recent_detections(self, limit: int = 100) -> list[dict]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM detection_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_detections_by_label(self, label: str, limit: int = 100) -> list[dict]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM detection_events WHERE label = ? ORDER BY id DESC LIMIT ?",
                (label, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_detections_by_severity(self, severity: str, limit: int = 100) -> list[dict]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM detection_events WHERE severity = ? ORDER BY id DESC LIMIT ?",
                (severity, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_detections_by_attack(self, is_attack: bool, limit: int = 100) -> list[dict]:
        """Detections whose is_attack flag matches (True = attacks)."""
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM detection_events WHERE is_attack = ? ORDER BY id DESC LIMIT ?",
                (int(is_attack), limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_detections_by_response_action(self, action: str, limit: int = 100) -> list[dict]:
        """Detections by response action (NO_ACTION / ALERT_ONLY / DRY_RUN_BLOCK / BLOCK_REQUESTED)."""
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM detection_events WHERE response_action = ? ORDER BY id DESC LIMIT ?",
                (action, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_detections_by_response_status(self, status: str, limit: int = 100) -> list[dict]:
        """Detections by response status (NONE / LOGGED / SIMULATED / AUTHORIZED / FAILED / SKIPPED)."""
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM detection_events WHERE response_status = ? ORDER BY id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_detections_in_range(
        self, start: str, end: str, limit: int = 1000
    ) -> list[dict]:
        """Detections with start <= detection timestamp <= end (ISO strings)."""
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM detection_events WHERE timestamp >= ? AND timestamp <= ? "
                "ORDER BY timestamp ASC LIMIT ?",
                (start, end, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_detections_with_model(
        self,
        limit: int = 100,
        *,
        label: str | None = None,
        severity: str | None = None,
        is_attack: bool | None = None,
        response_action: str | None = None,
        response_status: str | None = None,
        start: str | None = None,
        end: str | None = None,
    ) -> list[dict]:
        """Detection rows joined with their model names (for the dashboard).

        Optional filters: label, severity, attack/benign (is_attack),
        response action, response status, and an inclusive ISO timestamp
        range. Every value is parameterized; the UI never contains SQL.
        """
        query = (
            "SELECT e.id, e.timestamp, e.flow_id, e.prediction, e.label, e.is_attack, "
            "e.attack_probability, e.severity, e.model_id, e.status, e.created_at, "
            "e.response_action, e.response_mode, e.response_status, e.response_reason, "
            "e.response_timestamp, "
            "m.name AS model_name "
            "FROM detection_events e LEFT JOIN models m ON e.model_id = m.id "
        )
        clauses: list[str] = []
        params: list = []
        if label:
            clauses.append("e.label = ?")
            params.append(label)
        if severity:
            clauses.append("e.severity = ?")
            params.append(severity)
        if is_attack is not None:
            clauses.append("e.is_attack = ?")
            params.append(int(bool(is_attack)))
        if response_action:
            clauses.append("e.response_action = ?")
            params.append(response_action)
        if response_status:
            clauses.append("e.response_status = ?")
            params.append(response_status)
        if start:
            clauses.append("e.timestamp >= ?")
            params.append(start)
        if end:
            clauses.append("e.timestamp <= ?")
            params.append(end)
        if clauses:
            query += "WHERE " + " AND ".join(clauses) + " "
        query += "ORDER BY e.id DESC LIMIT ?"
        params.append(limit)
        with connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------
    #  Statistics (actual counts; zeros for an empty database)
    # ---------------------------------------------------------

    def get_detection_statistics(self) -> dict:
        """Return actual detection statistics computed from the database."""
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT "
                "COUNT(*) AS total, "
                "COALESCE(SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END), 0) AS attacks, "
                "COALESCE(SUM(CASE WHEN is_attack = 0 THEN 1 ELSE 0 END), 0) AS benign, "
                "COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) AS high, "
                "COALESCE(SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END), 0) AS medium, "
                "COALESCE(SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END), 0) AS low "
                "FROM detection_events"
            ).fetchone()
            status_rows = conn.execute(
                "SELECT status, COUNT(*) AS count FROM detection_events GROUP BY status"
            ).fetchall()
        total = int(row["total"] or 0)
        attacks = int(row["attacks"] or 0)
        status_counts = {r["status"]: int(r["count"]) for r in status_rows}
        return {
            "total_detections": total,
            "total_attacks": attacks,
            "total_benign": int(row["benign"] or 0),
            "attack_percentage": round(attacks / total * 100, 2) if total else 0.0,
            "high_severity_count": int(row["high"] or 0),
            "medium_severity_count": int(row["medium"] or 0),
            "low_severity_count": int(row["low"] or 0),
            "status_counts": status_counts,
        }

    def get_detections_over_time(self, limit: int = 1000) -> list[dict]:
        """Detection counts grouped by detection timestamp (newest first)."""
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT timestamp, COUNT(*) AS count FROM detection_events "
                "GROUP BY timestamp ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_response_statistics(self) -> dict:
        """Actual response counts (zeros for an empty database).

        Honest semantics — a requested response is never reported as a
        successful block:

          * `dry_run_block_count`   = DRY_RUN_BLOCK actions (simulated only)
          * `simulated_count`       = response_status SIMULATED (subset of dry-run)
          * `block_requested_count` = BLOCK_REQUESTED actions (real adapter requested)
          * `authorized_count`      = response_status AUTHORIZED (adapter confirmed)
          * `failed_response_count` = response_status FAILED (adapter attempted and failed)
          * `skipped_count`         = response_status SKIPPED (detection not applicable)
          * legacy/unknown rows are counted only in `total_detections`.
        """
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT "
                "COUNT(*) AS total, "
                "COALESCE(SUM(CASE WHEN response_action = 'NO_ACTION' THEN 1 ELSE 0 END), 0) AS no_action, "
                "COALESCE(SUM(CASE WHEN response_action = 'ALERT_ONLY' THEN 1 ELSE 0 END), 0) AS alerts, "
                "COALESCE(SUM(CASE WHEN response_action = 'DRY_RUN_BLOCK' THEN 1 ELSE 0 END), 0) AS dry_run_blocks, "
                "COALESCE(SUM(CASE WHEN response_action = 'BLOCK_REQUESTED' THEN 1 ELSE 0 END), 0) AS block_requests, "
                "COALESCE(SUM(CASE WHEN response_status = 'SIMULATED' THEN 1 ELSE 0 END), 0) AS simulated, "
                "COALESCE(SUM(CASE WHEN response_status = 'AUTHORIZED' THEN 1 ELSE 0 END), 0) AS authorized, "
                "COALESCE(SUM(CASE WHEN response_status = 'FAILED' THEN 1 ELSE 0 END), 0) AS failed, "
                "COALESCE(SUM(CASE WHEN response_status = 'SKIPPED' THEN 1 ELSE 0 END), 0) AS skipped "
                "FROM detection_events"
            ).fetchone()
        return {
            "total_detections": int(row["total"] or 0),
            "no_action_count": int(row["no_action"] or 0),
            "alert_count": int(row["alerts"] or 0),
            "dry_run_block_count": int(row["dry_run_blocks"] or 0),
            "block_requested_count": int(row["block_requests"] or 0),
            "simulated_count": int(row["simulated"] or 0),
            "authorized_count": int(row["authorized"] or 0),
            "failed_response_count": int(row["failed"] or 0),
            "skipped_count": int(row["skipped"] or 0),
        }

    def get_response_status_counts(self) -> dict:
        """Per-status response counts (includes legacy rows as 'UNKNOWN')."""
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT response_status, COUNT(*) AS count FROM detection_events "
                "GROUP BY response_status"
            ).fetchall()
        return {
            (r["response_status"] if r["response_status"] is not None else "UNKNOWN"): int(r["count"])
            for r in rows
        }

    def get_attack_probability_statistics(self) -> dict:
        """Actual attack-probability statistics over stored detections.

        Only rows with a stored probability are counted; an empty
        database (or no probabilities) returns zeros/Nones.
        """
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(attack_probability) AS n, "
                "MIN(attack_probability) AS min_p, "
                "MAX(attack_probability) AS max_p, "
                "AVG(attack_probability) AS avg_p "
                "FROM detection_events"
            ).fetchone()
        n = int(row["n"] or 0)
        return {
            "probability_count": n,
            "min_probability": float(row["min_p"]) if n else None,
            "max_probability": float(row["max_p"]) if n else None,
            "average_probability": round(float(row["avg_p"]), 6) if n else None,
        }

    def get_model_usage(self) -> list[dict]:
        """Detections per model (joins the models registry)."""
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT m.id AS model_id, m.name AS model_name, COUNT(e.id) AS detections "
                "FROM detection_events e LEFT JOIN models m ON e.model_id = m.id "
                "GROUP BY e.model_id ORDER BY detections DESC"
            ).fetchall()
        return [dict(r) for r in rows]
