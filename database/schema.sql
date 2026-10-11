-- SentinelAI database schema (Part 8)
-- Executed by database/connection.py via initialize_database().
-- Idempotent: CREATE ... IF NOT EXISTS only; nothing is ever dropped here.

PRAGMA foreign_keys = ON;

-- Model registry: every trained model that produced detections.
CREATE TABLE IF NOT EXISTS models (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    version       TEXT,
    algorithm     TEXT,
    file_path     TEXT,
    feature_count INTEGER,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    is_active     INTEGER NOT NULL DEFAULT 0
);

-- Detection events: one row per DetectionResult produced by Part 7.
-- Part 7 (response) adds the five response_* columns below; existing
-- databases receive them through a safe ALTER TABLE migration in
-- connection.py (no data is ever dropped).
CREATE TABLE IF NOT EXISTS detection_events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp          TEXT NOT NULL,          -- detection-run timestamp (ISO)
    flow_id            TEXT,
    prediction         INTEGER,
    label              TEXT,
    is_attack          INTEGER,                -- 0/1, NULL when unknown
    attack_probability REAL,
    severity           TEXT,
    model_id           INTEGER,
    status             TEXT NOT NULL,
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    response_action    TEXT,                   -- NO_ACTION / ALERT_ONLY / DRY_RUN_BLOCK / BLOCK_REQUESTED
    response_mode      TEXT,                   -- DRY_RUN / AUTHORIZED
    response_status    TEXT,                   -- NONE / LOGGED / SIMULATED / AUTHORIZED / FAILED / SKIPPED
    response_reason    TEXT,                   -- human-readable policy reason
    response_timestamp TEXT,
    FOREIGN KEY (model_id) REFERENCES models(id)
);

-- Useful indexes only: the columns the dashboard filters/counts on.
--   idx_detection_timestamp      -> "detections over time" grouping/range queries
--   idx_detection_label          -> label filter on the detections table
--   idx_detection_severity       -> severity filter
--   idx_detection_is_attack      -> attack/benign filtering and statistics
--   idx_detection_model_id       -> model-usage join
-- The two response indexes (response_action, response_status) are created
-- by the migration step in connection.py AFTER the response columns exist,
-- so old databases migrate cleanly.
CREATE INDEX IF NOT EXISTS idx_detection_timestamp ON detection_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_detection_label ON detection_events(label);
CREATE INDEX IF NOT EXISTS idx_detection_severity ON detection_events(severity);
CREATE INDEX IF NOT EXISTS idx_detection_is_attack ON detection_events(is_attack);
CREATE INDEX IF NOT EXISTS idx_detection_model_id ON detection_events(model_id);
