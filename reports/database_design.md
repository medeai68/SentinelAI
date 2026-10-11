# SentinelAI Database Design (Part 8)

## Purpose

Store actual detection results produced by the Part 7 threat detection
engine in a local SQLite database, so later phases (dashboard) can
query, filter and summarize them. The database contains only records
that were really produced — no fabricated data.

## Architecture

```
Threat Detection Engine (Part 7)
        ↓  DetectionResult objects
Repository (database/repository.py)
        ↓  parameterized SQL
SQLite (database/sentinelai.db)
        ↓  queries
Future Dashboard
```

The detector (`src/detection/`) contains **no SQL** — it keeps producing
`DetectionResult` objects; `DetectionRecord.from_detection_result()`
maps them one-way into storage rows.

## Tables

### models

| Column | Type | Notes |
| --- | --- | --- |
| id | INTEGER PK | |
| name | TEXT NOT NULL | e.g. "random_forest_optimized" |
| version | TEXT | from the model metadata |
| algorithm | TEXT | e.g. "RandomForest" |
| file_path | TEXT | path of the saved artifact |
| feature_count | INTEGER | |
| created_at | TEXT | UTC (datetime('now')) |
| is_active | INTEGER | 0/1 — the model currently producing detections |

### detection_events

| Column | Type | Notes |
| --- | --- | --- |
| id | INTEGER PK | |
| timestamp | TEXT NOT NULL | detection-run timestamp (ISO) |
| flow_id | TEXT | input row identity |
| prediction | INTEGER | 0/1 |
| label | TEXT | "BENIGN" / "ATTACK" |
| is_attack | INTEGER | 0/1, NULL when unknown |
| attack_probability | REAL | NULL when the model lacks predict_proba |
| severity | TEXT | LOW / MEDIUM / HIGH |
| model_id | INTEGER | FK → models.id |
| status | TEXT NOT NULL | success / validation_error / prediction_error |
| created_at | TEXT | UTC (datetime('now')) |

## Relationships

`detection_events.model_id → models.id` (foreign key, enforced via
`PRAGMA foreign_keys = ON`). Deleting a model row with detections is
therefore rejected by SQLite rather than silently orphaning rows.

## Indexes

Only the columns the dashboard will filter on: `timestamp`, `label`,
`severity`, `is_attack`, `model_id`. No unnecessary indexes.

## Security

- Every statement is parameterized (`?` placeholders) — values from
  detection results or callers are never concatenated into SQL.
- Input CSVs are parsed as data only by the detector; the database
  layer stores strings literally (verified by a test that inserts a
  SQL-injection-shaped flow id).
- The real database is git-ignored (`database/*.db` and journal
  files) so local records can never be committed to GitHub.
- No secrets are stored — the schema contains no credential fields.

## Data Lifecycle

1. `initialize_database()` creates the file and schema (idempotent —
   never drops tables or data).
2. A detection run stores its results via `Repository.insert_detections()`
   in one transaction (all-or-nothing — no partial batches).
3. Queries/stats read actual counts; an empty database returns zeros.
4. No automatic deletion or rotation is implemented yet (future phase).

## Limitations

- Local, single-file SQLite — fine for research and the future
  dashboard, not a multi-user server database.
- No retention/cleanup policy yet.
- Statistics reflect only detections that were actually stored.
- The database is currently empty: no detection run has happened yet
  (the CIC-IDS2017 dataset download is pending).
