# Part 8 — Database Layer Finalization

Status: complete. All measurements below are actual, produced on
2026-10-07 against the real database and an isolated temporary benchmark
database.

## 1. Database architecture

```
Application (detection / response CLIs, dashboard)
        ↓
Repository (database/repository.py)          — the ONLY normal DB interface
        ↓  parameterized SQL, transactions
Connection manager (database/connection.py)  — context manager, migration
        ↓
SQLite (database/sentinelai.db, git-ignored)
```

## 2. Schema

Two tables (`database/schema.sql`):

- `models` — model registry (name, version, algorithm, file_path,
  feature_count, created_at, is_active).
- `detection_events` — one row per DetectionResult + its ResponseResult:
  id, timestamp, flow_id, prediction, label, is_attack,
  attack_probability, severity, model_id, status, created_at, plus the
  Part 7 response fields, response_action, response_mode,
  response_status, response_reason, response_timestamp.

## 3. Tables and 4. Relationships

`detection_events.model_id → models.id` (FOREIGN KEY, enforced via
`PRAGMA foreign_keys = ON`; inserting an unknown model_id raises
SQLite IntegrityError — tested). Timestamps are stored as ISO strings
consistently; row creation times use SQLite `datetime('now')`.

## 5. Migration strategy

`initialize_database()` runs `schema.sql` (CREATE ... IF NOT EXISTS),
then the additive migration in `connection.py`:

- `ALTER TABLE ADD COLUMN` for each missing response column;
- creation of the two response indexes **after** the columns exist
  (ordering fix: creating them from schema.sql would fail on pre-Part-7
  databases — found by the old-schema migration tests and fixed).

The migration is safe, idempotent, backward compatible and
non-destructive: verified against an old schema (tables without the five
response columns) — columns are added exactly once, existing models,
rows and foreign keys are preserved, and running it twice is safe
(`test_migration_from_old_schema_is_idempotent`,
`test_migration_upgrades_old_schema_and_preserves_data`).

**Real database:** re-initialized in place — detections 4,996 → 4,996,
models 1 → 1, only the two indexes were added.

## 6. Response fields

`response_action` (NO_ACTION / ALERT_ONLY / DRY_RUN_BLOCK /
BLOCK_REQUESTED), `response_mode` (DRY_RUN / AUTHORIZED),
`response_status` (NONE / LOGGED / SIMULATED / AUTHORIZED / FAILED /
SKIPPED), `response_reason` (human-readable policy reason),
`response_timestamp`. All nullable — legacy rows remain valid and are
counted only in `total_detections`, never in an action/status category.

## 7. Repository design

The repository is the only normal database interface. Insert paths:
`insert_model`, `insert_detection`, `insert_detections` (single
transaction, all-or-nothing), `results_to_records`,
`DetectionRecord.from_detection_and_response`.

Query paths: `get_model`, `get_active_model`, `get_detection`,
`get_recent_detections`, `get_detections_by_label`,
`get_detections_by_severity`, `get_detections_by_attack`,
`get_detections_by_response_action`, `get_detections_by_response_status`,
`get_detections_in_range`, `get_detections_with_model` (joined),
`get_detections_over_time`, `get_model_usage`.

Statistics: `get_detection_statistics`, `get_response_statistics`,
`get_attack_probability_statistics`.

**Honest response semantics** (hardened in Part 8): a requested
response is never reported as a successful block —
`dry_run_block_count` and `simulated_count` describe simulations only;
`block_requested_count`/`authorized_count` describe real adapter
requests; `failed_response_count` and `skipped_count` are separate.
Real database today: 73 DRY_RUN_BLOCK ≡ 73 SIMULATED, 0 requested,
0 authorized, 0 failed.

**Insert-time integrity validation** (`validate_detection_record`,
`validate_model_record`): probability must be within [0, 1]; prediction
and is_attack binary or None; timestamps must parse as ISO datetimes;
response action/mode/status must come from the validated sets; action
and status must agree (DRY_RUN_BLOCK may only carry SIMULATED or the
request may fail — never AUTHORIZED). Model name must be non-empty;
feature_count non-negative. Validation happens before SQL, so a bad
batch is rejected whole. DB-level `model_id` integrity is enforced by
the SQLite foreign key.

## 8. Indexes

| Index | Why it exists |
| --- | --- |
| idx_detection_timestamp | "detections over time" grouping and range queries |
| idx_detection_label | label filter on the detections table |
| idx_detection_severity | severity filter |
| idx_detection_is_attack | attack/benign filtering and statistics |
| idx_detection_model_id | model-usage join |
| idx_detection_response_action | response-action counts/filters (Part 7/8) |
| idx_detection_response_status | response-status counts/filters (Part 7/8) |

No further indexes were added — nothing else materially affects the
expected queries.

## 9. Security

- All SQL is parameterized; enforced by the automated validation test
  (which also verifies the placeholder constant contains only `?`, `,`,
  space — the only interpolations are code-constant column/placeholder
  strings).
- No shell commands, no network access, no dynamic execution anywhere in
  the database layer (covered by the project-wide security test scans).
- Database path is configuration-based (`database/connection.py`,
  project-relative); no credentials or secrets exist in source.
- The real database file is git-ignored (`database/*.db`).

## 10. Integrity constraints

See §7 — insert-time validation plus the SQLite foreign key. The schema
itself was not over-constrained (no CHECK constraints added to the
existing table, which would have required a destructive table rebuild);
legacy NULL response fields remain fully supported.

## 11. Performance measurements (actual, temporary database, 10,000 rows)

| Operation | Time |
| --- | --- |
| Insert 10,000 detections (one transaction) | 100.1 ms |
| get_recent_detections(500) | 5.8 ms |
| get_detections_by_attack(True) | 8.0 ms |
| get_detections_by_severity('HIGH') | 6.5 ms |
| get_detections_by_response_action(DRY_RUN_BLOCK) | 6.4 ms |
| get_detections_by_response_status(SIMULATED) | 6.0 ms |
| get_detections_in_range (full span, 10,000 rows returned) | 71.3 ms |
| get_detections_with_model(500) (joined) | 4.4 ms |
| get_response_statistics() | 6.6 ms |
| get_detection_statistics() | 7.5 ms |
| get_attack_probability_statistics() | 4.7 ms |
| get_model_usage() | 1.9 ms |

Performance is already sufficient at this project's scale — no
optimization was invented or applied.

## 12. Test results

```
python -m pytest tests -q
→ 223 passed, 0 failed (36 benign warnings)
```

Part 8 added tests for: old-schema migration idempotency, response
columns and indexes after migration, attack/response/time-range filters,
attack-probability statistics (populated and empty), legacy NULL
response rows, and integrity validation (out-of-range probability,
invalid prediction, invalid timestamp, unknown response action,
mismatched response status, invalid foreign key, empty model name).

## 13. Limitations

- SQLite is single-file, single-writer: fine for research and the
  dashboard, not for concurrent multi-user workloads.
- No retention/rotation policy yet.
- Insert-time validation protects repository writes; direct external
  SQL writes to the file bypass it (SQLite offers no CHECK retrofits
  without table rebuilds).
- Timestamp ordering relies on consistent ISO formatting from writers.
