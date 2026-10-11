# Part 7 — Threat Detection & Controlled Response

Status: complete. All values below are actual measured results from the
real CIC-IDS2017 run on 2026-10-07.

## Objective

Extend SentinelAI from detection-and-analysis into a **controlled,
defensive response system**:

    Network Traffic -> Feature Extraction -> Optimized XGBoost Model
    -> Threat Detection -> Threat Classification -> Response Policy
    -> Safe/Dry-Run Response -> Database Logging -> Dashboard

The system never modifies the real Windows/Linux firewall or network
configuration. The default and only shipped mode is **DRY_RUN**.

## Architecture

- `src/detection/` — the existing detection engine (unchanged logic;
  one integration fix, see below).
- `src/response/` — NEW, detection logic stays separate:
  - `actions.py` — modes, actions, statuses, the isolated
    `ResponseExecutor` adapter protocol (no implementation shipped).
  - `policies.py` — configurable `ResponsePolicy` (pure decision logic).
  - `response_engine.py` — `ResponseEngine`, `ResponseResult`, and the
    detect -> respond -> (optionally store) orchestration CLI.

## Winning model (from Part 6, actual)

- Artifact: `models/xgboost_optimized.joblib`
- Metadata: `models/metadata/xgboost_optimized.json`
- Part 6 untouched-test results: F1 0.99824 · Recall 0.99868 ·
  ROC-AUC 0.99990 · TP 2263 · TN 163351 · FP 5 · FN 3 · FNR 0.00132

## Detection flow

1. Input CSV is parsed strictly as data (never executed).
2. Column names are normalized exactly like the Part 4 cleaning
   (strip, spaces -> underscores), so raw dataset names
   ("Flow Bytes/s") match the fitted preprocessor's schema
   ("Flow_Bytes/s").
3. The fitted Part 4 preprocessor is loaded and only `.transform()`ed.
4. The optimized XGBoost model predicts on the transformed features.
5. `DetectionResult` carries prediction, attack probability, severity,
   model name/version, timestamp and flow id.

### Integration fix found by the real run

The first real detection run exposed that the detector compared raw CSV
column names (spaces) against the Part 4 cleaned schema (underscores),
so every row failed validation. Fixed in
`src/detection/feature_validator.py` by applying the same
`clean_column_names` normalization before schema matching (mirrors the
existing preprocessing design; regression tests added). The erroneous
first batch (4,996 validation_error/SKIPPED rows) was removed from the
database after the fix — see "Database changes".

## Response flow

    DetectionResult
      -> ResponsePolicy.recommend()  (pure decision)
      -> ResponseResult (action, mode, status, reason)
      -> DRY_RUN: simulated + logged  |  AUTHORIZED: only via an
         explicitly supplied, isolated adapter (none shipped)

## Response policy

Configurable (`ResponsePolicy`), thresholds reuse validated values —
no arbitrary numbers invented:

| Concept | Value | Source |
| --- | --- | --- |
| Detection threshold | 0.50 | Part 6 threshold analysis (selected final test threshold AND training-only best-F1 threshold were both 0.50) |
| High-confidence threshold | 0.80 | existing documented severity threshold (`detection_config.HIGH_ATTACK_PROBABILITY`) |

Decision rule:

    attack probability < 0.50            -> NO_ACTION
    ATTACK, probability < 0.80           -> ALERT_ONLY
    high-confidence ATTACK (>= 0.80):
        DRY_RUN mode                     -> DRY_RUN_BLOCK  (simulated only)
        AUTHORIZED mode                  -> BLOCK_REQUESTED (adapter required)

Boundary behavior: thresholds are inclusive (>=). A missing probability
falls back to the model's predicted class (attack -> ALERT_ONLY, never
a block). Non-successful detections are SKIPPED (no response applies).

## DRY_RUN mode (default)

- `DEFAULT_RESPONSE_MODE = "DRY_RUN"`; `DEFAULT_POLICY` uses it.
- In DRY_RUN the engine NEVER calls an executor — even if one is
  provided (tested).
- DRY_RUN never yields `BLOCK_REQUESTED` at any probability (tested
  across the full grid).
- The response module contains no `subprocess`, `socket`, `netsh`,
  `iptables`, `ufw`, `pfctl`, `requests`, `urllib` or similar —
  enforced by an automated safety scan (`tests/validation/test_response_safety.py`).

## Authorization boundary

Four deliberately separated concepts:

1. **Detection** — the model's prediction (`src/detection/`).
2. **Recommended response** — policy decision (`policies.py`).
3. **Simulated response** — `DRY_RUN_BLOCK`/`SIMULATED`; nothing changes.
4. **Actual authorized response** — `BLOCK_REQUESTED`; reachable ONLY in
   AUTHORIZED mode with an explicitly supplied, isolated adapter
   (restricted to a local/authorized test environment). This project
   ships no such adapter; the CLI refuses AUTHORIZED mode outright.

## Database changes (safe, additive only)

`detection_events` gains five response columns:
`response_action`, `response_mode`, `response_status`, `response_reason`,
`response_timestamp`.

- Migration: `initialize_database()` runs an additive
  `ALTER TABLE ADD COLUMN` for any missing column — existing tables and
  data are never dropped (tested against an old-schema database with
  data in it).
- Repository: inserts carry the response fields; new
  `get_response_statistics()`; joined detection queries include the
  response columns.
- **First-run cleanup (disclosed):** the pre-fix run stored 4,996
  rows that were all `validation_error`/`SKIPPED` (column-name bug).
  After fixing the bug, exactly that batch (matched by its unique
  detection timestamp) and the model-registry row it had created were
  removed; no other rows existed or were touched. The database now
  contains only correct results.

## Dashboard changes

Threat Detections page now shows: Timestamp, Prediction, Label,
Attack Probability, Severity, Model, Status, **Response Action**,
**Response Mode**, **Response Status** — plus summary metrics: Total
detections, Attack detections, Alerts, Dry-run responses, Failed
responses. Detection details include the full response fields. Empty
database -> truthful empty state (unchanged). The dashboard only reads
(verified: queries do not modify data).

## Actual real-run results (development sample, 4,996 flows)

- Detections: 4,923 BENIGN / 73 ATTACK (1.46%); all 4,996 successful.
- Responses: 4,923 NO_ACTION, 0 ALERT_ONLY, **73 DRY_RUN_BLOCK**,
  0 BLOCK_REQUESTED, 0 FAILED, 0 SKIPPED.
- All 73 attack rows in the sample were detected at high confidence
  (>= 0.80) — simulated blocks, nothing changed on this machine.
- **Honest caveat:** the development sample was drawn from `data/raw/`
  before the Part 4 split, so its flows overlap the training data
  (100% match there reflects memorization, not generalization). The
  honest performance reference is the Part 6 untouched-test metrics.
- Informative validation notes (by design): 8 constant columns dropped,
  infinite values replaced with NaN and imputed, 7 rows imputed by the
  fitted artifact.

## Tests

`python -m pytest tests -q` -> **209 passed, 0 failed** (36 benign
warnings). New Part 7 tests cover: policy branches and boundaries,
configurability and validation; engine fail-closed configuration;
DRY_RUN executor isolation; adapter success/failure; the full
Detector -> ResponseEngine -> Repository -> SQLite chain; schema
migration preserving old data; empty-database response stats; the
orchestration CLI (including the AUTHORIZED refusal); and the safety
scan described above. All Parts 1–6 tests remain untouched and passing.

## Limitations

- Response is simulated by design; no real-response adapter exists in
  this project.
- The response policy is binary-focused (Part 6 model target) and uses
  two thresholds; severity is an interpretation layer, not ground truth.
- Detection quality equals the Part 6 model quality (F1 0.99824 on the
  untouched test set; lab dataset, no external validation).
- Flow-level responses only — no host/identity context.

## Future improvements

- Optional, explicitly scoped authorized adapter for a local testbed.
- Per-IP aggregation for response decisions (currently per-flow).
- Alert routing/notification beyond database logging.
