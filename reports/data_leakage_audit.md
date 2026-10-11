# Data Leakage Audit (Part 11)

Explicit audit of the preprocessing/training/detection code. Every
claim below was verified by reading the actual code paths (and, where
possible, by tests) on 2026-10-06.

## Checks

### 1. Test set never used for preprocessing fitting — PASS

`src/preprocessing/pipeline.py`: the train/test split happens first;
empty/constant-column decisions are derived from the TRAINING split
only and applied to both; `preprocessor.fit_transform(X_train)` is
followed by `preprocessor.transform(X_test)`. The imputer and scaler
statistics come exclusively from training data. A dedicated test
(`test_pipeline_fits_imputer_on_train_only`) proves the imputer learns
the train median, not the full-data median.

### 2. Test set never used for hyperparameter tuning — PASS

`src/training/optimize.py`: `tune_model`/`tune_and_record` accept only
`X_train`/`y_train` (no test-set parameter exists — enforced by
`test_tune_model_has_no_test_set_parameter`). `src/training/model_comparison.py`
passes `X_test`/`y_test` only to final evaluation and read-only
reporting helpers.

### 3. Target never included as a feature — PASS

The Part 4 pipeline builds the feature matrix from non-label columns
only; `feature_columns.json` contains feature names, never
`binary_label`, `multiclass_label`, or `Label`. Enforced by the
validation test `test_target_never_in_feature_list`.

### 4. Identifiers do not leak labels — PASS (documented)

`src/preprocessing/cleaning.py` removes the documented
identifier/metadata columns (Flow ID, source/destination IP, timestamp,
CSV artifact index) BEFORE the split, with per-column reasons. Features
are never dropped merely for correlating with the label.

### 5. Threshold selection did not use the final test data — PASS

`src/training/model_comparison.py`: the threshold analysis splits
`X_train.index` into a training-only sub-train/sub-validation slice;
the final test set is never passed to threshold selection.

## Documented caveats (not hidden)

- Part 6 evaluates BASELINE models on the test set once, before tuning,
  as a reference snapshot prescribed by the experiment design. This
  slightly reduces the holdout's strictness and is disclosed in the
  generated research report as a limitation.
- Part 6 read-only reporting helpers (ROC curves, confusion matrix,
  the report writer) receive `y_test` after evaluation; they fit,
  tune, or select nothing.

## Issue found and fixed during this audit

The Part 4 pipeline saved the PROCESSED (prefixed) column names
(`numeric__Flow_Duration`, ...) into `feature_columns.json`, but the
Part 7 detection engine validated input against those names while the
fitted preprocessor consumes RAW names — a consistency bug that would
have broken detection against real artifacts. Fixed:

- the detector now uses the preprocessor artifact's own input schema
  (`feature_names_in_`) as the authoritative feature list;
- `feature_columns.json` now also stores `input_feature_columns` (raw
  names) for the PCAP compatibility check;
- covered by the new full-offline-pipeline integration test.

## Part 11 final re-verification (post real-run, 2026-10-07)

Re-checked against the code that actually produced the real Parts 4–6
results:

- **Split-before-fit (measured anchor):** in
  `src/preprocessing/pipeline.py`, the `train_test_split(...)` call
  appears BEFORE `preprocessor.fit_transform(X_train)`, and
  `preprocessor.transform(X_test)` is the only call touching the test
  set (`fit_transform(X_test)` does not exist anywhere). Verified
  programmatically: True/True.
- **Tuner never sees the test set (measured anchor):** `tune_model` in
  `src/training/optimize.py` takes only `(estimator, param_grid,
  X_train, y_train, ...)` — its signature contains no test parameter
  (verified programmatically: True), and the Part 6 run's tuning phase
  consumed only the training split.
- **Target never a feature (verified on the real artifacts):** neither
  `feature_columns` nor `input_feature_columns` in the actual
  `models/preprocessing/feature_columns.json` contains any name with
  "label" (case-insensitive) — verified programmatically: True.
- **Threshold selection training-only:** the Part 6 threshold analysis
  sliced `X_train` (80/20 train-only validation slice); the untouched
  test set was used once, at the end, for the final comparison.
- **Identifiers:** the CIC-IDS2017 machine-learning CSVs contain no IP
  addresses or raw identifiers (documented in Part 3 inspection); the
  documented removal list (Flow ID/IPs/timestamp) still applies to
  other inputs and is exercised by tests.
- **Real-run consistency:** the Part 4 → 6 run recorded
  `validation_problems: []` and the Part 7 detection run used the saved
  artifacts transform-only (no fitting anywhere at detection time —
  enforced by tests).

No leakage findings. The audit remains PASS.

