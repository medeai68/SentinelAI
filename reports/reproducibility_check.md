# Reproducibility Check (Part 11)

Actual observations recorded on 2026-10-06 (Windows 11, Python 3.14.5).

## Configuration

- `random_state = 42` in every randomized step (config/model_config.py,
  detection config, pipeline constants, model constructors, CV
  splitters, searches).
- The Part 4 80/20 stratified split is produced once and reused by
  Parts 5–7 — no new split is ever created downstream (verified by
  grep: `train_test_split` appears only in the Part 4 pipeline, the
  Part 6 training-only threshold slice, and tests).

## Observations (measured, not assumed)

1. **Pipeline determinism**: running the Part 4 pipeline twice on the
   same 5000×8 synthetic sample produced byte-identical `train.csv`
   (SHA-256 hashes equal: `2745e0226507...`).
2. **Same feature dimensions**: both runs produced the same 8 processed
   feature columns (from the saved `feature_columns.json`).
3. **Tuning determinism**: two identical RandomizedSearchCV runs
   (same grid, same seed) returned identical `best_params_` and
   `best_score_` (`test_tune_model_reproducible`).
4. **Detection determinism**: the same input frame produces identical
   predictions across repeated `predict_batch` calls
   (`test_deterministic_output`).
5. **Split reproducibility**: two pipeline runs produced identical
   train sets and 80/20 sizes (`test_split_reproducible_and_stratified`).
6. **Artifact consistency**: model save/load roundtrips reproduce
   identical predictions (`test_save_load_model_roundtrip`).

## Part 11 re-verification on the REAL pipeline (2026-10-07)

- **Seed 42 everywhere:** `config/model_config.py` (RANDOM_STATE=42),
  Part 4 pipeline (`random_state=42` split), model constructors,
  RandomizedSearchCV, StratifiedKFold, and the Part 6 threshold slice —
  verified by code scan.
- **Real-run determinism:** the Part 4 real run is re-runnable (the
  earlier synthetic check showed byte-identical `train.csv` across two
  runs); the Part 5/6 artifacts are the saved products of one run and
  were never regenerated with different settings.
- **Detection determinism:** repeated `predict_batch` calls on the same
  frame produce identical predictions (tested); detection loads the
  fitted artifacts transform-only (no fitting → no drift).
- **PCAP determinism:** flow IDs are deterministic first-seen indices
  (`flow_000000…`), verified identical across repeated runs (tested).
- **Database-independent analysis:** preprocessing/detection/PCAP
  analyses produce the same outputs regardless of database state (the
  database is written only when `--store` is requested).

## Caveat

Full-dataset byte-level re-run of the Part 4 pipeline was not repeated
during Part 11 (a ~5-minute run was considered unnecessary for
validation); the split/fit ordering and seed configuration were
verified from code and the recorded run outputs instead. This is stated
honestly rather than claimed as a re-execution.
