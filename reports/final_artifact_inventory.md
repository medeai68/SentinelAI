# SentinelAI — Final Artifact Inventory

Generated 2026-10-07 (Part 11). Statuses: **verified** = exercised by
passing tests and/or a real run in this project.

## Source — `src/`

| Module | Purpose | Status |
| --- | --- | --- |
| `src/data/dataset_loader.py`, `inspect_dataset.py` | Part 3 dataset tooling (validated streaming load, inspection, summary, sample) | verified (real run) |
| `src/preprocessing/` (cleaning, feature_selection, label_encoding, pipeline, reports, visualization) | Part 4 pipeline: cleaning, leakage-safe split, train-only fitting, artifacts, reports | verified (real run on 904,877 rows) |
| `src/training/` (train_binary, optimize, model_comparison, model_utils) | Part 5 baselines + Part 6 tuning/comparison + artifact save/load | verified (real run; models trained) |
| `src/evaluation/` (metrics, evaluate_binary, visualization) | Test-set evaluation, metrics, figures | verified (real run) |
| `src/detection/` (detector, feature_validator, result_formatter, schemas) | Part 7 detection engine (transform-only, no refitting) | verified (real run, 4,996 flows) |
| `src/response/` (actions, policies, response_engine) | Part 7 controlled response (DRY_RUN default; AUTHORIZED refused without adapter) | verified |
| `src/network/` (pcap_reader, flow_extractor, feature_extractor, pcap_pipeline) | Part 10 offline PCAP: reading, flows, feature subset, compatibility gate, CLI | verified (real runs + safety scans) |
| `src/utils/logger.py` | Logging foundation | verified |
| `main.py` | Environment banner entry point | verified |

## Database — `database/`

| Item | Purpose | Status |
| --- | --- | --- |
| `schema.sql` | models + detection_events (+ 5 response columns) | verified |
| `connection.py` | context manager; idempotent additive migration (+2 response indexes) | verified (old-schema + idempotency tests) |
| `models.py` | ModelRecord, DetectionRecord (+ `from_detection_and_response`) | verified |
| `repository.py` | Only DB interface: inserts w/ integrity validation, parameterized queries, statistics | verified |
| `sentinelai.db` | Real local database — 4,996 detections, 1 model, 73≡73 simulated, 0 authorized | read-only verified (git-ignored) |

## Dashboard — `dashboard/`

| Item | Purpose | Status |
| --- | --- | --- |
| `app.py` | Thin shell: config, sidebar refresh, navigation | verified (headless + HTTP 200) |
| `pages.py` | 5 pages: Overview, Threat Detections, Analytics, Models, System Information | verified (bare-mode: all OK) |
| `services/dashboard_service.py` | Data layer (no SQL in UI, no Streamlit import) | verified |
| `components/` (metrics, charts, tables) | Cards, matplotlib charts (incl. simulation-labelled response chart), table | verified |

## Models — `models/`

| File | Purpose | Status |
| --- | --- | --- |
| `xgboost_optimized.joblib` (+ metadata) | **Active model** — Part 6 winner (test F1 0.99824) | hash `836afdda…39a2`, unchanged |
| `random_forest_optimized.joblib`, `logistic_regression_optimized.joblib` (+ metadata) | Part 6 optimized models | preserved |
| `random_forest.joblib`, `logistic_regression.joblib` (+ metadata) | Part 5 baselines | preserved |
| `preprocessing/preprocessor.joblib`, `label_encoder.joblib`, `feature_columns.json` | Part 4 artifacts (dual feature-name metadata) | preserved (hashed) |

## Reports — `reports/`

- **Phase reports:** `part4_real_run_console.txt`, `part5_model_summary.md`,
  `part6_model_comparison.md` (+ cv_results/*.csv, threshold_analysis,
  agreement, feature importances, model_comparison.csv/md),
  `part7_detection_response.md` (+ detection_sample.csv),
  `part8_database.md`, `part9_dashboard.md`, `part10_pcap_analysis.md`,
  `part11_validation_report.md`.
- **Audits:** `data_leakage_audit.md`, `reproducibility_check.md`,
  `test_coverage.txt`, `final_artifact_inventory.md` (this file).
- **Dataset:** `dataset_acquisition.md`, `dataset_inspection.md`,
  `dataset_summary.txt`, `class_distribution.png`.
- **Design docs:** `detection_engine.md`, `database_design.md`,
  `dashboard_design.md`, `pcap_analysis.md`,
  `pcap_feature_compatibility.md`.
- **Figures:** 15 PNGs under `reports/figures/` (class distributions,
  confusion matrices, ROC curves, feature importance, threshold curves,
  numeric distributions) + 3 CV CSVs under `reports/cv_results/`.

## Tests — `tests/`

23 files: 18 unit suites at the top level; `integration/` (offline
pipeline; PCAP full chain); `validation/` (security/portability, PCAP
safety, response safety). **249 passed, 0 failed** (Part 11 baseline).

## Configuration — `config/`

`settings.py` (project identity, paths) · `model_config.py` (seed 42,
CV, search spaces) · `detection_config.py` (active model file, severity
thresholds). No secrets.
