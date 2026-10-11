# Development Guide — SentinelAI

Quick-start for working on SentinelAI locally on Windows 11 with PowerShell.

- Project root: `F:\vs 1\SentinelAI`
- Virtual environment: `.venv` (already created, Python 3.14.5)

## Windows PowerShell Quickstart

Run these commands from the project root (`F:\vs 1\SentinelAI`), in order.

### 1. Activate the virtual environment

```powershell
.venv\Scripts\Activate.ps1
```

Your prompt now starts with `(.venv)`.

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

The `pip` inside `.venv` is used, so packages are installed into the project's virtual environment.

### 3. Run the project

```powershell
python main.py
```

You should see the SentinelAI banner and an `Environment: Ready` line.

### 4. Deactivate when you are done

```powershell
deactivate
```

The `(.venv)` prefix disappears from your prompt.

## If PowerShell blocks the activation script (execution policy)

If activation fails with a message like "running scripts is disabled on this system" or "Activate.ps1 is not digitally signed", you do **not** need to change any system-wide security settings. Instead, skip activation and call the virtual environment's Python executable directly — it always works:

```powershell
.\.venv\Scripts\python.exe main.py
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

- These commands use the `.venv` Python and its installed packages, exactly like running with the environment activated.
- There is nothing to deactivate — you just stop using that path (or close the terminal).
- On this machine the execution policy is already `RemoteSigned`, so `.venv\Scripts\Activate.ps1` normally works. The direct-executable method is only a fallback.

You can check your current policy at any time with:

```powershell
Get-ExecutionPolicy
```

## Part 3 — Dataset

The project uses **CIC-IDS2017** (Canadian Institute for Cybersecurity, UNB).
Note: this dataset is for **defensive research only** — analysing public,
labeled traffic; never run attacks or scan other systems.

### 1. Obtain the dataset from the legitimate source

1. Open the official page: <https://www.unb.ca/cic/datasets/ids-2017.html>
2. Click **"Download this dataset"** — it opens the CIC download portal
   (<http://cicresearch.ca/CICDataset/CIC-IDS-2017/>) with a short
   registration form (name, email, organization, country).
3. After registering you can download the files. The direct S3 links used in
   older tutorials no longer work (HTTP 403) — the portal is the current
   official way.
4. Preferred for development: the small **per-day CSV files** if the portal
   offers them individually — at minimum:
   - `Tuesday-WorkingHours.pcap_ISCX.csv` (benign + Brute Force FTP/SSH)
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (benign + Web Attacks)
   - `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` (benign + Infiltration — note the official misspelling "Infilteration")
   Otherwise download **`MachineLearningCSV.zip`** and extract just these three
   files from it. Avoid the PCAP archives (~11 GB/day) — they are not needed
   for the ML phases.
5. Remember to cite the dataset paper:
   Sharafaldin, Habibi Lashkari & Ghorbani, *"Toward Generating a New Intrusion
   Detection Dataset and Intrusion Traffic Characterization"*, ICISSP 2018.

### 2. Place the files in `data/raw/`

```powershell
# If the portal gave you the per-day CSV files (recommended), copy them
# from your Downloads folder into the project:
Copy-Item "$env:USERPROFILE\Downloads\Tuesday-WorkingHours.pcap_ISCX.csv" data\raw\
Copy-Item "$env:USERPROFILE\Downloads\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv" data\raw\
Copy-Item "$env:USERPROFILE\Downloads\Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv" data\raw\

# If you downloaded MachineLearningCSV.zip instead, extract just what you need:
Expand-Archive -Path "$env:USERPROFILE\Downloads\MachineLearningCSV.zip" -DestinationPath data\raw\ -Force
# (keep the three files above and delete the large per-day files you do not need)

# Verify the files are in place:
Get-ChildItem data\raw
```

`data/raw/` is git-ignored, so the dataset can never be committed by accident.

### 3. Run the inspection script

From the project root, with the virtual environment activated:

```powershell
python -m src.data.inspect_dataset
```

This inspects every CSV in `data/raw/` **without modifying it**, prints rows,
columns, types, missing values, duplicates, infinite values and the class
distribution, and then writes:

- `reports/dataset_summary.txt` — human-readable summary with real numbers
- `reports/class_distribution.png` — class distribution chart

### 4. Generate the development sample

The same command creates `data/sample/development_sample.csv` automatically —
a small, reproducible (seed 42), multi-class sample for fast development work.
It never replaces the original dataset.

### 5. Read the dataset summary

```powershell
Get-Content reports\dataset_summary.txt
```

## Part 4 — Data Preprocessing

With the dataset in `data/raw/` and the virtual environment activated, run the
preprocessing pipeline from the project root:

```powershell
python -m src.preprocessing.pipeline
```

What it does (raw files are never modified):

1. Loads and concatenates all CSVs in `data/raw/`.
2. Cleans: duplicate rows, normalized column names, leakage columns
   (Flow ID, IPs, timestamp), numeric type conversion, infinities → NaN.
   After the split, empty and constant columns are detected on the
   training split only and dropped from both splits.
3. Builds both targets: binary (`BENIGN` → 0, attack → 1) and multiclass.
4. Splits 80/20, stratified, `random_state = 42` — **before** any fitting.
5. Fits the median imputer and StandardScaler on the **training split only**,
   then transforms both splits (no test-set leakage).
6. Validates the output (no NaN/inf, valid labels, consistent columns,
   reversible label encoder).

Outputs:

- `data/processed/train.csv` and `data/processed/test.csv` (ML-ready)
- `models/preprocessing/preprocessor.joblib` — imputer + scaler
- `models/preprocessing/label_encoder.joblib` — multiclass label encoder
- `models/preprocessing/feature_columns.json` — final feature list
- `reports/label_mapping.json` — binary + multiclass label mappings
- `reports/feature_decisions.md` — every removed/converted column and why
- `reports/feature_summary.md` — per-feature overview
- `reports/class_imbalance.md` — imbalance analysis (no resampling in Part 4)
- `reports/preprocessing_summary.md` — reproducibility record
- `reports/figures/` — class distributions (raw/train/test) + feature histograms

Run the tests:

```powershell
python -m pytest tests -q
```

(or without activation: `.\.venv\Scripts\python.exe -m pytest tests -q`)

## Part 5 — First ML Models

With the dataset in `data/raw/` and Parts 3–4 run once (the processed
`train.csv`/`test.csv` and `models/preprocessing/` artifacts exist):

```powershell
# 1. Train the two binary baselines (reuses the Part 4 split, no new split)
python -m src.training.train_binary
#    -> models/logistic_regression.joblib, models/random_forest.joblib
#       + metadata under models/metadata/

# 2. Evaluate on the test set ONLY
python -m src.evaluation.evaluate_binary
#    -> reports/*_classification_report.txt, model_results.json/.csv,
#       part5_model_summary.md, feature-importance and coefficient CSVs,
#       and figures under reports/figures/ (confusion matrices, ROC curves,
#       feature importance)

# 3. Run the tests
python -m pytest tests -q
```

Notes:

- `random_state=42` everywhere; the Part 4 80/20 stratified split is reused,
  never re-created.
- The test set is only used for evaluation — never during training.
- Class weighting is used (`balanced` for logistic regression,
  `balanced_subsample` for random forest) and recorded in the metadata and
  in `reports/part5_model_summary.md`.
- All metrics in the reports are actual measured values — nothing is
  hardcoded.

## Part 6 — Advanced Model Comparison

With the dataset in `data/raw/` and the Part 4 processed data built:

```powershell
# Run the full Part 6 experiment: baselines -> tuning -> final test evaluation
python -m src.training.model_comparison
#    -> reports/cv_results/*.csv           full CV results per model (not just the winner)
#    -> reports/baseline_model_results.json/.csv
#    -> reports/optimized_model_results.json/.csv
#    -> reports/model_comparison.csv/.md, reports/part6_model_comparison.md
#    -> reports/model_agreement.csv, reports/threshold_analysis.csv
#    -> figures under reports/figures/ (metric comparison, ROC curves,
#       confusion matrices, feature importance, threshold curves)
#    -> models/*_optimized.joblib + models/metadata/*.json

# Run the tests
python -m pytest tests -q
```

Notes:

- Experiment configuration lives in `config/model_config.py`
  (random_state=42, 5-fold stratified CV, F1 scoring, search spaces,
  `SEARCH_N_ITER=30`). If the search is too slow on your machine,
  reduce `SEARCH_N_ITER` there — and mention the change in the report.
- The test set is used ONLY for the final evaluation, never for tuning.
- XGBoost class imbalance is handled via `scale_pos_weight` computed
  from the training set (documented in the research report).
- XGBoost is installed in `.venv` (version 3.4.1); `pip install -r
  requirements.txt` covers it for fresh environments.

## Part 7 — Threat Detection Engine

After Parts 4–6 have run once (artifacts exist) and the best Part 6
model is set in `config/detection_config.py` (`DEFAULT_MODEL_FILE`) or
passed via `--model`:

```powershell
# Analyze an authorized network-flow CSV
python -m src.detection.detector --input path\to\flows.csv

# Save the structured results to a file
python -m src.detection.detector --input path\to\flows.csv --output reports\detection_results.csv

# Run the tests
python -m pytest tests -q
```

Notes:

- The engine never fits anything at detection time — it loads the
  Part 4 preprocessor and the optimized model once, then only
  transforms and predicts.
- Input CSVs are parsed as data only; nothing from the CSV is ever
  executed or evaluated.
- Severity thresholds live in `config/detection_config.py` and are
  experimental defaults (documented in `reports/detection_engine.md`).
- One flow = one `DetectionResult`; invalid rows get an error status
  instead of being silently dropped.

## Part 8 — Database Layer

The SQLite database (`database/sentinelai.db`) stores actual detection
results for the future dashboard. It is git-ignored, so local records
never reach GitHub.

```powershell
# Initialize / verify the database (safe to run repeatedly; never drops tables)
python -c "from database.connection import initialize_database; print(initialize_database())"

# Store detection results (example after a Part 7 run):
python - <<'PY'
from database.connection import initialize_database
from database.models import DetectionRecord, ModelRecord
from database.repository import Repository, results_to_records
from src.detection.detector import ThreatDetector

repo = Repository()
model_id = repo.insert_model(ModelRecord(name="...", is_active=True))
detector = ThreatDetector.from_artifacts(model_path="models/<winner>_optimized.joblib")
results = detector.predict_batch(...)          # authorized data only
repo.insert_detections(results_to_records(results, model_id))
print(repo.get_detection_statistics())
PY

# Run the tests
python -m pytest tests -q
```

Notes:

- All SQL is parameterized; batch insertion is one transaction
  (all-or-nothing — no partial batches).
- Unit tests never touch the real `sentinelai.db` (they use temp
  databases).
- Schema and design details: `reports/database_design.md`.

## Part 9 — Streamlit Dashboard

```powershell
# Install dependencies (Streamlit included)
pip install -r requirements.txt

# Run the dashboard
streamlit run dashboard/app.py
# -> opens http://localhost:8501

# Run the tests
python -m pytest tests -q
```

Notes:

- Every number shown comes from the actual `database/sentinelai.db`
  (Part 8) or actual saved model reports (Parts 5/6). Empty databases
  and missing reports show clear empty states — nothing is fabricated.
- Pages: Overview, Threat Detections, Analytics, Models, System
  Information.
- Data access lives in `dashboard/services/dashboard_service.py` (no
  SQL duplicated in the UI); charts use matplotlib only (no seaborn,
  default colors).
- The dashboard is local and single-user — run it only on a trusted
  machine. No authentication layer exists yet.
- Part 9 additions: response monitoring section with an explicit
  DRY_RUN simulation banner (DRY_RUN_BLOCK is never shown as a real
  block), filters for attack/response/date-range, model registry view.
  Design details: `reports/dashboard_design.md` and
  `reports/part9_dashboard.md`.

## Part 10 — PCAP Analysis

Authorized offline PCAP analysis only — no live capture, no scanning,
no network activity of any kind.

```powershell
# Analyze a local authorized capture
python -m src.network.pcap_pipeline --input path\to\authorized.pcap

# Save the flow table and optionally store successful detections
python -m src.network.pcap_pipeline --input path\to\authorized.pcap --output reports\pcap_flows.csv --store

# Run the tests
python -m pytest tests -q
```

Notes:

- The pipeline extracts flows (5-tuple) and a documented subset of
  CIC-IDS2017 features. Because the full ~78-feature CICFlowMeter set
  cannot be reconstructed reliably from raw packets, predictions are
  only attempted when the feature set is fully compatible — otherwise
  flows are reported as `feature set incomplete` (never fake-filled).
  See `reports/pcap_feature_compatibility.md` after a run.
- Provide your own authorized PCAP; no sample capture is bundled.
- Scapy is installed in `.venv` (2.8.0). The "No libpcap provider"
  warning on import is expected on this machine and irrelevant for
  offline file reading (it only affects live capture, which this
  project does not do).
- Design details: `reports/pcap_analysis.md` and
  `reports/part10_pcap_analysis.md` (Part 10 finalization).
- Part 10: PCAP analysis now prints an explicit
  `MODE: OFFLINE | RESPONSE MODE: DRY_RUN` banner, routes compatible
  attacks through the existing Part 7 response engine (simulated only),
  stores detections **with** their response fields via the repository,
  and cross-checks the model metadata's feature count before any
  prediction. Real captures currently stop at the documented feature
  INCOMPLETE gate — the honest behavior, never fabricated features.

## Part 7 — Detection + Controlled Response

The detection engine now uses the actual Part 6 winning model
(`models/xgboost_optimized.joblib`), and a controlled response layer
sits on top. DRY_RUN is the default and the only shipped mode — no real
firewall/network modification ever happens.

```powershell
# Detect + respond + optionally store (DRY_RUN only)
python -m src.response.response_engine --input data\sample\development_sample.csv
python -m src.response.response_engine --input data\sample\development_sample.csv --output reports\detection_sample.csv --store

# Plain detection with the optimized model (response not applied)
python -m src.detection.detector --input <authorized.csv> --output reports\detection_sample.csv

# Tests
python -m pytest tests -q
```

Notes:

- Response policy: probability < 0.50 -> NO_ACTION; ATTACK < 0.80 ->
  ALERT_ONLY; >= 0.80 -> DRY_RUN_BLOCK (simulated). Thresholds are
  configurable in `src/response/policies.py` and reuse validated values
  (0.50 from Part 6; 0.80 from the severity config).
- `--mode AUTHORIZED` is refused: this build ships no adapter, and
  nothing may silently perform a real blocking action.
- Response columns were added to the database with a safe additive
  migration — existing detection data is preserved.
- Design details: `reports/part7_detection_response.md`.

## Part 8 — Database finalization

The database layer now validates every record before insert
(probability in [0, 1], binary labels, ISO timestamps, validated
response action/mode/status combinations), exposes response and
attack-probability queries/statistics, and adds two response indexes.
The migration stays idempotent and non-destructive — running
`initialize_database()` on an existing database only adds what is
missing.

```powershell
python -c "from database.connection import initialize_database; print(initialize_database())"
python -m pytest tests -q
```

Design, integrity rules and measured performance:
`reports/part8_database.md`.
