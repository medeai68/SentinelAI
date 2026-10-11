# SentinelAI

**AI-Powered Network Intrusion Detection and Threat Analysis System**

A defensive, research-oriented machine-learning NIDS: it trains and
tunes supervised models on the public CIC-IDS2017 dataset, runs a
leakage-safe detection pipeline, applies a **simulated** (DRY_RUN)
response policy, stores results in SQLite, visualizes them in a
Streamlit dashboard, and can analyze authorized PCAP files offline.

> **Scope:** defensive analysis of public/authorized data only. SentinelAI
> performs **no real firewall or network blocking**, no live packet
> capture, and no offensive functionality. See
> [Security Boundaries](#security-boundaries).

## Overview

SentinelAI answers a concrete research question: *can standard machine
learning separate benign from malicious network flows, and how far can
an honest, leakage-free pipeline carry that result toward a usable
defensive tooling prototype?* The project ships real, measured results
on a real dataset (904,877 raw flows → 662,486 train / 165,622 test),
3 trained models, a proven detection engine, a controlled response
layer, a database, a dashboard, and an offline PCAP analyzer — all
under a strict no-fabrication, defensive-only policy.

## Research Objective

- Build a complete, reproducible ML intrusion-detection pipeline:
  dataset → inspection → preprocessing → baselines → tuning → final
  evaluation → detection → controlled response → storage → dashboard.
- Quantify realistic detection quality on CIC-IDS2017 with proper
  leakage controls (fit-on-train-only, untouched test set).
- Demonstrate that response automation can be staged safely:
  simulation-first (DRY_RUN), with real actions gated behind explicit
  authorization that is *not* shipped.

## Key Features

- **Real ML pipeline** on the actual CIC-IDS2017 subset (3 official
  per-day files; 904,877 flows; 7 classes).
- **Three models compared** — Logistic Regression, Random Forest,
  XGBoost — under 5-fold stratified cross-validation (`random_state=42`).
- **Optimized winner:** XGBoost — test **F1 0.99824**, recall 0.99868,
  ROC-AUC 0.99990, **FP 5 / FN 3** on 165,622 untouched test flows.
- **Leakage-safe by construction:** split first, fit preprocessing on
  training data only, tune without the test set, evaluate once.
- **Threat detection engine** with schema validation, probability
  output, severity classification and deterministic results.
- **Controlled response policy** — `NO_ACTION`, `ALERT_ONLY`,
  `DRY_RUN_BLOCK`, `BLOCK_REQUESTED` — **DRY_RUN is the default and
  only shipped mode**.
- **SQLite database layer** — parameterized SQL, transactional batch
  inserts, integrity validation, safe additive migrations.
- **Streamlit dashboard** (5 pages) over the real database.
- **Offline PCAP analysis** with an honest feature-compatibility gate.
- **251 tests, 0 failures**, including security/safety scans.

## System Architecture

```
CIC-IDS2017 (3 official CSVs)
   ↓ inspection
   ↓ preprocessing (clean → split 80/20 → fit on train only)
   ↓ baseline models → hyperparameter optimization (5-fold CV, seed 42)
   ↓ optimized XGBoost (models/xgboost_optimized.joblib)
   ↓ threat detection engine  →  DetectionResult
   ↓ controlled response policy → DRY_RUN (simulated only)
   ↓ SQLite repository → Streamlit dashboard (5 pages)

Authorized PCAP (offline) → reader → flows → features → compatibility
gate → detection → DRY_RUN response → SQLite → dashboard
```

Full detail: [reports/final_architecture.md](reports/final_architecture.md).

## Machine Learning Pipeline

Parts 4–6 executed on the real dataset on 2026-10-07:

| Stage | Result |
| --- | --- |
| Raw flows (3 official files) | 904,877 × 79 columns |
| Duplicates removed | 76,769 |
| Cleaned records | 828,108 |
| Train / test split (stratified, seed 42) | 662,486 / 165,622 |
| Final features | 70 |

## Dataset

**CIC-IDS2017** (Canadian Institute for Cybersecurity, University of
New Brunswick). Files used (official per-day CSV set):

| File | Rows | Size |
| --- | --- | --- |
| Tuesday-WorkingHours.pcap_ISCX.csv | 445,909 | 128.8 MB |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 170,366 | 49.6 MB |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288,602 | 79.3 MB |

Classes observed (7): BENIGN (98.63% of cleaned data), FTP-Patator,
SSH-Patator, Web Attack - Brute Force, Web Attack - XSS, Web Attack -
Sql Injection, Infiltration. The raw data is **not committed to Git**
(see [Dataset Attribution](#dataset-attribution) for how to obtain it).

## Data Preprocessing

- Column-name normalization (raw names contain spaces and a cp1252
  en-dash in Web-Attack labels → normalized in memory, documented).
- Duplicate rows removed (76,769); infinite values (the known
  CIC-IDS2017 "Infinity" literals in Flow Bytes/s and Flow Packets/s)
  replaced with NaN and imputed with the **training-set median**;
  empty/constant columns dropped with documented reasons; numeric
  coercion where ≥95% of values parse.
- **Split first** (80/20 stratified, `random_state=42`); imputer and
  scaler fitted on the training split only — the test set is only
  transformed.
- Identifier/metadata columns (Flow ID, IPs, timestamp, CSV index) are
  removed for schemas that contain them, with reasons recorded in
  `reports/feature_decisions.md`.

## Model Development

Baselines (Part 5) and optimized models (Part 6) were trained on the
real processed data; class imbalance (binary train split: 653,421
benign / 9,065 attack) was handled via class weights
(`balanced` / `balanced_subsample`) and XGBoost `scale_pos_weight`
(72.08), documented rather than hidden.

**Untouched test set (165,622 flows), attack-class metrics:**

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression (optimized) | 0.99673 | 0.96396 | 0.79082 | 0.86885 | 0.99757 |
| Random Forest (optimized) | 0.99991 | 0.99823 | 0.99515 | 0.99669 | 0.99975 |
| **XGBoost (optimized)** | **0.99995** | **0.99780** | **0.99868** | **0.99824** | **0.99990** |

Confusion matrix (XGBoost): TP 2,263 · TN 163,351 · FP 5 · FN 3 ·
FPR 0.0031% · FNR 0.13%. Full tables, baselines, CV results, threshold
analysis and feature importance: [reports/final_model_results.md](reports/final_model_results.md).

## Model Comparison

30 candidates per model (10 sampled × 5 folds after the documented
`n_iter` reduction) were scored on **attack F1** in training-only
cross-validation. Best CV F1: Logistic Regression 0.8676 (liblinear,
C=10, no class weighting), Random Forest 0.9975 (200 trees, depth 30,
sqrt), XGBoost 0.9989 (200 trees, depth 3, lr 0.3, subsample 0.8).
Full per-combination results: `reports/cv_results/*.csv`.

## Optimized Model

**`models/xgboost_optimized.joblib`** (+ metadata in
`models/metadata/`) — selected strictly on training/CV results by the
stated criterion: highest attack F1, then attack recall, then lowest
false-positive rate. Selection stopped at CV; the test set was touched
once for the final comparison. SHA-256:
`836afdda…f39a2` (recorded, unchanged since training).

## Threat Detection

`src/detection/` — raw flow features → the fitted Part 4 preprocessing
artifact (transform-only, never refit) → optimized XGBoost →
`DetectionResult` with prediction, attack probability, severity (LOW/
MEDIUM/HIGH interpretation layer), model name/version, timestamp and
flow id. Invalid input yields structured error results; nothing is
silently filled with arbitrary values.

## Controlled Response

`src/response/` maps each detection to a response action under a
configurable policy (thresholds reuse validated values: detection 0.50
from the Part 6 threshold analysis; high-confidence 0.80 from the
severity configuration):

| Situation | Action | Status |
| --- | --- | --- |
| Below the detection threshold | `NO_ACTION` | NONE / SKIPPED |
| ATTACK below high confidence | `ALERT_ONLY` | LOGGED |
| High-confidence ATTACK, **DRY_RUN** (default) | `DRY_RUN_BLOCK` | **SIMULATED** |
| High-confidence ATTACK, AUTHORIZED | `BLOCK_REQUESTED` | only via an explicit adapter — **not shipped** |

> **SentinelAI does not perform real firewall or network blocking in the
> current implementation.** `DRY_RUN_BLOCK`/`SIMULATED` means the system
> *simulated* what a response would do and logged it. AUTHORIZED mode
> refuses to run without an explicitly supplied, isolated adapter.

## Database

SQLite (`database/sentinelai.db`, git-ignored) through a single
repository layer: `models` + `detection_events` (with five response
columns added by a safe, idempotent additive migration), parameterized
SQL, transactional all-or-nothing batch inserts, insert-time integrity
validation (probability range, validated response states, action/status
consistency). Current real contents: **4,996 detections · 73 attacks ·
73 DRY_RUN_BLOCK ≡ 73 SIMULATED · 0 AUTHORIZED · 0 BLOCK_REQUESTED ·
1 model**.

## Dashboard

Streamlit, five pages — **Overview** (detection + response metric
cards, charts), **Threat Detections** (table with response columns;
filters for label, severity, attack/benign, response action, response
status, date range; per-event details), **Analytics** (distributions,
timeline, attack-probability histogram, response monitoring with an
explicit simulation banner), **Models** (registry with the active model
highlighted, actual saved evaluation results, feature importance),
**System Information** (environment/storage/safety — no secrets).

**Screenshots:** dashboard screenshots should be captured manually
before publication (no browser automation was used in this project;
no screenshots are bundled).

## Offline PCAP Analysis

`src/network/` — **OFFLINE · AUTHORIZED INPUT · DRY_RUN RESPONSE**:
safe streaming reader (validation, size limits, untrusted-data policy)
→ bidirectional 5-tuple flow reconstruction (deterministic IDs) →
feature extraction → **compatibility gate** → detection (only when
compatible) → Part 7 response engine → optional repository storage.

**Documented limitation (do not hide):** the pipeline extracts **13
reliable features**, of which **11 overlap the model's 70-feature
schema** — so full compatible inference is **not currently possible
from arbitrary PCAPs**. Incompatible captures end at the honest
`INCOMPLETE` result with no predictions forced (real-model run: 50
flows → 59/70 features missing → `Detection not executed`, reason
recorded in `reports/pcap_feature_compatibility.md`).

## Testing & Validation

```
python -m pytest tests -q
→ 251 passed, 0 failed, 0 skipped (36 benign sklearn warnings)
```

Coverage **65%** (`reports/test_coverage.txt`). Validated in Part 11:
leakage audit (PASS), reproducibility, artifact hashes, model loading
in a clean process, detection behavior, response safety scans, database
integrity (0 invariant violations), dashboard (headless health `ok`,
HTTP 200, all five pages execute), PCAP safety scans, performance,
portability, dependency and git audits. Full report:
[reports/part11_validation_report.md](reports/part11_validation_report.md).

## Security Boundaries

Defensive-only: no live capture, no scanning, no injection, no attack
generation, no malware, no credentials handling, no firewall/network
modification, no real blocking. PCAP files are untrusted input
(validated, never executed, payloads never stored/logged). SQL is fully
parameterized. The dashboard is read-only toward the database.
Automatic safety tests enforce all of the above
(`tests/validation/`). Details: [reports/security.md](reports/security.md).

## Performance

Measured (Windows 11, Python 3.14.5) — **no real-time claim**:

| Operation | Measured |
| --- | --- |
| Preprocessing (5,000×8 flows) | 151 ms |
| Inference, XGBoost, 4,996 real flows | 91 ms (~54,800 flows/s) |
| SQLite insert 10,000 detections (one transaction) | 109 ms |
| Dashboard statistics / frame(500) | 3–7 ms |
| Offline PCAP analysis, 5,000 packets → 50 flows | 889 ms |

## Limitations

See [reports/limitations_and_future_work.md](reports/limitations_and_future_work.md).
Headlines: CIC-IDS2017 is a 2017 lab dataset (no external validation);
class imbalance is extreme; the PCAP gate limits end-to-end PCAP
inference; SQLite is single-writer; the dashboard is local with no
authentication and was **not** browser-visually tested; Windows was
tested, **Linux was not**; joblib artifacts are pickle-based and must
be loaded only from trusted local sources. The Part 6 untouched-test
metrics remain the authoritative model-performance reference — the
1.00 match rate mentioned in older run logs refers to a development
sample that overlaps training data and is **not** a generalization
claim.

## Future Work

External validation datasets · a validated CICFlowMeter-compatible
feature extractor to close the PCAP gate · browser-based UI tests ·
database retention policy · Linux CI · higher unit coverage on
experiment drivers · stronger model-artifact trust/serialization
strategy · richer host/context features.

## Project Structure

```
SentinelAI/
├── src/         dataset tooling, preprocessing, training, evaluation,
│                detection, response, offline network analysis, utils
├── database/    schema, connection/migration, repository, record models
├── dashboard/   Streamlit app, page functions, components, data service
├── models/      trained artifacts + preprocessing artifacts (git-ignored)
├── config/      settings, experiment config, detection config
├── data/        raw (git-ignored) / processed (git-ignored) / sample
├── reports/     phase reports, audits, figures, model-results tables
├── tests/       unit suites + integration/ + validation/ safety scans
├── main.py · requirements.txt · README.md · DEVELOPMENT.md ·
│   CONTRIBUTING.md · .gitignore · .env.example
```

Details: [reports/project_structure.md](reports/project_structure.md).

## Installation

```powershell
cd <project root>
python -m venv .venv
.venv\Scripts\Activate.ps1        # PowerShell
# cmd:        .venv\Scripts\activate.bat
# Git Bash:   source .venv/Scripts/activate
pip install -r requirements.txt
```

If PowerShell blocks the activation script, do not change system
security settings — call the interpreter directly instead:
`.\.venv\Scripts\python.exe -m pytest tests -q` (documented in
[DEVELOPMENT.md](DEVELOPMENT.md)).

## Usage

```powershell
# Environment check
python main.py

# Tests
python -m pytest tests -q

# Dashboard (http://localhost:8501)
streamlit run dashboard/app.py

# Offline PCAP analysis (authorized local files only; DRY_RUN)
python -m src.network.pcap_pipeline --input <authorized.pcap> [--output flows.csv] [--store]
```

Full pipeline (requires the dataset in `data/raw/` — see
[DEVELOPMENT.md](DEVELOPMENT.md) for the download steps):

```powershell
python -m src.data.inspect_dataset          # inspect + development sample
python -m src.preprocessing.pipeline        # processed data + artifacts
python -m src.training.train_binary         # baselines
python -m src.training.model_comparison     # tuning + optimized models
python -m src.response.response_engine --input data\sample\development_sample.csv --store
```

## Testing

```
python -m pytest tests -q
```

Runs 251 tests across unit (`tests/*.py`), integration
(`tests/integration/`) and validation (`tests/validation/`) suites.

## Reproducibility

Seed 42 everywhere; the split is created once and reused; artifacts are
saved with metadata. Guide: [reports/reproducibility_guide.md](reports/reproducibility_guide.md).
Honest note: the full 904k-row pipeline was executed once for the real
results and was not re-executed byte-for-byte during validation (the
configuration was verified from code and recorded outputs).

## Dataset Attribution

**CIC-IDS2017** — Canadian Institute for Cybersecurity (CIC),
University of New Brunswick (UNB). Official page:
<https://www.unb.ca/cic/datasets/ids-2017.html> (downloads are provided
through CIC's registration portal). The dataset is publicly available
for researchers and **requires citation**:

> Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).
> *Toward Generating a New Intrusion Detection Dataset and Intrusion
> Traffic Characterization.* ICISSP 2018.

The official page states research availability with a mandatory
citation; **no formal license text/SPDX identifier was verified** —
do not assume one. See
[reports/dataset_attribution.md](reports/dataset_attribution.md).

## License

**No license file has been added to this repository yet.** A license
choice must be made before publication (the CIC-IDS2017 dataset terms
above are separate from the code license). TODO before publishing.

## Project Status

All planned development parts (1–12) are complete: foundation,
dataset tooling, preprocessing, baselines, model comparison and
optimization, detection engine, controlled response, database,
dashboard, offline PCAP analysis, full validation, and documentation.
The project is a validated research prototype — **not production-ready**
and not a real-time IDS.
