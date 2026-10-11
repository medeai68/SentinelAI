# SentinelAI — Final Research Report

## Abstract

This report documents SentinelAI, a defensive, research-oriented
network intrusion detection and threat analysis system built end-to-end
on public data. Using a three-file subset of CIC-IDS2017 (904,877 raw
flows, 7 classes), a leakage-safe preprocessing pipeline produced
662,486 training and 165,622 untouched test flows over 70 features.
Logistic Regression, Random Forest and XGBoost were compared under
stratified 5-fold cross-validation (seed 42) with class-imbalance
handling; the tuned XGBoost model achieved, on the untouched test set,
F1 0.99824, recall 0.99868, ROC-AUC 0.99990, with 5 false positives and
3 false negatives. The model was deployed inside a validated detection
engine and a **simulation-only (DRY_RUN) controlled response layer**,
with SQLite persistence, a five-page Streamlit dashboard, and an
offline PCAP analyzer featuring an honest feature-compatibility gate.
Final validation recorded 251 passing tests, 65% coverage, and clean
leakage, security, database, and artifact-integrity audits. Results
reflect a single lab dataset; no external validation, real blocking, or
real-time capability is claimed.

## 1. Introduction

Network intrusion detection sits at an awkward intersection: attacks
are rare, benign traffic is overwhelming, and evaluation mistakes
(leakage, imbalanced-data shortcuts) are easy and persuasive. This
project builds the complete defensive chain — dataset, ML training,
detection, controlled response, storage, dashboard, offline PCAP
analysis — while enforcing two disciplines: **no fabricated results**
and **no real network actions**. Every number cited here comes from an
executed run recorded in the project's reports.

## 2. Problem Statement

Given flow-level network features, can standard supervised learning
separate benign from malicious traffic at a quality that is meaningful
for defense (high attack recall, controlled false positives), and can
the resulting detector be embedded in a response architecture that is
useful yet cannot cause harm in its shipped configuration?

## 3. Objectives

1. A reproducible, leakage-safe ML pipeline on a public benchmark.
2. Honest, imbalance-aware evaluation with an untouched test set.
3. A detection engine usable offline over stored or captured-parsed
   flows, with structured, auditable outputs.
4. A controlled response layer that is simulation-first and
   authorization-gated.
5. Persistence and visualization for research demonstration.
6. Comprehensive validation of safety, integrity and reproducibility.

## 4. Related/Background Concepts (concise)

Flow-based NIDS features (CICFlowMeter-style statistics) are the
standard tabular representation for ML intrusion detection;
CIC-IDS2017 is a widely used benchmark with documented quality caveats
(duplicates, infinite values, imbalance). Classic practice combines
tree ensembles and linear baselines under stratified cross-validation;
class imbalance is handled through class weighting (preferred here over
resampling, which was deliberately not applied). Safe automation
practice separates detection from action and stages response behind
explicit authorization — the design principle SentinelAI follows.

## 5. System Architecture

Full diagrams: `reports/final_architecture.md`. In brief: dataset →
inspection → preprocessing (split-first) → baselines → CV tuning →
optimized XGBoost → detection engine → controlled response (DRY_RUN) →
SQLite → dashboard, plus an offline PCAP path through a compatibility
gate into the same detection/response/storage components.

## 6. Dataset

**CIC-IDS2017** (CIC/UNB; citation in §Attribution below). Files
actually used and their measured properties:

| File | Rows | Columns |
| --- | ---: | ---: |
| Tuesday-WorkingHours.pcap_ISCX.csv | 445,909 | 79 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 170,366 | 79 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288,602 | 79 |

904,877 raw flows total; 7 observed labels; BENIGN 98.63% of cleaned
data. Full inspection values: `reports/dataset_inspection.md`.

## 7. Data Preprocessing

Measured on the real data: 76,769 duplicate rows removed (828,108
cleaned); 841 infinite values ("Infinity" literals in `Flow Bytes/s` /
`Flow Packets/s`) replaced with NaN, then median-imputed; empty and
constant columns dropped with documented reasons; object columns
numeric-coerced where ≥95% parseable; labels normalized (lossy en-dash
U+FFFD → "-", documented). **Split first:** 80/20 stratified,
`random_state=42`; imputer and scaler fitted on the training split only
(662,486 / 165,622 rows, 70 final features); the test set is only
transformed. Artifacts: preprocessor, label encoder, dual feature-name
metadata, label mapping. Validation reported zero problems.

## 8. Machine Learning Methodology

- **Models:** Logistic Regression (`liblinear`/`lbfgs` searched,
  `max_iter=2000`), Random Forest (100–400 trees searched), XGBoost
  (histogram trees; `scale_pos_weight` 72.0817 computed from the
  training set).
- **Imbalance handling:** class weights (`balanced` /
  `balanced_subsample`) for LR/RF; no resampling/SMOTE (deliberate).
- **Selection protocol:** RandomizedSearchCV, 10 sampled candidates ×
  stratified 5-fold CV **on the training set only**, scoring = attack
  F1 (justified over accuracy), seed 42; `n_iter` reduced from 30 to 10
  for this machine (documented in `config/model_config.py`).
- **Final evaluation:** each selected configuration re-fitted on the
  full training set, evaluated once on the untouched test set.
- **Metrics:** accuracy, precision, recall, F1, ROC-AUC,
  confusion-matrix counts, FPR, FNR — all for the ATTACK class.

## 9. Experimental Results

### Baseline (Part 5, test set)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.96665 | 0.28991 | 0.99206 | 0.44870 | 0.99719 |
| Random Forest | 0.99990 | 0.99911 | 0.99338 | 0.99624 | 0.99975 |
| XGBoost | 0.99996 | 0.99824 | 0.99868 | 0.99846 | 0.99998 |

### Optimized (Part 6, test set)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.99673 | 0.96396 | 0.79082 | 0.86885 | 0.99757 |
| Random Forest | 0.99991 | 0.99823 | 0.99515 | 0.99669 | 0.99975 |
| **XGBoost** | **0.99995** | **0.99780** | **0.99868** | **0.99824** | **0.99990** |

**No improvement is invented:** XGBoost's optimized F1 (0.99824) is
within noise of its strong baseline (0.99846); RF improved slightly
(0.99624 → 0.99669); LR improved substantially in F1 (0.44870 →
0.86885) by trading its baseline's near-total recall (0.99206) for
precision (0.28991 → 0.96396). Full CV tables:
`reports/cv_results/*.csv`.

## 10. Model Selection

Criterion (stated before final evaluation): highest attack F1 on
training/CV results, then attack recall, then lowest FPR.
**XGBoost** won with the best CV F1 (0.9989; RF 0.9975; LR 0.8676) and
the best operational error profile on the untouched test set —
2,263 TP, 163,351 TN, **5 FP, 3 FN** (FNR 0.13%, FPR 0.0031%).
Artifact: `models/xgboost_optimized.joblib` (SHA-256
`836afdda…f39a2`, unchanged through validation).

## 11. Threat Detection Engine

`src/detection/`: input validation against the fitted preprocessor's
own feature schema (with the same column normalization Part 4 applied),
transform-only preprocessing (never refit), XGBoost prediction with
probability, severity classification (LOW/MEDIUM/HIGH — an
interpretation layer), and structured `DetectionResult` objects
(prediction, attack probability, confidence, severity, model
name/version, timestamp, flow id, status, errors). Invalid rows produce
structured error results — never arbitrary fill values.

## 12. Controlled Response

Actions: `NO_ACTION` (below the validated 0.50 detection threshold),
`ALERT_ONLY` (attack below the 0.80 high-confidence threshold),
`DRY_RUN_BLOCK` (**simulated** block, the default for high-confidence
attacks), `BLOCK_REQUESTED` (reachable only in AUTHORIZED mode with an
explicitly supplied, isolated adapter — **not shipped**; the engine
refuses to construct without one). In DRY_RUN the engine never calls an
executor (tested across the probability grid).

> **SentinelAI does not perform real firewall or network blocking in
> the current implementation.** `DRY_RUN_BLOCK`/`SIMULATED` documents
> what a response *would* do. Real end-to-end evidence: 73
> high-confidence attacks → 73 simulated dry-run blocks, 0 requests,
> 0 authorized actions.

## 13. Database Architecture

SQLite behind a single repository (`database/`): two tables
(`models`, `detection_events` with five response columns added by an
additive idempotent migration), parameterized SQL, transactional
all-or-nothing batch inserts, insert-time integrity validation
(probability range, binary labels, ISO timestamps, validated
response action/mode/status with action-status consistency), new
response indexes (created post-migration for old-database safety),
and honest statistics (`dry_run_block_count ≡ simulated_count`,
separate `block_requested`/`authorized`/`failed`/`skipped`).
Current real contents: 4,996 detections, 1 model, 73 ≡ 73 simulated,
0 authorized. Performance (10,000-row benchmark, temporary database):
insert 109 ms; queries 3–8 ms.

## 14. Dashboard

Streamlit, five pages (Overview, Threat Detections, Analytics, Models,
System Information) reading exclusively through the service→repository
chain (no SQL in the UI). Response monitoring is explicitly labelled as
simulation (banner + chart annotations); the detections table exposes
response fields plus filters for label, severity, attack/benign,
response action/status and date range. Empty states are truthful.
Validation: headless health `ok`, HTTP 200, all five pages executed
against the real database. No browser-visual testing was performed.

## 15. Offline PCAP Analysis

Safe streaming reader (existence/extension/magic/size validation;
untrusted input; payloads never executed or stored) → bidirectional
5-tuple flow reconstruction (deterministic IDs) → feature extraction →
**compatibility gate** → detection and the Part 7 response engine only
when compatible → optional repository storage.

**Current limitation (documented, not hidden):** the pipeline extracts
**13 reliable extractable features**, of which **11 overlap the
70-feature model schema** — therefore **full compatible inference is
not currently possible from arbitrary PCAPs**. A real-model run over a
5,000-packet capture reported `INCOMPLETE (59 of 70 required features
missing)`, `Detection not executed`, zero predictions forced.

## 16. Testing & Validation

```
python -m pytest tests -q → 251 passed, 0 failed, 0 skipped
Coverage: 65% (2,938 statements) — reports/test_coverage.txt
```

Part 11 verified: leakage audit (split-before-fit anchors, tuner
signature, label-free feature lists), reproducibility (seed 42
throughout; deterministic detection/flow IDs; honest note that the
904k-row pipeline was not re-run byte-for-byte), artifact integrity
(hashes recorded, unchanged), model loading in a clean process,
detection behavior (benign → NO_ACTION; attack → DRY_RUN_BLOCK),
response safety scans (all dangerous-pattern hits confined to test
patterns/docs), database integrity (0 violations on all invariants),
dashboard validation, PCAP safety scans, performance, portability,
dependency and git audits.

## 17. Performance

Measured (Windows 11, Python 3.14.5; offline pipeline — **no real-time
claim**): preprocessing 5,000×8 flows 151 ms; inference of the real
XGBoost model on 4,996 real flows 91 ms (~54,800 flows/s); SQLite
insert of 10,000 detections in one transaction 109 ms (queries 3–8 ms);
dashboard statistics 3–7 ms; offline PCAP analysis of 5,000 packets
(→ 50 flows) 889 ms.

## 18. Security & Safety Boundaries

Defensive-only, enforced by automated validation scans: no
subprocess/shell/eval/exec, no sockets or live capture, no packet
injection, no firewall tooling, no external communication, no secrets,
parameterized SQL only, read-only dashboard, untrusted PCAP handling.
Residual risks documented: pickle-based model artifacts
(trusted-local loading), unauthenticated local dashboard.

## 19. Limitations

Single lab dataset with no external validation; extreme class
imbalance; PCAP feature-compatibility gate (§15); SQLite
single-writer; local unauthenticated dashboard without browser-visual
testing; Windows-tested only (Linux untested); pickle-based artifacts;
65% coverage with experiment drivers exercised by real runs.
Full list: `reports/limitations_and_future_work.md`.

## 20. Future Work

External validation datasets; a validated CICFlowMeter-compatible
feature extractor to close the PCAP gate; browser-based UI tests;
database retention policy; Linux CI; higher unit coverage; stronger
model serialization/trust strategy; broader multi-class validation;
richer host/context features under strict leakage controls.

## 21. Conclusion

SentinelAI demonstrates that a rigorously staged, honesty-first
pipeline can carry standard ML from public-flow features to a strong
detector on CIC-IDS2017 (untouched-test F1 0.99824, 3 misses in
165,622 flows) and embed it in a defensive architecture whose riskiest
capability — response — ships as simulation only. The system's value
as a research artifact lies as much in what it refuses to do
(no fabricated numbers, no forced PCAP predictions, no real blocking,
no hidden limitations) as in its measured results.

## Attribution

CIC-IDS2017 (CIC, University of New Brunswick), citation: Sharafaldin,
Habibi Lashkari & Ghorbani, *Toward Generating a New Intrusion
Detection Dataset and Intrusion Traffic Characterization*, ICISSP
2018. Details: `reports/dataset_attribution.md`.
