# SentinelAI — Final Architecture

## Training/analysis path

```
CIC-IDS2017 (3 official per-day CSVs, data/raw/ — git-ignored)
   ↓  src/data/inspect_dataset.py          inspection, summary, sample
   ↓  src/preprocessing/pipeline.py
        clean (names, duplicates, infinities, types)
        → 80/20 stratified split (seed 42)          ← SPLIT FIRST
        → fit imputer/scaler on TRAIN ONLY → transform both
        → artifacts: preprocessor.joblib, label_encoder.joblib,
          feature_columns.json (input + processed names), label_mapping.json
   ↓  src/training/train_binary.py          baselines (LR, RF)  [Part 5]
   ↓  src/training/model_comparison.py      RandomizedSearchCV
        (stratified 5-fold CV on TRAIN ONLY, scoring = attack F1)
        → optimized artifacts: models/*_optimized.joblib      [Part 6]
        → single final evaluation on the untouched test set
   ↓  src/evaluation/                       metrics, ROC, confusion,
                                            feature importance, threshold
```

## Serving/defensive path (offline)

```
Detection inputs:
  (a) an authorized flow-feature CSV (raw CIC-style columns)
  (b) an authorized PCAP file (offline)

(a) CSV →  src/response/response_engine.py (orchestrating CLI)
(b) PCAP → src/network/pcap_pipeline.py
        pcap_reader      safe streaming file reading
        flow_extractor   bidirectional 5-tuple flows, deterministic ids
        feature_extractor 13 reliable CIC-named features
        compatibility gate  vs model schema + metadata feature count
            ├─ INCOMPLETE → status "feature set incomplete",
            │               NO predictions forced, report written
            └─ COMPATIBLE → continue
   ↓  src/detection/detector.py   ThreatDetector
        validate input against the fitted preprocessor's OWN schema
        preprocessor.transform (transform-only — never refit)
        optimized XGBoost predict + predict_proba
        → DetectionResult (prediction, attack_probability, severity,
                           model name/version, timestamp, flow_id)
   ↓  src/response/response_engine.py   ResponseEngine (REUSED — no
   │    separate PCAP response mechanism exists)
        policy: <0.50 NO_ACTION · ATTACK<0.80 ALERT_ONLY ·
                ≥0.80 DRY_RUN_BLOCK (SIMULATED) | BLOCK_REQUESTED
                (AUTHORIZED only — requires an external adapter;
                 not shipped; the engine refuses without one)
        DRY_RUN never calls an executor — verified by tests
   ↓  database/repository.py   Repository (the ONLY DB interface)
        insert_model / insert_detections (one transaction)
        DetectionRecord.from_detection_and_response
        integrity validation before SQL
   ↓  SQLite  database/sentinelai.db (git-ignored)
   ↓  dashboard/  DashboardService → Repository → SQLite
        five Streamlit pages (read-only)
```

## Trust & safety boundaries

```
UNTRUSTED                 TRUSTED-LOCAL              NEVER PRESENT
PCAP bytes, CSV data  →   fitted artifacts       →   real firewall /
(validated, parsed as     (preprocessor, model,      network actions,
data only; payloads        metadata — pickle-         live capture,
never executed/stored)     based, trusted local        attack tooling
                           sources only)
```

- Response staging: detection ≠ recommended response ≠ simulated
  response ≠ actual authorized response. Only the last one could touch
  a network, and it is gated behind an explicitly supplied, isolated
  adapter that this project does not ship.
- The dashboard is read-only with respect to the database and contains
  no blocking controls.
- Automated validation tests enforce: no write-SQL in the dashboard, no
  live-capture/network APIs in `src/network/`, no executor calls in
  DRY_RUN, no dangerous patterns (subprocess, shell, eval/exec, raw
  sockets, firewall tooling) anywhere in operational code.

## Component map

| Component | Module | Responsibility |
| --- | --- | --- |
| Dataset tooling | `src/data/` | loading, inspection, quality checks, sample |
| Preprocessing | `src/preprocessing/` | cleaning, encoding, split, artifacts, reports |
| Training | `src/training/` | baselines, tuning, comparison, artifact utils |
| Evaluation | `src/evaluation/` | metrics, reports, figures |
| Detection | `src/detection/` | schema validation, transform, predict, format |
| Response | `src/response/` | policy, actions, engine, orchestration CLI |
| Network (offline) | `src/network/` | PCAP reading, flows, features, gate, CLI |
| Database | `database/` | schema, migration, repository, record models |
| Dashboard | `dashboard/` | data service, pages, components |
| Config | `config/` | settings, experiment config, detection config |
