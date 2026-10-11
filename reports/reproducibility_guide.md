# SentinelAI — Reproducibility Guide

## Environment (as validated)

- Windows 11 (PowerShell 7); Python **3.14.5** in a project-local `.venv`.
- Dependencies (`requirements.txt`): pandas 3.0.6, numpy 2.5.3,
  scikit-learn 1.9.1, joblib 1.6.0, python-dotenv 1.2.4,
  matplotlib 3.11.2, pytest 9.1.1, pytest-cov 7.1.0, xgboost 3.4.1,
  streamlit 1.65.0, scapy 2.8.0. SQLite from the standard library.
- **Linux was not tested** — Windows is the only verified platform.

## Random seed

`random_state = 42` everywhere: the Part 4 split, model constructors,
stratified 5-fold CV, RandomizedSearchCV, and the Part 6 threshold
slice. The Part 4 split is created **once** and reused by Parts 5–7 —
no downstream component re-splits.

## Dataset requirements

The official CIC-IDS2017 per-day CSVs (see
`reports/dataset_acquisition.md` for exact download steps through
CIC's registration portal). Place them directly in `data/raw/`
(git-ignored). The three files used in this project: Tuesday
(445,909 rows), Thursday morning WebAttacks (170,366), Thursday
afternoon Infiltration (288,602).

## Reproduction steps, in order

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python -m src.data.inspect_dataset        # writes dataset summary + sample + chart
python -m src.preprocessing.pipeline      # processed data + artifacts + figures
python -m src.training.train_binary       # Part 5 baselines
python -m src.training.model_comparison   # Part 6 tuning + optimized models
python -m pytest tests -q                 # 251 tests expected to pass
```

Persistence and serving (optional):

```powershell
python -m src.response.response_engine --input data\sample\development_sample.csv --store
streamlit run dashboard/app.py
python -m src.network.pcap_pipeline --input <authorized.pcap>
```

## Where results land

- Processed data: `data/processed/train.csv`, `test.csv`.
- Artifacts: `models/` (models + metadata), `models/preprocessing/`.
- Reports/figures: `reports/` (summaries, CV tables, metrics,
  threshold analysis, feature importance, figures).
- Database: `database/sentinelai.db` (created by `--store`).

## Verified reproducibility vs not re-run

**Verified:**
- Two pipeline runs on a deterministic sample produced byte-identical
  `train.csv` (SHA-256 equal) — seed/split determinism.
- Identical tuning runs return identical best parameters/scores.
- Detection output is deterministic; PCAP flow IDs are deterministic.
- Artifact hashes are recorded and unchanged (see
  `reports/part11_validation_report.md` §6).

**Not re-run in Part 11 (stated honestly):**
- The complete 904,878-row pipeline was executed once to produce the
  real results and was **not** re-executed byte-for-byte during
  validation; ordering/seed configuration was verified from code and
  the recorded run outputs instead.
- Model quality depends on the dataset revision served by CIC today;
  exact row counts could vary if the official files change.

## Test behavior

```
python -m pytest tests -q
→ 251 passed, 0 failed, 0 skipped (36 benign sklearn warnings)
```
The real-database read-only test is skipped automatically when
`database/sentinelai.db` does not exist (fresh clone) — the suite still
passes.
