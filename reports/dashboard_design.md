# SentinelAI Dashboard Design (Part 9)

## Purpose

A professional Streamlit dashboard that visualizes **actual** SentinelAI
data — detection records from the Part 8 SQLite database and evaluation
results from the Part 5/6 reports. Nothing shown is fabricated: when
data or reports do not exist yet, the dashboard shows a clear empty
state.

## Architecture

```
SQLite (database/sentinelai.db)
        ↓ Repository (Part 8 — no SQL duplicated in the UI)
DashboardService (dashboard/services/dashboard_service.py)
        ↓  plain dicts / DataFrames
Streamlit UI (dashboard/app.py + dashboard/components/)
```

- `dashboard/services/dashboard_service.py` — the data layer. It
  deliberately does **not** import Streamlit, so it is fully
  unit-testable.
- `dashboard/components/metrics.py` — metric cards.
- `dashboard/components/charts.py` — matplotlib charts (no seaborn,
  default colors, legends where multi-series).
- `dashboard/components/tables.py` — detection table rendering.
- `dashboard/app.py` — page definitions and navigation.

## Pages

1. **Overview** — metric cards (total detections, attacks, benign,
   attack %, high severity, active model) plus BENIGN-vs-ATTACK,
   severity, over-time and per-model charts.
2. **Threat Detections** — filterable table (label, severity) of actual
   detection rows with per-event details. The model's `prediction` is
   clearly distinguished from a ground-truth label (the database does
   not store ground truth yet — documented in the UI).
3. **Analytics** — detections over time, per-model usage, severity
   distribution.
4. **Models** — actual evaluation metrics loaded from the saved Part
   5/6 result files (nothing recalculated), and model feature
   importance for Random Forest / XGBoost ("association within the
   fitted model, not causation").
5. **System Information** — database availability/path, active model,
   model artifacts, preprocessing artifact availability. No secrets or
   environment variables are shown.

## Data Sources

- Overview/detections/analytics: `database/sentinelai.db` via the
  Part 8 `Repository` (joined queries live in the repository, not in
  the UI).
- Models: `reports/optimized_model_results.json` (fallbacks:
  `baseline_model_results.json`, `model_results.json`) and
  `reports/feature_importance_{random_forest,xgboost}.csv`.
- System status: filesystem checks for the database, `models/*.joblib`
  and `models/preprocessing/preprocessor.joblib`.

## Refresh and Caching

Data accessors use `st.cache_data` with a 30-second TTL — repeated
queries are cheap, but new detections appear within half a minute, and
the "Refresh data" button clears the cache immediately.

## Error Handling

Missing database, empty database, missing result files, malformed JSON,
missing feature-importance CSVs and unavailable artifacts all produce
clear empty/error states — the dashboard never crashes with a stack
trace for normal missing-data situations.

## Limitations

- Local single-user dashboard (Streamlit defaults) — not a hardened
  multi-user service; run it only on trusted machines.
- No authentication or authorization layer.
- The database is currently empty and no model reports exist yet —
  all pages currently show their designed empty states (verified
  startup: health endpoint `ok`, main page HTTP 200).
- No live network integration; values reflect only detections that
  were actually stored.
