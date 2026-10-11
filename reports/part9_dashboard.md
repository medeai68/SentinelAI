# Part 9 — Streamlit Dashboard Finalization

Status: complete. All results below are actual, verified on 2026-10-07
against the real Part 8 database (4,996 detection records).

## 1. Dashboard architecture

```
Streamlit UI (dashboard/app.py -> dashboard/pages.py, components/)
        ↓  no SQL anywhere in the UI
DashboardService (dashboard/services/dashboard_service.py)
        ↓
Repository (database/repository.py)          — the only normal DB interface
        ↓
SQLite (database/sentinelai.db)
```

- `dashboard/app.py` — app config, sidebar refresh button, navigation only.
- `dashboard/pages.py` — the five page functions (importable and
  testable; no navigation side effects).
- `dashboard/components/` — metric cards, matplotlib charts, table.
- `dashboard/services/dashboard_service.py` — all data access, catches
  sqlite errors into honest empty states, never writes.
- Part 9 repository additions: filtered joined queries
  (attack/response/date-range), `get_models()`,
  `get_response_status_counts()` — all parameterized, so the UI never
  holds SQL.

## 2. Pages

1. Overview · 2. Threat Detections · 3. Analytics · 4. Models ·
5. System Information. Existing functionality preserved; each page now
carries a concise description caption.

## 3. Metrics (Overview)

Row 1: Total detections, Attack detections, Benign detections,
Attack %, High severity, Active model.
Row 2 (response): Alerts (ALERT_ONLY), **Dry-run responses** (help text:
"DRY_RUN_BLOCK: a block was SIMULATED. No real firewall/network change
was made."), Failed responses, **Real block requests** (help: requires
AUTHORIZED mode and a real adapter; none shipped).
Empty database -> the message "No detection data available…" is shown
**instead of** metric cards or charts (no fake numbers).

## 4. Detection table

Columns: Timestamp, Flow ID, Prediction, Label, Attack Probability,
Severity, Model, Status, Response Action, Response Mode, Response
Status. Details panel (per selected event) shows the full record
including response reason/timestamp, with the note that `prediction` is
the model output and that `DRY_RUN_BLOCK` means a simulated block.

## 5. Filters (Threat Detections)

Label · Severity · Traffic (attacks only / benign only) · Response
action (all four states) · Response status (all six states) · optional
inclusive date range. All filters go through
`DashboardService.detections_frame(...)` -> repository (parameterized
SQL). "No detections match the current filters." empty state.

## 6. Response monitoring (Analytics)

- Explicit banner: **"Response Mode: DRY_RUN — no real firewall or
  network changes are performed. `DRY_RUN_BLOCK` entries are simulated
  defensive actions, never actual blocks."**
- Response metric cards (shared with Overview).
- Response-action bar chart titled *"Response actions - DRY_RUN
  simulation (no real blocking)"* with axis labels
  `DRY_RUN_BLOCK (simulated)` and `BLOCK_REQUESTED (real, requires
  adapter)` — the distinction is visual as well as textual.
- Response-status table with per-status counts and meanings (NONE /
  LOGGED / SIMULATED / AUTHORIZED / FAILED / SKIPPED, plus legacy
  UNKNOWN), derived from actual `GROUP BY response_status` counts.
- Caption clarifying SIMULATED vs AUTHORIZED.

## 7. Analytics

Detection distribution (benign vs attack), severity distribution,
response monitoring (above), timeline (counts over time), attack
probability histogram (from actual stored probabilities; honest caption
when none exist), detections per model. Charts are only drawn when
data exists — an empty database shows the empty state instead.

## 8. Models

- Model registry table (id, name, version, algorithm, feature count,
  active, created) from the actual `models` table; the active model is
  highlighted (`Active model: xgboost_optimized …`).
- Actual Parts 5/6 evaluation result files listed and displayed
  unchanged (nothing recalculated); explicit message when no report
  files exist.
- Feature importance for random_forest / xgboost with the
  association-not-causation caption; explicit message when the report
  file is missing.

## 9. System information

Project + version, Python version, database availability and
**relative** path (`database\sentinelai.db` — no local filesystem
layout exposed), detection record count, model record count, active
model, response mode (DRY_RUN), safety mode text, model artifacts,
preprocessing artifact. No secrets or environment variables.

## 10. Refresh behavior

Cached reads with short TTLs (30 s data, 60 s system status) plus TWO
manual refresh controls (sidebar button + detections-page button) that
clear the cache immediately. No polling.

## 11. Empty / error states

Empty database -> "No detection data available…" (Overview, Detections,
Analytics). Missing database -> clear error message, no stack trace.
Missing report files -> explanatory info messages. Missing feature
importance -> explanatory info message. Unknown/legacy response values
-> rendered as `UNKNOWN` with meaning text. Optional charts render
through a guarded helper — a failing visualization shows a warning
instead of crashing the page. Real-database read verified to leave row
counts unchanged (test).

## 12. Security boundaries

Automated validation tests (in the suite) assert that dashboard sources
contain: no raw SQL writes (`INSERT/UPDATE/DELETE/DROP/ALTER`), no
subprocess/os.system, no socket/requests/urllib imports, no
firewall-tooling references. The dashboard is read-only with respect to
the database and provides no controls that perform real network
blocking (the only "actions" are filters, refresh, and display).

## 13. Testing

`python -m pytest tests -q` -> **237 passed, 0 failed** (was 223 after
Part 8; +14 Part 9 tests). New/updated coverage: service filters
(attack/response/date-range), response status counts and rows (stable
order, meanings), models registry, extended system status (relative
path, response mode, safety text), real-database read-only invariants
(skipped if DB absent), component chart transforms (incl. the
simulation labels present on the response chart), detection table
columns, and the two dashboard security scans.

Two real bugs were found by the validation process itself and fixed:
1. `page_detections` referenced a statistics key that only exists in
   system status (`KeyError`) — would have crashed the page in the real
   app; found by the bare-mode page exercise.
2. The new dashboard-security regex initially flagged the UI label
   "Real block requests" as the `requests` library — tightened to
   import-based detection (a test-precision fix, not a code defect).

## 14. Headless validation (actual results)

- Streamlit server started headless: health endpoint returned `ok`,
  main page HTTP **200**, clean shutdown.
- All five page functions were executed against the **real database** in
  bare mode: `page_overview: OK · page_detections: OK ·
  page_analytics: OK · page_models: OK · page_system: OK`.
- Real-data read confirmed: **4,996 detections · 73 attacks ·
  73 dry-run blocks ≡ 73 SIMULATED · 0 authorized · 0 block requests ·
  1 model (active: xgboost_optimized)** — matching the Part 8 state
  exactly.
- Visual/browser rendering was NOT screenshot-verified (no browser
  automation) — stated honestly.

## 15. Limitations

- No browser-automation tests; page verification is via bare-mode
  execution + HTTP health checks, not visual inspection.
- Local single-user dashboard, no authentication — run on trusted
  machines only.
- Filters cap at 500 rows for the table view (display limit, not a data
  limit).
- Charts reflect only data stored in the local database.
