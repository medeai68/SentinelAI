"""SentinelAI dashboard pages (Part 9).

Page functions live here (importable/testable, no navigation side
effects); dashboard/app.py wires them into Streamlit navigation.

Rules kept throughout:
  * pages contain NO SQL — data comes from DashboardService;
  * every number shown is an actual stored value or an honest empty state;
  * DRY_RUN_BLOCK is always labelled as simulated — never as a real
    blocked attack;
  * one failing optional section never crashes the whole page.
"""

from __future__ import annotations

import datetime

import pandas as pd
import streamlit as st

from dashboard.components.charts import (
    attack_probability_chart,
    benign_vs_attack_chart,
    detections_over_time_chart,
    feature_importance_chart,
    model_usage_chart,
    response_action_chart,
    severity_distribution_chart,
)
from dashboard.components.metrics import (
    render_metric_cards,
    render_response_metric_cards,
)
from dashboard.components.tables import render_detection_table
from dashboard.services.dashboard_service import DashboardService
from src.response.actions import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_REQUESTED,
    ACTION_DRY_RUN_BLOCK,
    ACTION_NO_ACTION,
    RESPONSE_ACTIONS,
    STATUS_AUTHORIZED,
    STATUS_FAILED,
    STATUS_LOGGED,
    STATUS_NONE,
    STATUS_SIMULATED,
    STATUS_SKIPPED,
)

service = DashboardService()

EMPTY_MESSAGE = (
    "No detection data available. Run the detection + response pipeline "
    "(`python -m src.response.response_engine --input <csv> --store`) to "
    "populate the dashboard."
)

DRY_RUN_BANNER = (
    "**Response Mode: DRY_RUN** — no real firewall or network changes are "
    "performed. `DRY_RUN_BLOCK` entries are **simulated** defensive actions, "
    "never actual blocks."
)


# ---------------------------------------------------------------
#  Cached accessors (short TTL; the refresh button clears them)
# ---------------------------------------------------------------

@st.cache_data(ttl=30, show_spinner=False)
def cached_overview():
    return service.overview_statistics()


@st.cache_data(ttl=30, show_spinner=False)
def cached_response_stats():
    return service.response_statistics()


@st.cache_data(ttl=30, show_spinner=False)
def cached_detections(
    limit, label, severity, is_attack, response_action, response_status, start, end
):
    return service.detections_frame(
        limit=limit,
        label=label,
        severity=severity,
        is_attack=is_attack,
        response_action=response_action,
        response_status=response_status,
        start=start,
        end=end,
    )


@st.cache_data(ttl=30, show_spinner=False)
def cached_over_time(limit):
    return service.repository.get_detections_over_time(limit)


@st.cache_data(ttl=30, show_spinner=False)
def cached_model_usage():
    return service.repository.get_model_usage()


@st.cache_data(ttl=60, show_spinner=False)
def cached_system_status():
    return service.system_status()


@st.cache_data(ttl=60, show_spinner=False)
def cached_probability_frame(limit):
    frame = service.detections_frame(limit=limit)
    if frame.empty or "attack_probability" not in frame.columns:
        return pd.DataFrame()
    return frame[["attack_probability"]]


def render_empty_data_notice() -> None:
    st.info(EMPTY_MESSAGE)


def _safe_chart(figure, caption: str = "") -> None:
    """Render a chart without letting one failure kill the page."""
    try:
        if figure is not None:
            st.pyplot(figure)
            if caption:
                st.caption(caption)
    except Exception as exc:  # optional visualization must never crash a page
        st.warning(f"Chart unavailable: {exc}")


# ---------------------------------------------------------------
#  1. Overview
# ---------------------------------------------------------------

def page_overview() -> None:
    st.title("Overview")
    st.caption(
        "Live summary of SentinelAI detections and defensive (simulated) responses, "
        "computed from the SentinelAI SQLite database."
    )
    stats = cached_overview()
    if stats["database_error"]:
        st.error(
            "The database could not be read. Check that database/sentinelai.db "
            "exists (run the Part 8 initialization)."
        )
        return
    if stats["total_detections"] == 0:
        render_empty_data_notice()
        return

    render_metric_cards(stats)
    response_stats = cached_response_stats()
    render_response_metric_cards(response_stats)
    st.caption(DRY_RUN_BANNER)

    col1, col2 = st.columns(2)
    with col1:
        _safe_chart(benign_vs_attack_chart(stats))
        _safe_chart(model_usage_chart(cached_model_usage()))
    with col2:
        _safe_chart(severity_distribution_chart(stats))
        _safe_chart(detections_over_time_chart(cached_over_time(1000)))


# ---------------------------------------------------------------
#  2. Threat Detections
# ---------------------------------------------------------------

def _date_range_inputs() -> tuple[str | None, str | None]:
    """Optional inclusive ISO date-range filter; (None, None) when unused."""
    use_range = st.checkbox("Filter by date range", value=False)
    if not use_range:
        return None, None
    try:
        d1, d2 = st.columns(2)
        start_date = d1.date_input("From date", value=None)
        end_date = d2.date_input("To date", value=None)
        start = f"{start_date.isoformat()}T00:00:00" if start_date else None
        end = f"{end_date.isoformat()}T23:59:59" if end_date else None
        return start, end
    except Exception as exc:
        st.caption(f"Date filter unavailable: {exc}")
        return None, None


def page_detections() -> None:
    st.title("Threat Detections")
    st.caption(
        "Every stored detection with its model, severity and the defensive "
        "response that was (simulated) for it."
    )
    stats = cached_overview()
    if stats["database_error"]:
        st.error("The database could not be read.")
        return
    if stats["total_detections"] == 0:
        render_empty_data_notice()
        return

    response_stats = cached_response_stats()
    render_response_metric_cards(response_stats)

    st.subheader("Filters")
    f1, f2, f3, f4, f5 = st.columns(5)
    with f1:
        label_filter = st.selectbox("Label", ["all", "BENIGN", "ATTACK"])
    with f2:
        severity_filter = st.selectbox("Severity", ["all", "LOW", "MEDIUM", "HIGH"])
    with f3:
        attack_filter = st.selectbox("Traffic", ["all", "attacks only", "benign only"])
    with f4:
        action_filter = st.selectbox("Response action", ["all", *RESPONSE_ACTIONS])
    with f5:
        status_filter = st.selectbox(
            "Response status",
            ["all", STATUS_NONE, STATUS_LOGGED, STATUS_SIMULATED,
             STATUS_AUTHORIZED, STATUS_FAILED, STATUS_SKIPPED],
        )
    start, end = _date_range_inputs()

    if st.button("Refresh data"):
        st.cache_data.clear()
        st.rerun()

    frame = cached_detections(
        500,
        None if label_filter == "all" else label_filter,
        None if severity_filter == "all" else severity_filter,
        True if attack_filter == "attacks only" else (False if attack_filter == "benign only" else None),
        None if action_filter == "all" else action_filter,
        None if status_filter == "all" else status_filter,
        start,
        end,
    )
    if frame.empty:
        st.info("No detections match the current filters.")
        return

    rendered = render_detection_table(frame)
    if rendered is not None and not rendered.empty:
        st.subheader("Detection details")
        ids = rendered["id"].tolist() if "id" in rendered.columns else []
        if ids:
            selected = st.selectbox(
                "Select a detection event", ids, format_func=lambda i: f"#{i}"
            )
            details = service.detection_details(selected)
            if details:
                st.json(
                    {
                        k: details[k]
                        for k in (
                            "timestamp",
                            "flow_id",
                            "prediction",
                            "label",
                            "is_attack",
                            "attack_probability",
                            "severity",
                            "model_name",
                            "status",
                            "response_action",
                            "response_mode",
                            "response_status",
                            "response_reason",
                            "response_timestamp",
                        )
                        if k in details
                    }
                )
                st.caption(
                    "prediction is the model output. The database stores no "
                    "ground-truth label; where available it would be shown "
                    "separately. `DRY_RUN_BLOCK` means a block was SIMULATED — "
                    "no real network change was made."
                )


# ---------------------------------------------------------------
#  3. Analytics
# ---------------------------------------------------------------

def page_analytics() -> None:
    st.title("Analytics")
    st.caption("Actual distributions and trends computed from stored detections.")
    stats = cached_overview()
    if stats["database_error"]:
        st.error("The database could not be read.")
        return
    if stats["total_detections"] == 0:
        render_empty_data_notice()
        return

    st.subheader("Detection distribution")
    c1, c2 = st.columns(2)
    with c1:
        _safe_chart(benign_vs_attack_chart(stats))
    with c2:
        _safe_chart(severity_distribution_chart(stats))

    st.subheader("Response monitoring")
    st.info(DRY_RUN_BANNER.replace("**", ""))
    response_stats = cached_response_stats()
    render_response_metric_cards(response_stats)

    r1, r2 = st.columns([3, 2])
    with r1:
        _safe_chart(response_action_chart(response_stats))
    with r2:
        status_rows = service.response_status_rows()
        if status_rows:
            st.dataframe(pd.DataFrame(status_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("No response records yet.")
    st.caption(
        "SIMULATED = dry-run only (no real change). AUTHORIZED = a real adapter "
        "executed (requires explicit authorization; none is shipped in this project)."
    )

    st.subheader("Timeline")
    _safe_chart(detections_over_time_chart(cached_over_time(1000)))

    st.subheader("Attack probability")
    probability_frame = cached_probability_frame(5000)
    probability_chart = attack_probability_chart(probability_frame)
    if probability_chart is None:
        st.caption("No stored attack probabilities to plot yet.")
    else:
        _safe_chart(probability_chart)

    st.subheader("Detections per model")
    _safe_chart(model_usage_chart(cached_model_usage()))


# ---------------------------------------------------------------
#  4. Models
# ---------------------------------------------------------------

def page_models() -> None:
    st.title("Models")
    st.caption("Registered models and the actual evaluation reports they produced.")

    st.subheader("Model registry")
    registry = service.models_registry()
    if not registry:
        st.info("No models registered yet — run a detection/response run with --store.")
    else:
        registry_frame = pd.DataFrame(registry)[
            ["id", "name", "version", "algorithm", "feature_count", "is_active", "created_at"]
        ]
        st.dataframe(registry_frame, use_container_width=True, hide_index=True)
        active = next((m for m in registry if m["is_active"]), None)
        if active:
            st.success(f"Active model: {active['name']} (registered {active['created_at']})")

    st.subheader("Model evaluation results")
    files = service.available_result_files()
    if not files:
        st.info(
            "No model evaluation results available yet — Parts 5/6 have not "
            "produced result files in reports/."
        )
    else:
        choice = st.selectbox("Results file", files)
        results = service.model_results(choice)
        if results:
            frame = pd.DataFrame(
                [
                    {k: v for k, v in r.items() if k not in ("y_pred", "y_proba")}
                    for r in results
                ]
            )
            st.dataframe(frame, use_container_width=True, hide_index=True)
            st.caption(f"Actual values from {choice} — nothing recalculated here.")
        else:
            st.info("The selected results file could not be read.")

    st.subheader("Model feature importance")
    model_choice = st.selectbox("Feature importance model", ["random_forest", "xgboost"])
    importance = service.feature_importance(model_choice)
    if importance is None:
        st.info(
            f"No feature importance available for {model_choice} — the Part 6 "
            "report file is missing."
        )
    else:
        _safe_chart(feature_importance_chart(importance, model_choice))
        st.caption(
            "Model feature importance — association within the fitted model, "
            "not causation."
        )


# ---------------------------------------------------------------
#  5. System Information
# ---------------------------------------------------------------

def page_system() -> None:
    st.title("System Information")
    st.caption("Environment, storage and safety status (no secrets are shown).")
    status = cached_system_status()
    table = pd.DataFrame(
        {
            "Item": [
                "Project",
                "Python version",
                "Database available",
                "Database path (relative)",
                "Detection records",
                "Model records",
                "Active model",
                "Response mode",
                "Safety mode",
                "Model artifacts",
                "Preprocessing artifact available",
            ],
            "Value": [
                f"{status['project_name']} v{status['project_version']}",
                status["python_version"],
                "Yes" if status["database_available"] else "No",
                status["database_path_relative"],
                status["detection_records"] if status["detection_records"] is not None else "-",
                status["model_records"] if status["model_records"] is not None else "-",
                status["active_model"] or "-",
                status["response_mode"],
                status["safety_mode"],
                ", ".join(status["model_artifacts"]) or "none",
                "Yes" if status["preprocessing_artifact_available"] else "No",
            ],
        }
    )
    st.table(table)
    st.caption(
        "The dashboard is read-only with respect to the database and provides "
        "no controls that perform real network blocking."
    )
