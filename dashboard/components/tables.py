"""Dashboard table rendering (Part 9)."""

import pandas as pd
import streamlit as st

# User-facing columns only — internal ids are not exposed in the table.
DETECTION_COLUMNS = [
    "timestamp",
    "flow_id",
    "prediction",
    "label",
    "attack_probability",
    "severity",
    "model_name",
    "status",
    "response_action",
    "response_mode",
    "response_status",
]


def render_detection_table(frame: pd.DataFrame):
    """Render the actual detection rows as a filterable table.

    Returns the full frame (with ids) so callers can offer detail
    selection, or None when there is nothing to show.
    """
    if frame is None or frame.empty:
        st.info("No detection data available yet.")
        return None
    available = [c for c in DETECTION_COLUMNS if c in frame.columns]
    display = frame[available].copy()
    if "attack_probability" in display.columns:
        display["attack_probability"] = display["attack_probability"].apply(
            lambda v: round(float(v), 4) if pd.notna(v) else None
        )
    st.dataframe(display, use_container_width=True, hide_index=True)
    return frame
