"""SentinelAI Streamlit dashboard (Part 9).

Run from the project root:

    streamlit run dashboard/app.py

Every number shown comes from the actual SQLite database (Part 8) or
actual saved model reports (Parts 5/6). When no detection data or
reports exist yet, clear empty states are shown — nothing is
fabricated.

Page functions live in dashboard/pages.py; this file only configures
the app and wires the navigation.
"""

import streamlit as st

from dashboard.pages import (
    page_analytics,
    page_detections,
    page_models,
    page_overview,
    page_system,
)

st.set_page_config(page_title="SentinelAI Dashboard", layout="wide")

# Global manual refresh: clears cached reads so new detections appear
# immediately instead of waiting for the 30 s cache TTL.
with st.sidebar:
    st.markdown("### SentinelAI")
    if st.button("Refresh data"):
        st.cache_data.clear()
        st.rerun()
    st.caption("Defensive research dashboard — response simulation only (DRY_RUN).")

pages = st.navigation(
    [
        st.Page(page_overview, title="Overview", default=True),
        st.Page(page_detections, title="Threat Detections"),
        st.Page(page_analytics, title="Analytics"),
        st.Page(page_models, title="Models"),
        st.Page(page_system, title="System Information"),
    ]
)
pages.run()
