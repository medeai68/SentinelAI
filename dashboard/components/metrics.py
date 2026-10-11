"""Dashboard metric cards (Part 9). Values come from actual statistics."""

import streamlit as st


def render_metric_cards(stats: dict) -> None:
    """Render the overview metric cards from actual database statistics."""
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total detections", stats["total_detections"])
    c2.metric("Attack detections", stats["total_attacks"])
    c3.metric("Benign detections", stats["total_benign"])
    c4.metric("Attack %", f"{stats['attack_percentage']:.2f}%")
    c5.metric("High severity", stats["high_severity_count"])
    c6.metric("Active model", stats["active_model"] or "-")


def render_response_metric_cards(response_stats: dict) -> None:
    """Render the response metric cards from actual response statistics.

    DRY_RUN_BLOCK is labelled as simulated — never as an actual block.
    """
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alerts (ALERT_ONLY)", response_stats["alert_count"])
    c2.metric("Dry-run responses", response_stats["dry_run_block_count"],
              help="DRY_RUN_BLOCK: a block was SIMULATED. No real firewall/network change was made.")
    c3.metric("Failed responses", response_stats["failed_response_count"])
    c4.metric("Real block requests", response_stats["block_requested_count"],
              help="BLOCK_REQUESTED requires AUTHORIZED mode and a real adapter; none are shipped.")
