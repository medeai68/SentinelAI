"""Dashboard charts (Part 9).

matplotlib only, default colors (per project spec), no seaborn.
Single-series charts have no legend — the title names the series.
All values come from actual database/report data.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")  # headless-safe backend

import matplotlib.pyplot as plt
import pandas as pd


def benign_vs_attack_chart(stats: dict):
    """Bar chart: benign vs attack counts."""
    fig, ax = plt.subplots(figsize=(7, 4))
    counts = pd.Series(
        {"BENIGN": stats["total_benign"], "ATTACK": stats["total_attacks"]}
    )
    counts.plot(kind="bar", ax=ax, width=0.6)
    ax.set_title("Detections: BENIGN vs ATTACK")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=0)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return fig


def severity_distribution_chart(stats: dict):
    """Bar chart: severity distribution."""
    fig, ax = plt.subplots(figsize=(7, 4))
    counts = pd.Series(
        {
            "LOW": stats["low_severity_count"],
            "MEDIUM": stats["medium_severity_count"],
            "HIGH": stats["high_severity_count"],
        }
    )
    counts.plot(kind="bar", ax=ax, width=0.6)
    ax.set_title("Severity distribution")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=0)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return fig


def detections_over_time_chart(rows: list[dict]):
    """Line chart of detections per timestamp (chronological order)."""
    fig, ax = plt.subplots(figsize=(9, 4))
    if not rows:
        ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("Detections over time")
        fig.tight_layout()
        return fig
    frame = pd.DataFrame(rows).sort_values("timestamp")
    ax.plot(frame["timestamp"], frame["count"], marker="o")
    ax.set_title("Detections over time")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45, labelsize=8)
    ax.grid(linestyle="--", alpha=0.4)
    fig.tight_layout()
    return fig


def model_usage_chart(rows: list[dict]):
    """Bar chart: detections per model."""
    fig, ax = plt.subplots(figsize=(7, 4))
    if not rows:
        ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("Detections per model")
        fig.tight_layout()
        return fig
    frame = pd.DataFrame(rows)
    ax.bar(frame["model_name"].fillna("unknown"), frame["detections"])
    ax.set_title("Detections per model")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return fig


def feature_importance_chart(frame: pd.DataFrame, model: str, top_n: int = 15):
    """Horizontal bar chart of the top features of one model."""
    top = frame.head(top_n).iloc[::-1]
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(top["feature"], top["importance"])
    ax.set_title(f"Model feature importance - {model} (top {top_n})")
    ax.set_xlabel("Importance")
    fig.tight_layout()
    return fig


def response_action_chart(stats: dict):
    """Bar chart of response actions.

    The title states explicitly that DRY_RUN_BLOCK is a simulation — the
    chart must never imply a real blocked attack.
    """
    fig, ax = plt.subplots(figsize=(7, 4))
    counts = pd.Series(
        {
            "NO_ACTION": stats["no_action_count"],
            "ALERT_ONLY": stats["alert_count"],
            "DRY_RUN_BLOCK\n(simulated)": stats["dry_run_block_count"],
            "BLOCK_REQUESTED\n(real, requires adapter)": stats["block_requested_count"],
        }
    )
    counts.plot(kind="bar", ax=ax, width=0.6)
    ax.set_title("Response actions - DRY_RUN simulation (no real blocking)")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=0, labelsize=8)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return fig


def attack_probability_chart(frame: pd.DataFrame, bins: int = 20):
    """Histogram of stored attack probabilities, or None when unavailable."""
    if frame is None or frame.empty or "attack_probability" not in frame.columns:
        return None
    probabilities = pd.to_numeric(frame["attack_probability"], errors="coerce").dropna()
    if probabilities.empty:
        return None
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(probabilities, bins=bins)
    ax.set_title("Attack probability distribution (stored detections)")
    ax.set_xlabel("Attack probability")
    ax.set_ylabel("Flows")
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return fig
