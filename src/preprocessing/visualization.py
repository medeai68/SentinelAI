"""
SentinelAI — Part 4 visualizations.

matplotlib only, default colors (per project spec), saved under
reports/figures/. Single-series bar charts need no legend — the title
names the series.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless-safe backend (no display needed)

import matplotlib.pyplot as plt
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
FIGURES_DIR = PROJECT_ROOT / "reports" / "figures"


def plot_class_distribution(labels: pd.Series, title: str, path: Path) -> Path:
    """Save a bar chart of class counts (single series, default colors)."""
    counts = labels.value_counts(dropna=False)
    fig, ax = plt.subplots(figsize=(12, 6))
    counts.plot(kind="bar", ax=ax, width=0.8)
    ax.set_title(title)
    ax.set_ylabel("Number of records")
    ax.set_xlabel("Class label")
    ax.tick_params(axis="x", rotation=45)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_selected_numeric_features(
    df: pd.DataFrame, columns: list[str], path: Path, bins: int = 30
) -> Path:
    """Save small-multiple histograms of selected numeric features."""
    fig, axes = plt.subplots(2, 3, figsize=(14, 8))
    for ax, col in zip(axes.flat, columns):
        ax.hist(df[col].dropna(), bins=bins)
        ax.set_title(col, fontsize=9)
        ax.tick_params(labelsize=8)
    fig.suptitle("Distributions of selected numeric features (training split, raw values)")
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path
