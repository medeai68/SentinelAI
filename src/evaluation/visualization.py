"""
SentinelAI — Part 6 evaluation visualizations.

matplotlib only, default colors (per project spec). Multi-series charts
always carry a legend.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless-safe backend (no display needed)

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def plot_metric_comparison(results: list[dict], path: Path) -> Path:
    """Grouped bar chart comparing the metric values of the models."""
    metrics = [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "false_positive_rate",
        "false_negative_rate",
    ]
    models = [r["model"] for r in results]
    x = np.arange(len(metrics))
    width = 0.25

    fig, ax = plt.subplots(figsize=(13, 7))
    for i, model in enumerate(models):
        values = [next(r[m] for r in results if r["model"] == model) for m in metrics]
        ax.bar(x + (i - (len(models) - 1) / 2) * width, values, width, label=model)
    ax.set_xticks(x, metrics)
    ax.set_ylabel("Score (higher is better, except FPR/FNR)")
    ax.set_title("Model comparison - optimized models (test set)")
    ax.set_ylim(0, 1)
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_feature_importance_comparison(
    imp_rf: pd.DataFrame, imp_xgb: pd.DataFrame, path: Path, top_n: int = 20
) -> Path:
    """Side-by-side horizontal bar charts of RF vs XGBoost importances."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 9))
    top_rf = imp_rf.head(top_n).iloc[::-1]
    top_xgb = imp_xgb.head(top_n).iloc[::-1]
    ax1.barh(top_rf["feature"], top_rf["importance"])
    ax1.set_title("Random Forest - feature importance (top 20)")
    ax1.set_xlabel("Importance")
    ax2.barh(top_xgb["feature"], top_xgb["importance"])
    ax2.set_title("XGBoost - feature importance (top 20)")
    ax2.set_xlabel("Importance")
    fig.suptitle(
        "Model feature importance (association within the fitted model, not causation)"
    )
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_threshold_analysis(
    table: pd.DataFrame, threshold_summary: dict, path: Path
) -> Path:
    """F1-vs-threshold curves per model (validation data only).

    The best validation-F1 threshold per model is shown in the title,
    keeping the figure color-free of extra encodings.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    for model, group in table.groupby("model"):
        ax.plot(group["threshold"], group["f1"], label=model)
    title = "Threshold analysis - F1 (ATTACK) on training validation slice\n"
    title += " | ".join(
        f"{name}: best F1 at {t['best_threshold']:.2f}" for name, t in threshold_summary.items()
    )
    ax.set_title(title, fontsize=9)
    ax.set_xlabel("Classification threshold")
    ax.set_ylabel("F1 (ATTACK)")
    ax.legend()
    ax.grid(linestyle="--", alpha=0.4)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path
