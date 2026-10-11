"""
SentinelAI — evaluation metric calculations (Part 5).

Pure calculation functions — no file writing, no plotting. All
functions treat class 1 as the ATTACK class (the positive class):

    0 = BENIGN, 1 = ATTACK

For an intrusion detection system the important numbers are attack
recall, the false positive/negative rates and F1 — accuracy alone is
misleading on imbalanced data.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ATTACK_LABEL = 1
CLASS_NAMES = ("BENIGN", "ATTACK")


def calculate_confusion_matrix(y_true, y_pred) -> np.ndarray:
    """Return the 2x2 confusion matrix (rows = true, columns = predicted)."""
    return confusion_matrix(y_true, y_pred, labels=[0, 1])


def confusion_matrix_counts(y_true, y_pred) -> dict:
    """Return the confusion matrix as TN/FP/FN/TP counts."""
    cm = calculate_confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    return {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def calculate_classification_metrics(y_true, y_pred, y_proba=None) -> dict:
    """Calculate the Part 5 metric set for the ATTACK class (class 1).

    If probability scores are provided, ROC-AUC is included too.
    """
    counts = confusion_matrix_counts(y_true, y_pred)
    tn, fp, fn, tp = counts["tn"], counts["fp"], counts["fn"], counts["tp"]

    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, pos_label=ATTACK_LABEL, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=ATTACK_LABEL, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, pos_label=ATTACK_LABEL, zero_division=0)),
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
    }
    if y_proba is not None:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba))
    return metrics


def calculate_roc_auc(y_true, y_proba) -> float:
    """Return the ROC-AUC score for the positive class."""
    return float(roc_auc_score(y_true, y_proba))


def generate_classification_report(y_true, y_pred) -> str:
    """Return sklearn's per-class text report (BENIGN / ATTACK)."""
    return classification_report(y_true, y_pred, target_names=list(CLASS_NAMES), zero_division=0)


def validate_predictions(y_true, y_pred, y_proba=None) -> list[str]:
    """Return a list of problems in the predictions (empty = valid)."""
    problems = []
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    if len(y_true) != len(y_pred):
        problems.append(
            f"length mismatch: {len(y_true)} true labels vs {len(y_pred)} predictions"
        )
    if not set(np.unique(y_pred)) <= {0, 1}:
        problems.append(f"predictions contain values outside {{0, 1}}")
    if not set(np.unique(y_true)) <= {0, 1}:
        problems.append(f"true labels contain values outside {{0, 1}}")
    if np.isnan(y_pred).any():
        problems.append("predictions contain NaN values")
    if y_proba is not None:
        y_proba = np.asarray(y_proba)
        if len(y_proba) != len(y_true):
            problems.append("probability scores length mismatch")
        if np.isnan(y_proba).any():
            problems.append("probability scores contain NaN values")
        if not ((y_proba >= 0) & (y_proba <= 1)).all():
            problems.append("probability scores outside [0, 1]")
    return problems


# ---------------------------------------------------------------
#  Threshold analysis (Part 6 — validation data only, never the test set)
# ---------------------------------------------------------------

def threshold_metrics(y_true, y_proba, thresholds) -> pd.DataFrame:
    """Return metrics for the ATTACK class at each classification threshold.

    A prediction is class 1 when proba >= threshold. Use only on
    validation/CV data — never on the final test set.
    """
    y_true = np.asarray(y_true)
    y_proba = np.asarray(y_proba)
    rows = []
    for t in thresholds:
        y_pred = (y_proba >= t).astype(int)
        m = calculate_classification_metrics(y_true, y_pred)
        rows.append(
            {
                "threshold": float(t),
                "precision": m["precision"],
                "recall": m["recall"],
                "f1": m["f1"],
                "false_positive_rate": m["false_positive_rate"],
                "false_negative_rate": m["false_negative_rate"],
            }
        )
    return pd.DataFrame(rows)


def select_best_threshold(y_true, y_proba, thresholds, metric: str = "f1") -> tuple[float, float]:
    """Return (best_threshold, best_metric_value) on validation data."""
    table = threshold_metrics(y_true, y_proba, thresholds)
    best = table.loc[table[metric].idxmax()]
    return float(best["threshold"]), float(best[metric])


# ---------------------------------------------------------------
#  Model agreement analysis (Part 6 — exploratory)
# ---------------------------------------------------------------

def agreement_summary(predictions: dict) -> dict:
    """Pairwise and all-model agreement percentages on the same samples.

    `predictions` maps model names to arrays of the same length.
    Disagreement is exploratory — it is not a ranking signal.
    """
    names = list(predictions)
    n = len(predictions[names[0]]) if names else 0
    summary = {"samples": int(n)}
    if n == 0:
        return summary
    stack = np.column_stack([np.asarray(predictions[name]) for name in names])
    all_agree = int(np.all(stack == stack[:, [0]], axis=1).sum())
    summary["all_agree_count"] = all_agree
    summary["all_agree_percentage"] = float(all_agree / n * 100)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            agree = int((stack[:, i] == stack[:, j]).sum())
            summary[f"{names[i]}_vs_{names[j]}_agree_percentage"] = float(agree / n * 100)
    return summary
