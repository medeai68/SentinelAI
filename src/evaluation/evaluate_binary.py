"""
SentinelAI — binary model evaluation (Part 5).

Evaluates the two baseline models on the TEST SET ONLY (the test set
was never used during training) and writes all results as files with
ACTUAL measured values.

Run from the project root:

    python -m src.evaluation.evaluate_binary

Outputs:
    reports/logistic_regression_classification_report.txt
    reports/random_forest_classification_report.txt
    reports/model_results.json
    reports/model_results.csv
    reports/part5_model_summary.md
    reports/random_forest_feature_importance.csv
    reports/logistic_regression_coefficients.csv
    reports/figures/logistic_regression_confusion_matrix.png
    reports/figures/random_forest_confusion_matrix.png
    reports/figures/binary_roc_curves.png
    reports/figures/random_forest_feature_importance.png
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless-safe backend

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve

from src.evaluation.metrics import (
    calculate_classification_metrics,
    generate_classification_report,
    validate_predictions,
)
from src.training.model_utils import ModelArtifactError, load_model, validate_model_artifact
from src.training.train_binary import (
    LOGISTIC_MODEL_PATH,
    RANDOM_FOREST_MODEL_PATH,
    load_feature_columns,
    load_test_data,
    load_training_data,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"

MODELS = [
    ("logistic_regression", LOGISTIC_MODEL_PATH),
    ("random_forest", RANDOM_FOREST_MODEL_PATH),
]


# ---------------------------------------------------------------
#  Prediction
# ---------------------------------------------------------------

def predict(model, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray | None]:
    """Return (y_pred, y_proba) for the positive class (1 = ATTACK)."""
    y_pred = model.predict(X)
    y_proba = None
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X)[:, 1]
    return y_pred, y_proba


def evaluate_model(name: str, model, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    """Evaluate one model on the test set; raises RuntimeError if invalid."""
    y_pred, y_proba = predict(model, X_test)
    problems = validate_predictions(y_test, y_pred, y_proba)
    if problems:
        raise RuntimeError(f"Model '{name}' produced invalid predictions:\n" + "\n".join(problems))
    metrics = calculate_classification_metrics(y_test, y_pred, y_proba)
    return {
        "model": name,
        "test_samples": int(len(y_test)),
        "y_pred": y_pred,
        "y_proba": y_proba,
        **metrics,
    }


# ---------------------------------------------------------------
#  Figures
# ---------------------------------------------------------------

def plot_confusion_matrix(cm: np.ndarray, title: str, path: Path) -> Path:
    """Save a labeled confusion matrix figure (matplotlib defaults)."""
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            color = "white" if cm[i, j] > cm.max() / 2 else "black"
            ax.text(j, i, str(cm[i, j]), ha="center", va="center", color=color)
    ax.set_xticks([0, 1], labels=["BENIGN", "ATTACK"])
    ax.set_yticks([0, 1], labels=["BENIGN", "ATTACK"])
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True label")
    ax.set_title(title)
    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_roc_curves(roc_pairs: list[tuple[str, np.ndarray, np.ndarray, float]], path: Path) -> Path:
    """Save both models' ROC curves on one figure (legend included)."""
    fig, ax = plt.subplots(figsize=(8, 8))
    for name, fpr, tpr, auc in roc_pairs:
        ax.plot(fpr, tpr, label=f"{name} (AUC = {auc:.4f})")
    ax.plot([0, 1], [0, 1], linestyle="--", label="Chance (AUC = 0.50)")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves - SentinelAI binary models (test set)")
    ax.legend(loc="lower right")
    ax.grid(linestyle="--", alpha=0.4)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_feature_importance(importance: pd.DataFrame, path: Path, top_n: int = 20) -> Path:
    """Save a horizontal bar chart of the most important features."""
    top = importance.head(top_n).iloc[::-1]
    fig, ax = plt.subplots(figsize=(10, 8))
    ax.barh(top["feature"], top["importance"])
    ax.set_xlabel("Importance")
    ax.set_title(f"Random Forest feature importance (top {top_n})")
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


# ---------------------------------------------------------------
#  Reports
# ---------------------------------------------------------------

def write_model_results_json(results: list[dict], path: Path) -> Path:
    """Save the machine-readable metrics (actual measured values only)."""
    serializable = []
    for r in results:
        serializable.append({k: v for k, v in r.items() if k not in ("y_pred", "y_proba")})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
    return path


def write_model_results_csv(results: list[dict], path: Path) -> Path:
    """Save the metrics table as CSV."""
    rows = []
    for r in results:
        rows.append({k: v for k, v in r.items() if k not in ("y_pred", "y_proba")})
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def write_part5_summary(results: list[dict], extras: dict, path: Path) -> Path:
    """Write the Part 5 model summary markdown from the actual results."""
    lines = [
        "# Part 5 — First ML Models",
        "",
        "## Objective",
        "",
        "Can basic machine-learning models distinguish benign network traffic from",
        "malicious network traffic using the prepared network-flow features?",
        "This part trains and evaluates two binary-classification baselines",
        "(BENIGN -> 0, ATTACK -> 1) on the Part 4 processed data.",
        "",
        "## Dataset",
        "",
        f"- Training samples: {extras['train_samples']}",
        f"- Test samples: {extras['test_samples']}",
        f"- Number of features: {extras['feature_count']}",
        f"- Training class distribution (0=BENIGN, 1=ATTACK): {extras['train_distribution']}",
        f"- Test class distribution (0=BENIGN, 1=ATTACK): {extras['test_distribution']}",
        f"- Split: the Part 4 80/20 stratified split (random_state=42), reused unchanged.",
        f"- Class weighting: class weights were used ({extras['class_weight_note']}) — the data",
        "  is imbalanced, and this is recorded rather than hidden.",
        "",
        "## Models",
        "",
        "- **Logistic Regression** — linear baseline, class_weight='balanced', max_iter=2000.",
        "- **Random Forest** — 200 trees, class_weight='balanced_subsample', random_state=42.",
        "",
        "## Evaluation Metrics",
        "",
        "Computed on the test set only. Precision/recall/F1 are for the ATTACK class (1).",
        "",
        "| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | TP | TN | FP | FN |",
        "| ----- | -------- | --------- | ------ | -- | ------- | -- | -- | -- | -- |",
    ]
    for r in results:
        lines.append(
            f"| {r['model']} | {r['accuracy']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} | "
            f"{r['f1']:.4f} | {r['roc_auc']:.4f} | {r['true_positives']} | {r['true_negatives']} | "
            f"{r['false_positives']} | {r['false_negatives']} |"
        )
    lines += [
        "",
        "## Cybersecurity Interpretation",
        "",
        "The numbers above are the actual measured values. Interpretations are kept",
        "cautious: these are baseline models on a development subset of a public",
        "dataset, not production detectors.",
        "",
        f"- Attack recall: logistic regression {results[0]['recall']:.4f}, "
        f"random forest {results[1]['recall']:.4f}. The experiment suggests that "
        "(on this subset) the higher-recall model misses fewer attacks.",
        f"- False positives on the test set: {results[0]['false_positives']} "
        f"(logistic regression), {results[1]['false_positives']} (random forest). "
        "In a real IDS every false positive costs analyst time.",
        f"- False negatives on the test set: {results[0]['false_negatives']} "
        f"(logistic regression), {results[1]['false_negatives']} (random forest). "
        "A false negative is a missed attack — the most serious error for an IDS.",
        "- Accuracy alone would be misleading here because the data is imbalanced:",
        "a model that always predicts BENIGN would still look accurate while",
        "detecting nothing. F1, recall and the confusion matrix are the relevant",
        "measures.",
        "- Random Forest feature importance (see reports/random_forest_feature_importance.csv)",
        "indicates which flow features the MODEL relies on most within this fitted",
        "model. It does not prove that any feature causes an attack.",
        "",
        "## Limitations",
        "",
        "- Public-dataset limitations: CIC-IDS2017 was captured in a lab in 2017; its",
        "traffic may not match other networks.",
        "- Possible dataset bias: known label noise and duplicate flows exist in the",
        "original data (documented in the literature and in Part 3 inspection).",
        "- Class imbalance: the subset is dominated by BENIGN traffic.",
        "- Baseline hyperparameters: no tuning beyond the documented defaults.",
        "- No real-time traffic evaluation yet, and no external validation dataset.",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ---------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------

def main() -> int:
    print("SentinelAI - binary model evaluation (Part 5)")

    try:
        feature_cols = load_feature_columns()
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        return 1

    try:
        X_test, y_test = load_test_data(feature_cols=feature_cols)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        return 1

    results = []
    roc_pairs = []
    for name, path in MODELS:
        try:
            validate_model_artifact(path)
            model = load_model(path)
        except ModelArtifactError as exc:
            print(f"ERROR: {exc}")
            print("Run 'python -m src.training.train_binary' first.")
            return 1
        try:
            result = evaluate_model(name, model, X_test, y_test)
        except RuntimeError as exc:
            print(f"ERROR: {exc}")
            return 1
        results.append(result)

        # per-model text report + confusion matrix figure
        report_text = (
            f"Model: {name}\n"
            f"Test samples: {result['test_samples']}\n\n"
            f"{generate_classification_report(y_test, result['y_pred'])}"
        )
        report_path = REPORTS_DIR / f"{name}_classification_report.txt"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_text, encoding="utf-8")
        plot_confusion_matrix(
            calculate_confusion_matrix_for_plot(y_test, result["y_pred"]),
            f"{name} - confusion matrix (test set)",
            FIGURES_DIR / f"{name}_confusion_matrix.png",
        )

        if result["y_proba"] is not None:
            fpr, tpr, _ = roc_curve(y_test, result["y_proba"], pos_label=1)
            roc_pairs.append((name, fpr, tpr, result["roc_auc"]))

    # combined outputs
    write_model_results_json(results, REPORTS_DIR / "model_results.json")
    write_model_results_csv(results, REPORTS_DIR / "model_results.csv")
    if roc_pairs:
        plot_roc_curves(roc_pairs, FIGURES_DIR / "binary_roc_curves.png")

    # feature importance (random forest) + coefficients (logistic regression)
    rf_model = load_model(RANDOM_FOREST_MODEL_PATH)
    lr_model = load_model(LOGISTIC_MODEL_PATH)
    importance = pd.DataFrame(
        {"feature": feature_cols, "importance": rf_model.feature_importances_}
    ).sort_values("importance", ascending=False)
    importance.to_csv(REPORTS_DIR / "random_forest_feature_importance.csv", index=False)
    plot_feature_importance(importance, FIGURES_DIR / "random_forest_feature_importance.png")

    coefficients = pd.DataFrame(
        {
            "feature": feature_cols,
            "coefficient": lr_model.coef_[0],
            "absolute_coefficient": np.abs(lr_model.coef_[0]),
        }
    ).sort_values("absolute_coefficient", ascending=False)
    coefficients.to_csv(REPORTS_DIR / "logistic_regression_coefficients.csv", index=False)

    # summary markdown
    write_part5_summary(
        results,
        extras={
            "train_samples": _train_sample_count(),
            "test_samples": int(len(y_test)),
            "feature_count": len(feature_cols),
            "train_distribution": _train_distribution(),
            "test_distribution": y_test.value_counts().sort_index().to_dict(),
            "class_weight_note": "logistic regression: 'balanced', random forest: 'balanced_subsample'",
        },
        path=REPORTS_DIR / "part5_model_summary.md",
    )

    print("\nEvaluation finished. Results:")
    for r in results:
        print(
            f"  {r['model']}: accuracy={r['accuracy']:.4f} precision={r['precision']:.4f} "
            f"recall={r['recall']:.4f} f1={r['f1']:.4f} roc_auc={r['roc_auc']:.4f} "
            f"tp={r['true_positives']} tn={r['true_negatives']} "
            f"fp={r['false_positives']} fn={r['false_negatives']}"
        )
    print("All reports and figures are under reports/.")
    return 0


def calculate_confusion_matrix_for_plot(y_true, y_pred) -> np.ndarray:
    from src.evaluation.metrics import calculate_confusion_matrix

    return calculate_confusion_matrix(y_true, y_pred)


def _train_sample_count() -> int:
    try:
        _, y = load_training_data(feature_cols=load_feature_columns())
        return int(len(y))
    except (FileNotFoundError, ValueError):
        return 0


def _train_distribution() -> dict:
    try:
        _, y = load_training_data(feature_cols=load_feature_columns())
        return y.value_counts().sort_index().to_dict()
    except (FileNotFoundError, ValueError):
        return {}


if __name__ == "__main__":
    sys.exit(main())
