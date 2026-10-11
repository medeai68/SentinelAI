"""
SentinelAI — Part 6: advanced model comparison & optimization.

Research question:
    "Which supervised machine-learning model provides the best balance
    between attack detection capability and false-positive control on
    the prepared network intrusion dataset?"

Run from the project root:

    python -m src.training.model_comparison

Pipeline (the test set is touched ONLY in the final evaluation):

    1. Load the Part 4 processed data (train/test split reused as-is).
    2. BASELINE comparison: fit LR / RF / XGBoost baselines on the full
       training set, evaluate on the test set (reference snapshot).
    3. HYPERPARAMETER OPTIMIZATION: RandomizedSearchCV with stratified
       5-fold CV on the TRAINING SET ONLY; full CV results saved.
    4. FINAL MODELS: the best configuration per model (re-fitted on the
       complete training set by the search) is evaluated on the
       untouched test set — this is the final fair comparison.
    5. Comparison reports/figures, feature importance, model agreement,
       threshold analysis (training-only data), model artifacts.
"""

from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_curve
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from config import model_config as cfg
from src.evaluation.evaluate_binary import (
    plot_confusion_matrix,
    plot_roc_curves,
)
from src.evaluation.metrics import (
    agreement_summary,
    calculate_classification_metrics,
    select_best_threshold,
    threshold_metrics,
    validate_predictions,
)
from src.evaluation.visualization import (
    plot_feature_importance_comparison,
    plot_metric_comparison,
    plot_threshold_analysis,
)
from src.training.model_utils import save_model
from src.training.optimize import tune_and_record
from src.training.train_binary import (
    DATASET_NAME,
    RANDOM_STATE,
    TARGET_NAME,
    load_feature_columns,
    load_test_data,
    load_training_data,
    validate_training_inputs,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"
CV_DIR = REPORTS_DIR / "cv_results"
MODELS_DIR = PROJECT_ROOT / "models"

MODEL_NAMES = ["logistic_regression", "random_forest", "xgboost"]

BASELINE_PARAMS = {
    "logistic_regression": {"max_iter": 2000, "class_weight": "balanced"},
    "random_forest": {"n_estimators": 200, "class_weight": "balanced_subsample"},
    "xgboost": {
        "n_estimators": 200,
        "max_depth": 6,
        "learning_rate": 0.3,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
        "min_child_weight": 1,
        "imbalance": "scale_pos_weight computed from the training set",
    },
}


# ---------------------------------------------------------------
#  Model builders
# ---------------------------------------------------------------

def compute_scale_pos_weight(y_train: pd.Series) -> float:
    """XGBoost imbalance weight: benign_count / attack_count (>= 1)."""
    counts = y_train.value_counts()
    return float(counts.get(0, 0) / max(1, counts.get(1, 0)))


def build_logistic_baseline() -> LogisticRegression:
    return LogisticRegression(
        max_iter=2000, class_weight="balanced", random_state=RANDOM_STATE
    )


def build_random_forest_baseline() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )


def build_xgboost_baseline(scale_pos_weight: float | None = None) -> XGBClassifier:
    return XGBClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        n_jobs=-1,
    )


def build_logistic_tuned_estimator() -> LogisticRegression:
    return LogisticRegression(max_iter=2000, random_state=RANDOM_STATE)


def build_random_forest_tuned_estimator() -> RandomForestClassifier:
    return RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1)


def build_xgboost_tuned_estimator(scale_pos_weight: float | None = None) -> XGBClassifier:
    return XGBClassifier(
        random_state=RANDOM_STATE,
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        n_jobs=-1,
    )


# ---------------------------------------------------------------
#  Evaluation helpers
# ---------------------------------------------------------------

def evaluate_on_test(name: str, model, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    """Evaluate one fitted model on the test set; raises on invalid output."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    problems = validate_predictions(y_test, y_pred, y_proba)
    if problems:
        raise RuntimeError(
            f"Model '{name}' produced invalid predictions:\n" + "\n".join(problems)
        )
    metrics = calculate_classification_metrics(y_test, y_pred, y_proba)
    return {
        "model": name,
        "test_samples": int(len(y_test)),
        "y_pred": y_pred,
        "y_proba": y_proba,
        **metrics,
    }


def select_best_model(results: list[dict]) -> tuple[str, str]:
    """Pick the best model with a clearly stated criterion.

    Primary: highest ATTACK F1. Ties broken by higher attack recall,
    then by lower false-positive rate. The criterion is reported
    verbatim in the research report.
    """
    ranked = sorted(
        results,
        key=lambda r: (-r["f1"], -r["recall"], r["false_positive_rate"]),
    )
    criterion = (
        "highest attack F1 on the test set, with attack recall and then "
        "false-positive rate as tie-breakers"
    )
    return ranked[0]["model"], criterion


def _metrics_columns() -> list[str]:
    return [
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "true_positives",
        "true_negatives",
        "false_positives",
        "false_negatives",
        "false_positive_rate",
        "false_negative_rate",
    ]


def _results_frame(results: list[dict]) -> pd.DataFrame:
    rows = [{k: r[k] for k in ["model", *_metrics_columns()]} for r in results]
    return pd.DataFrame(rows)


# ---------------------------------------------------------------
#  Report writers
# ---------------------------------------------------------------

def write_part6_report(
    *,
    baseline_results: list[dict],
    tuned: dict,
    optimized_results: list[dict],
    best_model: str,
    criterion: str,
    agreement: dict,
    threshold_summary: dict,
    feature_cols: list[str],
    X_train: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series,
    path: Path,
) -> Path:
    """Write the Part 6 research report from actual measured values."""
    L: list[str] = []
    add = L.append
    add("# Part 6 — Advanced Model Comparison")
    add("")
    add("## Research Question")
    add("")
    add("Which supervised machine-learning model provides the best balance between")
    add("attack detection capability and false-positive control on the prepared")
    add("network intrusion dataset?")
    add("")
    add("## Experimental Setup")
    add("")
    add(f"- Dataset: {DATASET_NAME}")
    add(f"- Target: {TARGET_NAME}")
    add(f"- Features: {len(feature_cols)} (the Part 4 processed features, reused unchanged)")
    add(f"- Training samples: {len(X_train)} | Test samples: {len(y_test)}")
    add(f"- Training class distribution (0=BENIGN, 1=ATTACK): "
        f"{y_train.value_counts().sort_index().to_dict()}")
    add("- Train/test strategy: the Part 4 80/20 stratified split (random_state=42),")
    add("  reused as-is — no new split was created.")
    add(f"- CV strategy for tuning: StratifiedKFold(n_splits={cfg.CV_FOLDS}, "
        f"shuffle={cfg.CV_SHUFFLE}, random_state={cfg.RANDOM_STATE}) inside RandomizedSearchCV.")
    add(f"- Optimization metric: {cfg.OPTIMIZATION_SCORING.upper()} for the ATTACK class.")
    add("  F1 balances precision and recall; it is chosen over accuracy because the")
    add("  data is imbalanced and an IDS must find attacks, not just look accurate.")
    add("- Models: Logistic Regression, Random Forest, XGBoost")
    add("- Imbalance handling: LR/RF use class_weight (searched); XGBoost uses")
    add("  scale_pos_weight computed from the training set (documented in BASELINE_PARAMS).")
    add("")
    add("## Baseline Results")
    add("")
    add("Baseline configurations (documented parameters only):")
    add("")
    for name in MODEL_NAMES:
        add(f"- {name}: {BASELINE_PARAMS[name]}")
    add("")
    add("| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR |")
    add("| ----- | -------- | --------- | ------ | -- | ------- | --- | --- |")
    for r in baseline_results:
        add(f"| {r['model']} | {r['accuracy']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} | "
            f"{r['f1']:.4f} | {r['roc_auc']:.4f} | {r['false_positive_rate']:.4f} | "
            f"{r['false_negative_rate']:.4f} |")
    add("")
    add("Note: baseline metrics were measured on the test set as a pre-tuning reference")
    add("snapshot, as prescribed by the experiment design; the final comparison below is")
    add("the authoritative evaluation, and using the test set for both is recorded as a")
    add("limitation.")
    add("")
    add("## Optimization")
    add("")
    add(f"- Search method: RandomizedSearchCV (n_iter={cfg.SEARCH_N_ITER}, "
        f"cv={cfg.SEARCH_CV}, scoring='{cfg.OPTIMIZATION_SCORING}', "
        f"random_state={cfg.RANDOM_STATE})")
    add("- Full per-parameter-combination CV results: reports/cv_results/*.csv")
    add("")
    add("| Model | Best parameters | Best CV score (F1) | Duration (s) |")
    add("| ----- | --------------- | ------------------ | ------------ |")
    for name in MODEL_NAMES:
        record = tuned[name]
        add(f"| {name} | {record['best_params']} | {record['best_cv_score']:.4f} | "
            f"{record['duration_seconds']} |")
    add("")
    add("## Optimized Results (final test-set evaluation)")
    add("")
    add("Each selected configuration was re-fitted on the complete training set, then")
    add("evaluated once on the untouched test set.")
    add("")
    add("| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR | TP | TN | FP | FN |")
    add("| ----- | -------- | --------- | ------ | -- | ------- | --- | --- | -- | -- | -- | -- |")
    for r in optimized_results:
        add(f"| {r['model']} | {r['accuracy']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} | "
            f"{r['f1']:.4f} | {r['roc_auc']:.4f} | {r['false_positive_rate']:.4f} | "
            f"{r['false_negative_rate']:.4f} | {r['true_positives']} | {r['true_negatives']} | "
            f"{r['false_positives']} | {r['false_negatives']} |")
    add("")
    add("## Model Comparison")
    add("")
    add("Attack recall: " + ", ".join(
        f"{r['model']} {r['recall']:.4f}" for r in optimized_results
    ))
    add("Attack F1: " + ", ".join(
        f"{r['model']} {r['f1']:.4f}" for r in optimized_results
    ))
    add("False positives on the test set: " + ", ".join(
        f"{r['model']} {r['false_positives']}" for r in optimized_results
    ))
    add("False negatives on the test set: " + ", ".join(
        f"{r['model']} {r['false_negatives']}" for r in optimized_results
    ))
    add("")
    add(f"The experiment suggests that, on this development subset, **{best_model}**")
    add(f"offers the best balance under the stated criterion: {criterion}.")
    add("This is a baseline-stage finding on a lab dataset — not a proof of")
    add("superiority in production.")
    add("")
    add("## Model Agreement (exploratory)")
    add("")
    add(f"- Samples compared: {agreement['samples']}")
    add(f"- All three models agree on {agreement['all_agree_percentage']:.1f}% of samples")
    for name_a in MODEL_NAMES:
        for name_b in MODEL_NAMES:
            key = f"{name_a}_vs_{name_b}_agree_percentage"
            if key in agreement:
                add(f"- {name_a} vs {name_b}: {agreement[key]:.1f}% agreement")
    add("Disagreement is exploratory — it is not a ranking signal.")
    add("")
    add("## Threshold Analysis (training-only data)")
    add("")
    for name in MODEL_NAMES:
        t = threshold_summary[name]
        add(f"- {name}: best validation-F1 threshold = {t['best_threshold']:.2f} "
            f"(validation F1 = {t['best_f1']:.4f})")
    add("The default 0.5 threshold was kept for the final test evaluation; the selected")
    add("thresholds above are reported for later deployment phases. Full sweep:")
    add("reports/threshold_analysis.csv.")
    add("")
    add("## Feature Importance")
    add("")
    add("These features contributed most strongly to the fitted models according to")
    add("their feature-importance measure. This is model-specific association, NOT")
    add("proof of causation. See reports/feature_importance_random_forest.csv and")
    add("reports/feature_importance_xgboost.csv.")
    add("")
    add("## Limitations")
    add("")
    add("- Public-dataset limitations: CIC-IDS2017 was captured in a lab in 2017; the")
    add("  traffic may not match other networks.")
    add("- Possible class imbalance: the subset is dominated by BENIGN traffic; class")
    add("  weighting mitigates but does not remove the problem.")
    add("- Overfitting risk: CV-based selection reduces it, but the test set is a single")
    add("  holdout from the same capture — no external validation yet.")
    add("- The test set was used for the baseline reference snapshot before tuning,")
    add("  which slightly reduces its strictness as a holdout (recorded, not hidden).")
    add("- No real-time traffic validation yet.")
    add("- Hyperparameter search spaces are deliberately small (baseline-stage).")
    add("")
    add("## Reproducibility")
    add("")
    add("```powershell")
    add(".venv\\Scripts\\Activate.ps1")
    add("python -m src.preprocessing.pipeline        # once: Part 4 processed data")
    add("python -m src.training.train_binary         # Part 5 baselines (optional)")
    add("python -m src.training.model_comparison     # Part 6: baselines -> tuning -> final eval")
    add("python -m pytest tests -q")
    add("```")
    add("")
    add("Configuration: config/model_config.py (random_state=42, 5-fold stratified CV,")
    add("scoring=F1, search spaces). All metrics above are actual measured values.")
    add("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(L), encoding="utf-8")
    return path


# ---------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------

def main() -> int:
    print("SentinelAI - Part 6: advanced model comparison & optimization")
    print(f"scoring={cfg.OPTIMIZATION_SCORING} cv={cfg.CV_FOLDS}-fold "
          f"random_state={cfg.RANDOM_STATE}")

    try:
        feature_cols = load_feature_columns()
        X_train, y_train = load_training_data(feature_cols=feature_cols)
        X_test, y_test = load_test_data(feature_cols=feature_cols)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        return 1

    problems = validate_training_inputs(X_train, y_train, X_test, y_test, feature_cols)
    if problems:
        print("STOP: the processed data failed validation:")
        for p in problems:
            print(f"  - {p}")
        return 1

    scale_pos_weight = compute_scale_pos_weight(y_train)
    print(f"Training samples: {len(X_train)} | Test samples: {len(X_test)} | "
          f"Features: {len(feature_cols)}")
    print(f"XGBoost scale_pos_weight: {scale_pos_weight:.4f}")

    # ---- 1) BASELINES ------------------------------------------------
    print("\n[1/5] Training and evaluating baselines ...")
    baseline_builders = {
        "logistic_regression": build_logistic_baseline,
        "random_forest": build_random_forest_baseline,
        "xgboost": lambda: build_xgboost_baseline(scale_pos_weight),
    }
    baseline_results = []
    for name in MODEL_NAMES:
        model = baseline_builders[name]().fit(X_train, y_train)
        baseline_results.append(evaluate_on_test(name, model, X_test, y_test))
        print(f"  {name}: f1={baseline_results[-1]['f1']:.4f} "
              f"recall={baseline_results[-1]['recall']:.4f}")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    _results_frame(baseline_results).to_json(REPORTS_DIR / "baseline_model_results.json", indent=2, orient="records")
    _results_frame(baseline_results).to_csv(REPORTS_DIR / "baseline_model_results.csv", index=False)

    # ---- 2) HYPERPARAMETER OPTIMIZATION (training set only) ----------
    print("\n[2/5] Hyperparameter optimization (training set only) ...")
    tuned_estimators = {
        "logistic_regression": (build_logistic_tuned_estimator(), cfg.LOGISTIC_PARAM_GRID),
        "random_forest": (build_random_forest_tuned_estimator(), cfg.RANDOM_FOREST_PARAM_GRID),
        "xgboost": (build_xgboost_tuned_estimator(scale_pos_weight), cfg.XGBOOST_PARAM_GRID),
    }
    tuned = {}
    for name in MODEL_NAMES:
        estimator, grid = tuned_estimators[name]
        tuned[name] = tune_and_record(estimator, grid, name, X_train, y_train, CV_DIR)
        print(f"  {name}: best_cv_f1={tuned[name]['best_cv_score']:.4f} "
              f"({tuned[name]['duration_seconds']}s)")
        # checkpoint after each model so a long run cannot lose completed
        # tunings if a later model fails
        checkpoint = {
            n: {
                "best_params": t["best_params"],
                "best_cv_score": t["best_cv_score"],
                "duration_seconds": t["duration_seconds"],
            }
            for n, t in tuned.items()
        }
        (REPORTS_DIR / "part6_tuning_checkpoint.json").write_text(
            json.dumps(checkpoint, indent=2), encoding="utf-8"
        )

    # ---- 3) FINAL TEST EVALUATION (optimized models) -----------------
    print("\n[3/5] Final evaluation on the untouched test set ...")
    optimized_results = []
    optimized_models = {}
    for name in MODEL_NAMES:
        model = tuned[name]["search"].best_estimator_  # re-fitted on full train
        optimized_models[name] = model
        optimized_results.append(evaluate_on_test(name, model, X_test, y_test))
        print(f"  {name}: accuracy={optimized_results[-1]['accuracy']:.4f} "
              f"f1={optimized_results[-1]['f1']:.4f} "
              f"recall={optimized_results[-1]['recall']:.4f} "
              f"fpr={optimized_results[-1]['false_positive_rate']:.4f}")
    _results_frame(optimized_results).to_json(REPORTS_DIR / "optimized_model_results.json", indent=2, orient="records")
    _results_frame(optimized_results).to_csv(REPORTS_DIR / "optimized_model_results.csv", index=False)

    # ---- 4) COMPARISON + FIGURES -------------------------------------
    print("\n[4/5] Comparison reports and figures ...")
    comparison = _results_frame(optimized_results)[
        ["model", "accuracy", "precision", "recall", "f1", "roc_auc",
         "false_positive_rate", "false_negative_rate"]
    ]
    comparison.to_csv(REPORTS_DIR / "model_comparison.csv", index=False)
    comparison_lines = ["# Model Comparison (optimized models, test set)", ""]
    comparison_lines.append(
        "| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR |\n"
        "| ----- | -------- | --------- | ------ | -- | ------- | --- | --- |"
    )
    for _, row in comparison.iterrows():
        comparison_lines.append(
            f"| {row['model']} | {row['accuracy']:.4f} | {row['precision']:.4f} | "
            f"{row['recall']:.4f} | {row['f1']:.4f} | {row['roc_auc']:.4f} | "
            f"{row['false_positive_rate']:.4f} | {row['false_negative_rate']:.4f} |"
        )
    comparison_lines.append("")
    (REPORTS_DIR / "model_comparison.md").write_text("\n".join(comparison_lines), encoding="utf-8")

    best_model, criterion = select_best_model(optimized_results)

    plot_metric_comparison(optimized_results, FIGURES_DIR / "model_comparison_metrics.png")
    roc_pairs = []
    for r in optimized_results:
        fpr, tpr, _ = roc_curve(y_test, r["y_proba"], pos_label=1)
        roc_pairs.append((r["model"], fpr, tpr, r["roc_auc"]))
    plot_roc_curves(roc_pairs, FIGURES_DIR / "optimized_roc_curves.png")
    for r in optimized_results:
        from src.evaluation.metrics import calculate_confusion_matrix

        cm = calculate_confusion_matrix(y_test, r["y_pred"])
        plot_confusion_matrix(
            cm,
            f"{r['model']} (optimized) - confusion matrix (test set)",
            FIGURES_DIR / f"optimized_{r['model']}_confusion_matrix.png",
        )

    # feature importance (RF and XGBoost)
    imp_rf = pd.DataFrame(
        {"feature": feature_cols, "importance": optimized_models["random_forest"].feature_importances_}
    ).sort_values("importance", ascending=False)
    imp_xgb = pd.DataFrame(
        {"feature": feature_cols, "importance": optimized_models["xgboost"].feature_importances_}
    ).sort_values("importance", ascending=False)
    imp_rf.to_csv(REPORTS_DIR / "feature_importance_random_forest.csv", index=False)
    imp_xgb.to_csv(REPORTS_DIR / "feature_importance_xgboost.csv", index=False)
    plot_feature_importance_comparison(imp_rf, imp_xgb, FIGURES_DIR / "feature_importance_comparison.png")

    # model agreement
    agreement = agreement_summary(
        {r["model"]: r["y_pred"] for r in optimized_results}
    )
    pd.DataFrame([agreement]).to_csv(REPORTS_DIR / "model_agreement.csv", index=False)

    # threshold analysis (training-only validation slice)
    sub_train_idx, sub_val_idx = train_test_split(
        X_train.index,
        test_size=cfg.THRESHOLD_VALIDATION_SIZE,
        random_state=cfg.RANDOM_STATE,
        stratify=y_train,
    )
    X_sub, y_sub = X_train.loc[sub_train_idx], y_train.loc[sub_train_idx]
    X_val, y_val = X_train.loc[sub_val_idx], y_train.loc[sub_val_idx]
    threshold_summary = {}
    threshold_tables = []
    for name in MODEL_NAMES:
        probe = clone(optimized_models[name]).fit(X_sub, y_sub)
        y_proba = probe.predict_proba(X_val)[:, 1]
        table = threshold_metrics(y_val, y_proba, cfg.THRESHOLD_GRID)
        table.insert(0, "model", name)
        threshold_tables.append(table)
        best_t, best_f1 = select_best_threshold(y_val, y_proba, cfg.THRESHOLD_GRID, cfg.THRESHOLD_METRIC)
        threshold_summary[name] = {"best_threshold": best_t, "best_f1": best_f1}
    threshold_table = pd.concat(threshold_tables, ignore_index=True)
    threshold_table.to_csv(REPORTS_DIR / "threshold_analysis.csv", index=False)
    plot_threshold_analysis(threshold_table, threshold_summary, FIGURES_DIR / "threshold_analysis.png")

    # ---- 5) ARTIFACTS + RESEARCH REPORT ------------------------------
    print("\n[5/5] Saving optimized models and research report ...")
    for name in MODEL_NAMES:
        record = tuned[name]
        save_model(
            optimized_models[name],
            MODELS_DIR / f"{name}_optimized.joblib",
            metadata={
                "model_name": f"{name}_optimized",
                "dataset": DATASET_NAME,
                "target": TARGET_NAME,
                "random_state": RANDOM_STATE,
                "parameters": record["best_params"],
                "baseline_parameters": BASELINE_PARAMS[name],
                "feature_count": len(feature_cols),
                "training_samples": len(X_train),
                "cv_strategy": f"StratifiedKFold(n_splits={cfg.CV_FOLDS}, shuffle={cfg.CV_SHUFFLE}, random_state={cfg.RANDOM_STATE})",
                "optimization_metric": cfg.OPTIMIZATION_SCORING,
                "best_cv_score": record["best_cv_score"],
                "created": datetime.datetime.now().isoformat(timespec="seconds"),
                "note": "Tuned on the training set only; test set used only for final evaluation.",
            },
        )

    write_part6_report(
        baseline_results=baseline_results,
        tuned=tuned,
        optimized_results=optimized_results,
        best_model=best_model,
        criterion=criterion,
        agreement=agreement,
        threshold_summary=threshold_summary,
        feature_cols=feature_cols,
        X_train=X_train,
        y_train=y_train,
        y_test=y_test,
        path=REPORTS_DIR / "part6_model_comparison.md",
    )

    print(f"\nBest model on the stated criterion: {best_model} ({criterion}).")
    print("All results, reports and figures are under reports/; models under models/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
