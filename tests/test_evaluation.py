"""Tests for Part 5 evaluation: metric calculations, confusion matrix
counts, ROC-AUC, and prediction validation.

All cases are small hand-computed examples — deterministic, no external
data.
"""

import json

import numpy as np
import pandas as pd
import pytest
from sklearn.datasets import make_classification

from src.evaluation.metrics import (
    calculate_classification_metrics,
    calculate_confusion_matrix,
    calculate_roc_auc,
    confusion_matrix_counts,
    generate_classification_report,
    validate_predictions,
)


def test_confusion_matrix_counts_hand_computed():
    y_true = [0, 0, 1, 1]
    y_pred = [0, 1, 0, 1]
    assert confusion_matrix_counts(y_true, y_pred) == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}


def test_calculate_confusion_matrix_shape_and_values():
    cm = calculate_confusion_matrix([0, 0, 1, 1], [0, 1, 0, 1])
    assert cm.shape == (2, 2)
    assert (cm == np.array([[1, 1], [1, 1]])).all()


def test_classification_metrics_hand_computed():
    m = calculate_classification_metrics([0, 0, 1, 1], [0, 1, 0, 1])
    assert m["accuracy"] == 0.5
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
    assert m["f1"] == 0.5
    assert m["false_positive_rate"] == 0.5
    assert m["false_negative_rate"] == 0.5
    assert m["true_positives"] == 1 and m["true_negatives"] == 1
    assert m["false_positives"] == 1 and m["false_negatives"] == 1


def test_classification_metrics_perfect_detection():
    y_true = [0, 0, 1, 1, 1]
    y_pred = [0, 0, 1, 1, 1]
    m = calculate_classification_metrics(y_true, y_pred, y_proba=[0.1, 0.2, 0.9, 0.8, 0.95])
    assert m["accuracy"] == 1.0
    assert m["recall"] == 1.0
    assert m["false_positive_rate"] == 0.0
    assert m["false_negative_rate"] == 0.0
    assert m["roc_auc"] == 1.0


def test_roc_auc_perfect_and_inverted():
    assert calculate_roc_auc([0, 0, 1, 1], [0.1, 0.2, 0.9, 0.8]) == 1.0
    assert calculate_roc_auc([0, 0, 1, 1], [0.9, 0.8, 0.1, 0.2]) == 0.0


def test_metrics_contain_no_nan_or_inf():
    m = calculate_classification_metrics([0, 1, 1, 0, 1], [0, 1, 0, 0, 1],
                                         y_proba=[0.1, 0.9, 0.4, 0.3, 0.8])
    for key, value in m.items():
        assert not (isinstance(value, float) and (np.isnan(value) or np.isinf(value))), key


def test_generate_classification_report_contains_classes():
    report = generate_classification_report([0, 1, 1], [0, 1, 0])
    assert "BENIGN" in report and "ATTACK" in report


def test_validate_predictions_ok():
    assert validate_predictions([0, 1], [0, 1], y_proba=[0.2, 0.8]) == []


def test_validate_predictions_catches_problems():
    problems = validate_predictions([0, 1], [0, 1, 0])
    assert any("length mismatch" in p for p in problems)

    problems = validate_predictions([0, 1], [0, 2])
    assert any("outside {0, 1}" in p for p in problems)

    problems = validate_predictions([0, 1], [0, np.nan])
    assert any("NaN" in p for p in problems)

    problems = validate_predictions([0, 1], [0, 1], y_proba=[0.2, 1.5])
    assert any("outside [0, 1]" in p for p in problems)


# --- module wiring (regression: every name used in main() must exist) ---

def test_train_binary_imports_complete():
    import src.training.train_binary as tb

    assert callable(tb.save_model)
    assert callable(tb.validate_training_inputs)
    assert callable(tb.train_logistic_regression)
    assert callable(tb.train_random_forest)


def test_evaluate_binary_imports_complete():
    import src.evaluation.evaluate_binary as eb

    assert callable(eb.validate_model_artifact)
    assert callable(eb.load_model)
    assert callable(eb.load_training_data)
    assert callable(eb.load_test_data)


def test_evaluate_binary_end_to_end_with_fixture(tmp_path, monkeypatch):
    """Run evaluate_binary.main() against fixture models in temp dirs.

    Exercises the whole evaluation flow — loading, prediction, metrics,
    every report/CSV/figure writer — without needing the real dataset.
    Guards against NameError wiring bugs and broken file generation.
    """
    import src.evaluation.evaluate_binary as eb
    import src.training.train_binary as tb
    from src.training.model_utils import save_model

    X, y = make_classification(
        n_samples=120, n_features=6, n_informative=4, random_state=42
    )
    X = pd.DataFrame(X, columns=[f"f{i}" for i in range(6)])
    y = pd.Series(y, name="binary_label")

    # balanced, deterministic train/test split (both classes in both folds)
    test_idx = y[y == 0].index[:10].union(y[y == 1].index[:10])
    train_idx = y.index.difference(test_idx)

    lr_path = tmp_path / "logistic_regression.joblib"
    rf_path = tmp_path / "random_forest.joblib"
    # MODELS is built at import time, so patch the list itself; the path
    # constants are also patched for the direct load_model() calls in main().
    monkeypatch.setattr(
        eb,
        "MODELS",
        [("logistic_regression", lr_path), ("random_forest", rf_path)],
    )
    monkeypatch.setattr(eb, "LOGISTIC_MODEL_PATH", lr_path)
    monkeypatch.setattr(eb, "RANDOM_FOREST_MODEL_PATH", rf_path)
    monkeypatch.setattr(eb, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(eb, "FIGURES_DIR", tmp_path / "reports" / "figures")

    monkeypatch.setattr(eb, "load_feature_columns", lambda artifacts_dir=None: list(X.columns))
    monkeypatch.setattr(
        eb, "load_test_data",
        lambda processed_dir=None, feature_cols=None: (X.loc[test_idx], y.loc[test_idx]),
    )
    monkeypatch.setattr(
        eb, "load_training_data",
        lambda processed_dir=None, feature_cols=None: (X.loc[train_idx], y.loc[train_idx]),
    )

    lr = tb.train_logistic_regression(X.loc[train_idx], y.loc[train_idx])
    rf = tb.train_random_forest(X.loc[train_idx], y.loc[train_idx], n_estimators=10)
    save_model(
        lr, lr_path,
        metadata=tb.build_model_metadata(
            "logistic_regression", {"max_iter": 2000, "class_weight": "balanced"},
            feature_count=6, training_samples=len(train_idx),
        ),
    )
    save_model(
        rf, rf_path,
        metadata=tb.build_model_metadata(
            "random_forest", {"n_estimators": 10, "class_weight": "balanced_subsample"},
            feature_count=6, training_samples=len(train_idx),
        ),
    )

    assert eb.main() == 0

    reports = tmp_path / "reports"
    for name in (
        "model_results.json",
        "model_results.csv",
        "part5_model_summary.md",
        "logistic_regression_classification_report.txt",
        "random_forest_classification_report.txt",
        "random_forest_feature_importance.csv",
        "logistic_regression_coefficients.csv",
    ):
        assert (reports / name).exists(), f"missing report: {name}"

    figures = reports / "figures"
    for name in (
        "logistic_regression_confusion_matrix.png",
        "random_forest_confusion_matrix.png",
        "binary_roc_curves.png",
        "random_forest_feature_importance.png",
    ):
        assert (figures / name).exists(), f"missing figure: {name}"

    results = json.loads((reports / "model_results.json").read_text(encoding="utf-8"))
    assert len(results) == 2
    for r in results:
        for key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            value = r[key]
            assert not (isinstance(value, float) and (np.isnan(value) or np.isinf(value))), key
