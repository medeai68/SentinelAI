"""Tests for Part 6: model comparison framework, hyperparameter search,
cross-validation, threshold analysis, agreement and best-model selection.

All fixtures are small and deterministic (random_state=42) — no
external data. XGBoost-specific tests skip if xgboost is not installed.
"""

import inspect

import numpy as np
import pandas as pd
import pytest
from sklearn.datasets import make_classification

from config import model_config as cfg
from src.evaluation.metrics import (
    agreement_summary,
    select_best_threshold,
    threshold_metrics,
)
from src.training.model_comparison import (
    build_logistic_baseline,
    build_logistic_tuned_estimator,
    build_random_forest_baseline,
    build_xgboost_baseline,
    compute_scale_pos_weight,
    evaluate_on_test,
    select_best_model,
)
from src.training.optimize import make_cv, tune_and_record, tune_model

try:
    import xgboost  # noqa: F401

    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False


@pytest.fixture
def fixture_data():
    """Deterministic binary dataset with 6 features (seed 42)."""
    X, y = make_classification(
        n_samples=240, n_features=6, n_informative=4, random_state=42
    )
    X = pd.DataFrame(X, columns=[f"f{i}" for i in range(6)])
    return X, pd.Series(y, name="binary_label")


# --- XGBoost availability ------------------------------------------------

@pytest.mark.skipif(not XGB_AVAILABLE, reason="xgboost is not installed")
def test_xgboost_available():
    assert xgboost.__version__


# --- model creation -------------------------------------------------------

def test_model_builders_return_estimators():
    lr = build_logistic_baseline()
    rf = build_random_forest_baseline()
    assert hasattr(lr, "fit") and hasattr(lr, "predict") and hasattr(lr, "predict_proba")
    assert hasattr(rf, "fit") and hasattr(rf, "predict") and hasattr(rf, "predict_proba")


@pytest.mark.skipif(not XGB_AVAILABLE, reason="xgboost is not installed")
def test_xgboost_builder_returns_estimator():
    xgb = build_xgboost_baseline(scale_pos_weight=4.0)
    assert hasattr(xgb, "fit") and hasattr(xgb, "predict_proba")


def test_compute_scale_pos_weight():
    y = pd.Series([0] * 80 + [1] * 20)
    assert compute_scale_pos_weight(y) == 4.0


# --- cross-validation -----------------------------------------------------

def test_make_cv_reproducible():
    cv1 = make_cv()
    cv2 = make_cv()
    assert cv1.n_splits == cfg.CV_FOLDS == 5
    for (a_train, a_test), (b_train, b_test) in zip(
        cv1.split(np.zeros(100), np.zeros(100)),
        cv2.split(np.zeros(100), np.zeros(100)),
    ):
        assert np.array_equal(a_train, b_train)
        assert np.array_equal(a_test, b_test)


# --- hyperparameter search (small, deterministic) --------------------------

def test_tune_model_small_search(fixture_data, tmp_path):
    X, y = fixture_data
    grid = {"C": [0.1, 1.0], "class_weight": ["balanced", None]}
    search = tune_model(build_logistic_tuned_estimator(), grid, X, y, n_iter=4, cv=3)
    assert search.best_params_ is not None
    assert isinstance(search.best_score_, float)

    record = tune_and_record(
        build_logistic_tuned_estimator(), grid, "logistic_regression", X, y, tmp_path
    )
    cv_csv = tmp_path / "logistic_regression_cv.csv"
    assert cv_csv.exists()
    table = pd.read_csv(cv_csv)
    assert {"mean_test_score", "std_test_score", "rank_test_score"} <= set(table.columns)
    assert len(table) >= 1


def test_tune_model_reproducible(fixture_data):
    X, y = fixture_data
    grid = {"C": [0.1, 1.0, 10.0], "class_weight": ["balanced", None]}
    s1 = tune_model(build_logistic_tuned_estimator(), grid, X, y, n_iter=4, cv=3)
    s2 = tune_model(build_logistic_tuned_estimator(), grid, X, y, n_iter=4, cv=3)
    assert s1.best_params_ == s2.best_params_
    assert s1.best_score_ == s2.best_score_


def test_tune_model_has_no_test_set_parameter():
    """The tuner structurally cannot receive the test set."""
    sig = inspect.signature(tune_model)
    assert not any("test" in name for name in sig.parameters)


# --- predictions -----------------------------------------------------------

def test_evaluate_on_test_shapes_and_values(fixture_data):
    X, y = fixture_data
    model = build_random_forest_baseline().fit(X.iloc[:180], y.iloc[:180])
    result = evaluate_on_test("random_forest", model, X.iloc[180:], y.iloc[180:])
    assert len(result["y_pred"]) == 60
    assert result["y_proba"].shape == (60,)
    assert not np.isnan(result["y_pred"]).any()
    assert not np.isnan(result["y_proba"]).any()
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        value = result[key]
        assert isinstance(value, float) and not (np.isnan(value) or np.isinf(value))


@pytest.mark.skipif(not XGB_AVAILABLE, reason="xgboost is not installed")
def test_xgboost_proba_shape(fixture_data):
    X, y = fixture_data
    model = build_xgboost_baseline(scale_pos_weight=1.0).fit(X.iloc[:180], y.iloc[:180])
    proba = model.predict_proba(X.iloc[180:])
    assert proba.shape == (60, 2)
    assert ((proba >= 0) & (proba <= 1)).all()


# --- threshold analysis ------------------------------------------------------

def test_threshold_metrics_hand_computed():
    table = threshold_metrics([0, 0, 1, 1], [0.1, 0.4, 0.6, 0.9], [0.5, 0.7])
    at_05 = table[table["threshold"] == 0.5].iloc[0]
    assert at_05["recall"] == 1.0
    assert at_05["f1"] == 1.0
    at_07 = table[table["threshold"] == 0.7].iloc[0]
    assert at_07["recall"] == 0.5


def test_select_best_threshold():
    best_t, best_f1 = select_best_threshold(
        [0, 0, 1, 1], [0.1, 0.4, 0.6, 0.9], [0.5, 0.7]
    )
    assert best_t == 0.5
    assert best_f1 == 1.0


# --- agreement analysis --------------------------------------------------------

def test_agreement_summary_all_agree():
    summary = agreement_summary(
        {
            "a": np.array([0, 1, 1, 0]),
            "b": np.array([0, 1, 1, 0]),
            "c": np.array([0, 1, 1, 0]),
        }
    )
    assert summary["samples"] == 4
    assert summary["all_agree_count"] == 4
    assert summary["all_agree_percentage"] == 100.0


def test_agreement_summary_partial():
    summary = agreement_summary(
        {
            "a": np.array([0, 1, 1, 0]),
            "b": np.array([0, 1, 0, 0]),
            "c": np.array([0, 1, 1, 0]),
        }
    )
    assert summary["all_agree_count"] == 3
    assert summary["a_vs_c_agree_percentage"] == 100.0
    assert summary["a_vs_b_agree_percentage"] == 75.0


# --- best model selection -----------------------------------------------------

def test_select_best_model_uses_f1_primary():
    results = [
        {"model": "a", "f1": 0.9, "recall": 0.8, "false_positive_rate": 0.1},
        {"model": "b", "f1": 0.9, "recall": 0.9, "false_positive_rate": 0.1},
        {"model": "c", "f1": 0.85, "recall": 1.0, "false_positive_rate": 0.0},
    ]
    best, criterion = select_best_model(results)
    assert best == "b"  # F1 tie broken by recall
    assert "F1" in criterion
