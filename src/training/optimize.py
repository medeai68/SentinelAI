"""
SentinelAI — controlled hyperparameter optimization (Part 6).

RandomizedSearchCV over small, documented search spaces with
stratified 5-fold cross-validation. Tuning uses ONLY the training set;
the final test set is never passed to anything in this module.

All parameters come from config/model_config.py.
"""

from __future__ import annotations

import time
from pathlib import Path

import pandas as pd
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold

from config import model_config as cfg


def make_cv(
    *, n_splits: int = cfg.CV_FOLDS, shuffle: bool = cfg.CV_SHUFFLE, random_state: int = cfg.RANDOM_STATE
) -> StratifiedKFold:
    """Return the reproducible stratified CV splitter used for tuning."""
    return StratifiedKFold(n_splits=n_splits, shuffle=shuffle, random_state=random_state)


def tune_model(
    estimator,
    param_grid: dict,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    *,
    n_iter: int = cfg.SEARCH_N_ITER,
    scoring: str = cfg.OPTIMIZATION_SCORING,
    cv=None,
    random_state: int = cfg.RANDOM_STATE,
    n_jobs: int = cfg.SEARCH_N_JOBS,
) -> RandomizedSearchCV:
    """Run RandomizedSearchCV on the TRAINING set only.

    By design this function has no test-set parameter — the test set
    stays untouched until the final evaluation. With refit=True the
    returned search object contains best_estimator_, i.e. the best
    configuration already re-fitted on the complete training set.
    """
    if cv is None:
        cv = make_cv()
    search = RandomizedSearchCV(
        estimator=estimator,
        param_distributions=param_grid,
        n_iter=n_iter,
        scoring=scoring,
        cv=cv,
        random_state=random_state,
        n_jobs=n_jobs,
        refit=True,
    )
    search.fit(X_train, y_train)
    return search


def cv_results_table(search: RandomizedSearchCV, model_name: str) -> pd.DataFrame:
    """Return the full per-parameter-combination CV results as a DataFrame."""
    results = pd.DataFrame(search.cv_results_)
    keep = [c for c in ("params", "mean_test_score", "std_test_score", "rank_test_score") if c in results.columns]
    table = results[keep].copy()
    table.insert(0, "model", model_name)
    return table


def save_cv_results(search: RandomizedSearchCV, model_name: str, path: Path) -> Path:
    """Save the full CV results table (not only the best row) as CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    cv_results_table(search, model_name).to_csv(path, index=False)
    return path


def tune_and_record(
    estimator,
    param_grid: dict,
    model_name: str,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    cv_dir: Path,
) -> dict:
    """Tune one model, save its CV results CSV, and return a summary dict.

    The returned dict contains the fitted search object (with
    best_estimator_ re-fitted on the full training set), the best
    parameters, the best CV score and the wall-clock duration.
    """
    start = time.perf_counter()
    search = tune_model(estimator, param_grid, X_train, y_train)
    duration = time.perf_counter() - start
    save_cv_results(search, model_name, cv_dir / f"{model_name}_cv.csv")
    return {
        "model": model_name,
        "search": search,
        "best_params": search.best_params_,
        "best_cv_score": float(search.best_score_),
        "duration_seconds": round(duration, 1),
    }
