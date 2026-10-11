"""
SentinelAI — binary classification baseline training (Part 5).

Research question:
    "Can basic machine-learning models distinguish benign network
    traffic from malicious network traffic using the prepared
    network-flow features?"

Two baselines are trained on the Part 4 processed data:

    * Logistic Regression (class_weight="balanced", max_iter=2000)
    * Random Forest (200 trees, class_weight="balanced_subsample")

Run from the project root:

    python -m src.training.train_binary

This module REUSES the Part 4 artifacts exactly as they were created:
the processed train/test CSVs, the saved feature-column list, and the
Part 4 80/20 stratified split. No new random split is created and no
preprocessing is re-fitted. The test set is not touched during
training.
"""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from src.training.model_utils import save_model

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
ARTIFACTS_DIR = PROJECT_ROOT / "models" / "preprocessing"
MODELS_DIR = PROJECT_ROOT / "models"

LOGISTIC_MODEL_PATH = MODELS_DIR / "logistic_regression.joblib"
RANDOM_FOREST_MODEL_PATH = MODELS_DIR / "random_forest.joblib"

RANDOM_STATE = 42

DATASET_NAME = "CIC-IDS2017 development subset (processed by Part 4 pipeline)"
TARGET_NAME = "binary_label (BENIGN=0, ATTACK=1)"


# ---------------------------------------------------------------
#  Loading (reuses Part 4 artifacts — no duplicated preprocessing)
# ---------------------------------------------------------------

def load_feature_columns(artifacts_dir: Path = ARTIFACTS_DIR) -> list[str]:
    """Load the final feature list saved by the Part 4 pipeline."""
    import json

    path = artifacts_dir / "feature_columns.json"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run 'python -m src.preprocessing.pipeline' first "
            "(it requires the dataset in data/raw/ — see DEVELOPMENT.md)."
        )
    return json.loads(path.read_text(encoding="utf-8"))["feature_columns"]


def _load_processed(
    csv_path: Path, feature_cols: list[str]
) -> tuple[pd.DataFrame, pd.Series]:
    """Load one processed CSV and return (X, y_binary) using the saved feature list."""
    if not csv_path.exists():
        raise FileNotFoundError(
            f"{csv_path} not found. Run 'python -m src.preprocessing.pipeline' first "
            "(it requires the dataset in data/raw/ — see DEVELOPMENT.md)."
        )
    df = pd.read_csv(csv_path)
    missing = [c for c in feature_cols + ["binary_label"] if c not in df.columns]
    if missing:
        raise ValueError(
            f"{csv_path} is missing expected columns {missing} — it does not match "
            "the Part 4 artifact structure."
        )
    return df[feature_cols], df["binary_label"]


def load_training_data(
    processed_dir: Path = PROCESSED_DIR, feature_cols: list[str] | None = None
) -> tuple[pd.DataFrame, pd.Series]:
    """Load the processed training set as (X_train, y_train_binary)."""
    if feature_cols is None:
        feature_cols = load_feature_columns()
    return _load_processed(processed_dir / "train.csv", feature_cols)


def load_test_data(
    processed_dir: Path = PROCESSED_DIR, feature_cols: list[str] | None = None
) -> tuple[pd.DataFrame, pd.Series]:
    """Load the processed test set as (X_test, y_test_binary)."""
    if feature_cols is None:
        feature_cols = load_feature_columns()
    return _load_processed(processed_dir / "test.csv", feature_cols)


# ---------------------------------------------------------------
#  Validation (STOP and report if anything is wrong)
# ---------------------------------------------------------------

def validate_training_inputs(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    feature_cols: list[str],
) -> list[str]:
    """Return a list of problems (empty list = inputs are valid)."""
    problems = []

    # feature dimensions and order
    for name, frame in (("train", X_train), ("test", X_test)):
        if frame.shape[1] != len(feature_cols):
            problems.append(
                f"{name}: {frame.shape[1]} feature columns, expected {len(feature_cols)}"
            )
        if list(frame.columns) != list(feature_cols):
            problems.append(f"{name}: feature names/order do not match the saved feature list")

    # rows vs labels
    if len(X_train) != len(y_train):
        problems.append(f"train: {len(X_train)} rows but {len(y_train)} labels")
    if len(X_test) != len(y_test):
        problems.append(f"test: {len(X_test)} rows but {len(y_test)} labels")

    # binary target validity
    for name, y in (("train", y_train), ("test", y_test)):
        if not set(pd.unique(y.dropna())) <= {0, 1}:
            problems.append(f"{name}: target contains values outside {{0, 1}}")
        if y.isna().any():
            problems.append(f"{name}: target contains NaN values")

    # no NaN / infinite values in features
    for name, frame in (("train", X_train), ("test", X_test)):
        if frame.isna().any().any():
            problems.append(f"{name}: features contain NaN values")
        numeric = frame.select_dtypes(include="number")
        if np.isinf(numeric).any().any():
            problems.append(f"{name}: features contain infinite values")

    return problems


# ---------------------------------------------------------------
#  Baseline models (reproducible, simple, documented)
# ---------------------------------------------------------------

def train_logistic_regression(
    X_train: pd.DataFrame, y_train: pd.Series, *, random_state: int = RANDOM_STATE
) -> LogisticRegression:
    """Train the Logistic Regression baseline.

    - max_iter=2000 so convergence can be reached on scaled features
    - class_weight="balanced" because the data is imbalanced (recorded
      in the metadata and in the Part 5 summary report)
    - features are NOT scaled again here: Part 4 already standardized
      them, and re-scaling would silently change the preprocessing
      design.
    """
    model = LogisticRegression(
        max_iter=2000, class_weight="balanced", random_state=random_state
    )
    return model.fit(X_train, y_train)


def train_random_forest(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    *,
    random_state: int = RANDOM_STATE,
    n_estimators: int = 200,
) -> RandomForestClassifier:
    """Train the Random Forest baseline.

    - 200 trees, random_state=42 (reproducible)
    - class_weight="balanced_subsample" for the imbalanced data
      (recorded in the metadata and in the Part 5 summary report)
    """
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        class_weight="balanced_subsample",
        n_jobs=-1,
    )
    return model.fit(X_train, y_train)


def build_model_metadata(
    name: str, params: dict, *, feature_count: int, training_samples: int
) -> dict:
    """Build the metadata dict that is saved next to a trained model."""
    return {
        "model_name": name,
        "dataset": DATASET_NAME,
        "target": TARGET_NAME,
        "random_state": RANDOM_STATE,
        "parameters": params,
        "class_weight": "balanced" if name == "logistic_regression" else "balanced_subsample",
        "feature_count": feature_count,
        "training_samples": training_samples,
        "created": datetime.datetime.now().isoformat(timespec="seconds"),
        "note": "Test set was not used during training.",
    }


# ---------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------

def main() -> int:
    print("SentinelAI - binary baseline training (Part 5)")
    print(f"random_state={RANDOM_STATE} | reuses the Part 4 train/test split")

    try:
        feature_cols = load_feature_columns()
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1

    try:
        X_train, y_train = load_training_data(feature_cols=feature_cols)
        X_test, y_test = load_test_data(feature_cols=feature_cols)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1

    problems = validate_training_inputs(X_train, y_train, X_test, y_test, feature_cols)
    if problems:
        print("STOP: the processed data failed validation:")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(f"Training samples: {len(X_train)} | Test samples: {len(X_test)}")
    print(f"Features: {len(feature_cols)}")
    print(f"Training class distribution (0=BENIGN, 1=ATTACK): "
          f"{y_train.value_counts().sort_index().to_dict()}")

    lr = train_logistic_regression(X_train, y_train)
    rf = train_random_forest(X_train, y_train)

    lr_path = save_model(
        lr,
        LOGISTIC_MODEL_PATH,
        metadata=build_model_metadata(
            "logistic_regression",
            {"max_iter": 2000, "class_weight": "balanced"},
            feature_count=len(feature_cols),
            training_samples=len(X_train),
        ),
    )
    rf_path = save_model(
        rf,
        RANDOM_FOREST_MODEL_PATH,
        metadata=build_model_metadata(
            "random_forest",
            {"n_estimators": 200, "class_weight": "balanced_subsample"},
            feature_count=len(feature_cols),
            training_samples=len(X_train),
        ),
    )
    print(f"Saved: {lr_path}")
    print(f"Saved: {rf_path}")
    print("Next: python -m src.evaluation.evaluate_binary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
