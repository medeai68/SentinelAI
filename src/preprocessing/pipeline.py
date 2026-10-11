"""
SentinelAI — preprocessing pipeline (Part 4).

    Raw data -> Loading -> Cleaning -> Validation -> Feature selection
    -> Label encoding -> Train/test preparation -> Processed dataset

Correctness rules enforced here:

  * raw files are never modified;
  * duplicates and identifier/leakage columns are handled before
    splitting (row-level and schema-level decisions);
  * the train/test split (80/20, stratified, random_state=42) happens
    BEFORE any imputer or scaler is fitted;
  * imputer and scaler statistics come from the TRAINING split only;
  * the test set is only transformed — never used for fitting — so it
    stays unseen until model evaluation in later phases.

Run from the project root:

    python -m src.preprocessing.pipeline
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline as SklearnPipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from src.data.dataset_loader import DatasetLoaderError, find_csv_files, load_csv
from src.data.inspect_dataset import detect_label_column
from src.preprocessing.cleaning import (
    clean_column_names,
    coerce_numeric_columns,
    drop_constant_columns,
    drop_empty_columns,
    identify_leakage_columns,
    remove_duplicate_rows,
    replace_infinite_with_nan,
)
from src.preprocessing.label_encoding import (
    build_binary_target,
    build_multiclass_target,
    save_label_mapping,
    standardize_label_values,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORTS_DIR = PROJECT_ROOT / "reports"
ARTIFACTS_DIR = PROJECT_ROOT / "models" / "preprocessing"

RANDOM_STATE = 42
TEST_SIZE = 0.2


class PreprocessingPipeline:
    """Reproducible preprocessing pipeline for the SentinelAI dataset."""

    def __init__(self, *, random_state: int = RANDOM_STATE, test_size: float = TEST_SIZE):
        self.random_state = random_state
        self.test_size = test_size
        self.decisions: list[dict] = []  # every column removal/conversion, documented
        self.summary: dict = {}

    # ---------------------------------------------------------
    #  Loading
    # ---------------------------------------------------------

    def load_raw(self, raw_dir: Path = RAW_DIR) -> pd.DataFrame:
        """Load and concatenate every CSV in raw_dir (raw files untouched)."""
        files = find_csv_files(raw_dir)
        if not files:
            raise DatasetLoaderError(f"No CSV files found in {raw_dir}")
        frames = [clean_column_names(load_csv(f)) for f in files]
        combined = pd.concat(frames, ignore_index=True)
        self.summary["source_files"] = [f.name for f in files]
        return combined

    # ---------------------------------------------------------
    #  Cleaning (row/schema decisions — safe before splitting)
    # ---------------------------------------------------------

    def clean(self, df: pd.DataFrame, label_col: str) -> pd.DataFrame:
        """Remove duplicates, standardize labels, drop leakage columns,
        coerce numeric columns, and replace infinities with NaN."""
        df, n_dup = remove_duplicate_rows(df)
        self.summary["duplicates_removed"] = n_dup

        df[label_col] = standardize_label_values(df[label_col])

        leakage = identify_leakage_columns(df)
        df = df.drop(columns=[d["feature"] for d in leakage])
        self.decisions.extend(leakage)

        df, type_decisions = coerce_numeric_columns(df, exclude=[label_col])
        self.decisions.extend(type_decisions)

        df, n_inf = replace_infinite_with_nan(df)
        self.summary["infinite_replaced_with_nan"] = n_inf
        return df

    # ---------------------------------------------------------
    #  Split (BEFORE any fitting)
    # ---------------------------------------------------------

    def split(
        self,
        df: pd.DataFrame,
        multiclass_labels: pd.Series,
        binary_labels: pd.Series,
    ) -> tuple[pd.Index, pd.Index]:
        """Stratified reproducible split on the multiclass labels.

        If a class has too few records for multiclass stratification,
        the split falls back to binary stratification (documented in
        the summary).
        """
        try:
            train_idx, test_idx = train_test_split(
                df.index,
                test_size=self.test_size,
                random_state=self.random_state,
                stratify=multiclass_labels,
            )
            self.summary["stratification"] = "multiclass"
        except ValueError:
            train_idx, test_idx = train_test_split(
                df.index,
                test_size=self.test_size,
                random_state=self.random_state,
                stratify=binary_labels,
            )
            self.summary["stratification"] = "binary (fallback: a class had too few records)"
        return train_idx, test_idx

    # ---------------------------------------------------------
    #  Full pipeline
    # ---------------------------------------------------------

    def run(
        self,
        raw_dir: Path = RAW_DIR,
        processed_dir: Path = PROCESSED_DIR,
        artifacts_dir: Path = ARTIFACTS_DIR,
        reports_dir: Path = REPORTS_DIR,
    ) -> dict:
        raw = self.load_raw(raw_dir)
        self.summary["raw_records"] = int(len(raw))
        self.summary["raw_features"] = int(len(raw.columns))
        label_col = detect_label_column(raw)
        self.summary["label_column"] = label_col
        self.summary["random_state"] = self.random_state
        self.summary["test_fraction"] = self.test_size  # the split fraction (e.g. 0.2)

        cleaned = self.clean(raw, label_col)
        self.summary["records_after_cleaning"] = int(len(cleaned))
        self.cleaned_df = cleaned

        # --- targets ---------------------------------------------
        binary = build_binary_target(cleaned[label_col])
        multiclass, encoder, multiclass_mapping = build_multiclass_target(cleaned[label_col])
        binary_mapping = {"BENIGN": 0, "ATTACK": 1}

        # --- split, then fit preprocessing on TRAIN only ---------
        train_idx, test_idx = self.split(cleaned, multiclass, binary)
        train_raw = cleaned.loc[train_idx].copy()
        test_raw = cleaned.loc[test_idx].copy()
        self.summary["train_size"] = int(len(train_raw))
        self.summary["test_size"] = int(len(test_raw))

        # column decisions derived from the TRAINING split only
        train_clean, empty_decisions = drop_empty_columns(train_raw)
        train_clean, constant_decisions = drop_constant_columns(train_clean, ignore=[label_col])
        self.decisions.extend(empty_decisions + constant_decisions)
        drop_cols = [d["feature"] for d in empty_decisions + constant_decisions]
        test_clean = test_raw.drop(columns=[c for c in drop_cols if c in test_raw.columns])

        # --- feature matrix ---------------------------------------
        feature_cols = [c for c in train_clean.columns if c != label_col]
        numeric_cols = train_clean[feature_cols].select_dtypes(include="number").columns.tolist()
        non_numeric_cols = [c for c in feature_cols if c not in numeric_cols]

        transformers = []
        if numeric_cols:
            transformers.append(
                (
                    "numeric",
                    SklearnPipeline(
                        steps=[
                            ("imputer", SimpleImputer(strategy="median")),
                            ("scaler", StandardScaler()),
                        ]
                    ),
                    numeric_cols,
                )
            )
        if non_numeric_cols:
            # Documented decision: one-hot encoding only for genuinely
            # categorical features. High-cardinality identifiers (IPs,
            # Flow IDs) were already removed as leakage columns.
            transformers.append(
                (
                    "categorical",
                    SklearnPipeline(
                        steps=[
                            ("imputer", SimpleImputer(strategy="most_frequent")),
                            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
                        ]
                    ),
                    non_numeric_cols,
                )
            )
        self.summary["numeric_features"] = len(numeric_cols)
        self.summary["categorical_features"] = len(non_numeric_cols)
        preprocessor = ColumnTransformer(transformers, remainder="drop")

        X_train = train_clean[feature_cols]
        X_test = test_clean[feature_cols]
        X_train_proc = pd.DataFrame(
            preprocessor.fit_transform(X_train),
            columns=preprocessor.get_feature_names_out(),
        )
        X_test_proc = pd.DataFrame(
            preprocessor.transform(X_test),
            columns=preprocessor.get_feature_names_out(),
        )
        self.feature_cols = list(X_train_proc.columns)
        self.summary["final_features"] = len(self.feature_cols)

        # --- assemble final frames ---------------------------------
        train_final = self._assemble(
            X_train_proc,
            binary.loc[train_idx],
            multiclass.loc[train_idx],
            train_clean[label_col],
        )
        test_final = self._assemble(
            X_test_proc,
            binary.loc[test_idx],
            multiclass.loc[test_idx],
            test_clean[label_col],
        )

        # --- validation ---------------------------------------------
        problems = self.validate(train_final, test_final, self.feature_cols)
        self.summary["validation_problems"] = problems
        if problems:
            raise RuntimeError(
                "Processed data failed validation:\n" + "\n".join(f"  - {p}" for p in problems)
            )

        # label encoder must be reversible
        decoded = pd.Series(encoder.inverse_transform(multiclass), index=multiclass.index)
        if not decoded.equals(cleaned[label_col]):
            raise RuntimeError("Label encoder is not reversible — aborting.")

        # --- save artifacts -------------------------------------------
        processed_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        train_final.to_csv(processed_dir / "train.csv", index=False)
        test_final.to_csv(processed_dir / "test.csv", index=False)
        joblib.dump(preprocessor, artifacts_dir / "preprocessor.joblib")
        joblib.dump(encoder, artifacts_dir / "label_encoder.joblib")
        # feature_columns      = the processed (post-transform) column names,
        #                        used by the Part 5/6 loaders;
        # input_feature_columns = the RAW input feature names the fitted
        #                        preprocessor consumes, used by the Part 7
        #                        detection engine and the Part 10 PCAP
        #                        compatibility check.
        (artifacts_dir / "feature_columns.json").write_text(
            json.dumps(
                {
                    "feature_columns": self.feature_cols,
                    "input_feature_columns": feature_cols,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        save_label_mapping(
            reports_dir / "label_mapping.json", binary_mapping, multiclass_mapping
        )

        # --- keep frames for report generation --------------------------
        self.train_clean = train_clean
        self.train_final = train_final
        self.test_final = test_final
        self.preprocessor = preprocessor
        self.label_encoder = encoder
        self.binary_mapping = binary_mapping
        self.multiclass_mapping = multiclass_mapping

        self.summary["binary_mapping"] = binary_mapping
        self.summary["multiclass_mapping"] = multiclass_mapping
        self.summary["artifacts"] = {
            "train": str(processed_dir / "train.csv"),
            "test": str(processed_dir / "test.csv"),
            "preprocessor": str(artifacts_dir / "preprocessor.joblib"),
            "label_encoder": str(artifacts_dir / "label_encoder.joblib"),
            "label_mapping": str(reports_dir / "label_mapping.json"),
        }
        return self.summary

    @staticmethod
    def _assemble(
        features: pd.DataFrame,
        binary: pd.Series,
        multiclass: pd.Series,
        labels: pd.Series,
    ) -> pd.DataFrame:
        """Combine the processed features with the three label representations."""
        return pd.concat(
            [
                features.reset_index(drop=True),
                pd.Series(binary.values, name="binary_label"),
                pd.Series(multiclass.values, name="multiclass_label"),
                labels.reset_index(drop=True),
            ],
            axis=1,
        )

    @staticmethod
    def validate(
        train: pd.DataFrame, test: pd.DataFrame, feature_cols: list[str]
    ) -> list[str]:
        """Return a list of problems (empty list = processed data is valid)."""
        problems = []
        for name, df in (("train", train), ("test", test)):
            if df[feature_cols].isna().any().any():
                problems.append(f"{name}: unexpected NaN values remain in features")
            numeric = df[feature_cols].select_dtypes(include="number")
            if np.isinf(numeric).any().any():
                problems.append(f"{name}: infinite values remain in features")
            if not df["binary_label"].isin([0, 1]).all():
                problems.append(f"{name}: invalid binary labels")
            if df["multiclass_label"].isna().any():
                problems.append(f"{name}: invalid multiclass labels")
        if list(train.columns) != list(test.columns):
            problems.append("train and test columns differ")
        return problems


def main() -> int:
    """Run the pipeline and generate all Part 4 reports and figures."""
    print("SentinelAI preprocessing pipeline (Part 4)")
    print(f"random_state={RANDOM_STATE}, test_size={TEST_SIZE}")

    from src.preprocessing.reports import (
        write_class_imbalance,
        write_feature_decisions,
        write_feature_summary,
        write_preprocessing_summary,
    )
    from src.preprocessing.visualization import (
        plot_class_distribution,
        plot_selected_numeric_features,
    )

    pipeline = PreprocessingPipeline()
    try:
        summary = pipeline.run()
    except DatasetLoaderError as exc:
        print(f"ERROR: {exc}")
        print("Download the dataset into data/raw/ first (see DEVELOPMENT.md).")
        return 1

    cleaned = pipeline.cleaned_df
    label_col = summary["label_column"]

    # --- reports (actual computed values only) ---------------------
    write_feature_decisions(pipeline.decisions)
    write_feature_summary(
        feature_statistics_df(cleaned, label_col), pipeline.decisions
    )
    write_class_imbalance(cleaned[label_col])
    write_preprocessing_summary(summary, pipeline.decisions)
    print("Reports written to: reports/")

    # --- figures ----------------------------------------------------
    figures = [
        plot_class_distribution(
            cleaned[label_col],
            "Class distribution before preprocessing (raw subset)",
            REPORTS_DIR / "figures" / "class_distribution_raw.png",
        ),
        plot_class_distribution(
            pipeline.train_final["Label"],
            "Class distribution — training set",
            REPORTS_DIR / "figures" / "class_distribution_train.png",
        ),
        plot_class_distribution(
            pipeline.test_final["Label"],
            "Class distribution — test set",
            REPORTS_DIR / "figures" / "class_distribution_test.png",
        ),
    ]
    selected = [
        "Flow_Duration",
        "Total_Fwd_Packets",
        "Total_Backward_Packets",
        "Flow_Bytes/s",
        "Packet_Length_Mean",
        "Flow_Packets/s",
    ]
    selected = [c for c in selected if c in pipeline.train_clean.columns]
    if selected:
        figures.append(
            plot_selected_numeric_features(
                pipeline.train_clean,
                selected,
                REPORTS_DIR / "figures" / "numeric_feature_distributions.png",
            )
        )
    for f in figures:
        print(f"  {f}")

    print("\nSummary:")
    print(json.dumps(summary, indent=2, default=str))
    print("\nPreprocessing finished — processed data is ML-ready.")
    return 0


def feature_statistics_df(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    """Small wrapper used by main() for the feature summary report."""
    from src.preprocessing.feature_selection import feature_statistics

    return feature_statistics(df, label_columns=[label_col])


if __name__ == "__main__":
    sys.exit(main())
