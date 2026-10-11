"""Tests for Part 4 preprocessing: cleaning, missing/infinite-value
handling, label encoding, train/test split and pipeline leakage rules.

The synthetic DataFrames used here are standard unit-test fixtures,
not fabricated dataset results. Integration against the real dataset
happens by running `python -m src.preprocessing.pipeline` on the
downloaded data.
"""

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

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
    standardize_label_values,
)
from src.preprocessing.pipeline import PreprocessingPipeline


def make_synthetic_flows(n: int = 200, seed: int = 0) -> pd.DataFrame:
    """Small synthetic flow table used as unit-test fixture."""
    rng = np.random.default_rng(seed)
    return pd.DataFrame(
        {
            "Flow_ID": [f"id-{i}" for i in range(n)],
            "Flow_Duration": rng.integers(1, 1000, n).astype(float),
            "Total_Fwd_Packets": rng.integers(1, 20, n).astype(float),
            "Total_Backward_Packets": rng.integers(1, 20, n).astype(float),
            "Src_IP": ["192.168.1.10"] * n,
            "Dst_IP": ["10.0.0.5"] * n,
            "Timestamp": ["03/07/2017 10:00:00"] * n,
            "Label": rng.choice(["BENIGN", "DoS", "PortScan"], n, p=[0.8, 0.1, 0.1]),
        }
    )


# --- cleaning ----------------------------------------------------------

def test_clean_column_names():
    df = pd.DataFrame({" Flow Duration ": [1], "Total Fwd Packets": [2]})
    assert list(clean_column_names(df).columns) == ["Flow_Duration", "Total_Fwd_Packets"]


def test_remove_duplicate_rows():
    df = pd.DataFrame({"a": [1, 1, 2], "b": [2, 2, 3]})
    cleaned, removed = remove_duplicate_rows(df)
    assert removed == 1
    assert len(cleaned) == 2


def test_drop_empty_columns_records_decision():
    df = pd.DataFrame({"a": [1.0, np.nan], "b": [np.nan, np.nan]})
    cleaned, decisions = drop_empty_columns(df)
    assert "b" not in cleaned.columns
    assert decisions and decisions[0]["feature"] == "b"
    assert decisions[0]["reason"]


def test_drop_constant_columns_ignores_listed():
    df = pd.DataFrame({"a": [1, 1, 1], "b": [1, 2, 3]})
    cleaned, decisions = drop_constant_columns(df, ignore=["b"])
    assert "a" not in cleaned.columns and "b" in cleaned.columns


def test_replace_infinite_with_nan():
    df = pd.DataFrame({"a": [1.0, np.inf, -np.inf, 2.0]})
    cleaned, count = replace_infinite_with_nan(df)
    assert count == 2
    assert cleaned["a"].isna().sum() == 2


def test_coerce_numeric_columns_converts_numbers_keeps_text():
    df = pd.DataFrame({"x": ["1", "2", "Infinity"], "name": ["a", "b", "c"]})
    converted, decisions = coerce_numeric_columns(df)
    assert converted["x"].dtype == "float64"
    assert pd.api.types.is_string_dtype(converted["name"].dtype)  # stays text
    kept = [d for d in decisions if d["feature"] == "name"]
    assert kept and kept[0]["decision"] == "kept as categorical"


def test_identify_leakage_columns_finds_identifiers():
    df = make_synthetic_flows()
    decisions = identify_leakage_columns(df)
    found = {d["feature"] for d in decisions}
    assert {"Flow_ID", "Src_IP", "Dst_IP", "Timestamp"} <= found
    for d in decisions:
        assert d["decision"].startswith("removed") and d["reason"]


# --- missing / infinite value handling (imputer side) -------------------

def test_pipeline_leaves_no_nan_or_inf(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    df = make_synthetic_flows()
    df.loc[0, "Flow_Duration"] = np.nan
    df.loc[1, "Total_Fwd_Packets"] = np.inf
    df.to_csv(raw_dir / "flows.csv", index=False)

    pipeline = PreprocessingPipeline()
    summary = pipeline.run(
        raw_dir=raw_dir,
        processed_dir=tmp_path / "processed",
        artifacts_dir=tmp_path / "artifacts",
        reports_dir=tmp_path / "reports",
    )
    assert summary["validation_problems"] == []
    train = pipeline.train_final
    test = pipeline.test_final
    features = pipeline.feature_cols
    for name, frame in (("train", train), ("test", test)):
        assert not frame[features].isna().any().any(), f"{name} still has NaN"
        assert not np.isinf(frame[features].select_dtypes("number")).any().any(), (
            f"{name} still has inf"
        )


# --- label encoding -----------------------------------------------------

def test_standardize_label_values():
    labels = pd.Series(["Web Attack – Brute Force", "  BENIGN ", "DDoS"])
    out = standardize_label_values(labels)
    assert out.tolist() == ["Web Attack - Brute Force", "BENIGN", "DDoS"]


def test_standardize_label_values_replacement_character():
    """CIC-IDS2017 files can contain U+FFFD where an en-dash was lost in
    upstream re-encoding — normalized to a hyphen, documented."""
    labels = pd.Series(["Web Attack � Brute Force", "Web Attack � XSS"])
    out = standardize_label_values(labels)
    assert out.tolist() == ["Web Attack - Brute Force", "Web Attack - XSS"]


def test_standardize_label_values_nan_becomes_unknown():
    out = standardize_label_values(pd.Series([np.nan]))
    assert out.tolist() == ["UNKNOWN"]


def test_build_binary_target():
    labels = pd.Series(["BENIGN", "benign", "DDoS", "PortScan"])
    out = build_binary_target(labels)
    assert out.tolist() == [0, 0, 1, 1]


def test_build_binary_target_raises_without_benign():
    with pytest.raises(ValueError, match="benign"):
        build_binary_target(pd.Series(["DDoS", "PortScan"]))


def test_build_multiclass_target_deterministic_and_reversible():
    labels = pd.Series(["DoS", "BENIGN", "DoS", "PortScan", "BENIGN"])
    encoded, encoder, mapping = build_multiclass_target(labels)
    assert list(mapping.values()) == [0, 1, 2]  # sorted classes, contiguous
    assert encoded.nunique() == 3
    # reversibility
    decoded = pd.Series(encoder.inverse_transform(encoded))
    assert decoded.tolist() == standardize_label_values(labels).tolist()


# --- train/test split ---------------------------------------------------

def test_split_reproducible_and_stratified(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    make_synthetic_flows().to_csv(raw_dir / "flows.csv", index=False)

    run1 = PreprocessingPipeline().run(
        raw_dir=raw_dir,
        processed_dir=tmp_path / "p1",
        artifacts_dir=tmp_path / "a1",
        reports_dir=tmp_path / "r1",
    )
    run2 = PreprocessingPipeline().run(
        raw_dir=raw_dir,
        processed_dir=tmp_path / "p2",
        artifacts_dir=tmp_path / "a2",
        reports_dir=tmp_path / "r2",
    )
    train1 = pd.read_csv(tmp_path / "p1" / "train.csv")
    train2 = pd.read_csv(tmp_path / "p2" / "train.csv")
    assert run1["train_size"] == run2["train_size"]
    assert run1["test_size"] == run2["test_size"]
    assert run1["test_fraction"] == run2["test_fraction"] == 0.2
    pd.testing.assert_frame_equal(train1, train2)  # fully reproducible
    # 80/20 sizes
    total = run1["train_size"] + run1["test_size"]
    assert run1["train_size"] == int(round(total * 0.8))
    # stratification: class proportions preserved in both folds
    for col in ("binary_label", "multiclass_label"):
        overall = pd.concat([train1, pd.read_csv(tmp_path / "p1" / "test.csv")])
        for frame in (train1, pd.read_csv(tmp_path / "p1" / "test.csv")):
            pd.testing.assert_series_equal(
                frame[col].value_counts(normalize=True).sort_index(),
                overall[col].value_counts(normalize=True).sort_index(),
                check_exact=False,
                rtol=0.2,
            )


# --- pipeline: no leakage, raw untouched, dimensions --------------------

def test_pipeline_fits_imputer_on_train_only(tmp_path, monkeypatch):
    """The imputer must learn the median from the TRAINING split only.

    Train rows carry the value 10/20 (median 15); test rows carry 100
    and NaN. The NaN must be filled with the train median (15), which
    standardizes to exactly 0.0. If the pipeline fitted on all data,
    the fill would use the full-data median (20) and the scaled value
    would differ.
    """
    import src.preprocessing.pipeline as pipeline_module

    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    df = pd.DataFrame(
        {
            "Flow_Duration": [10.0, 20.0, 100.0, np.nan],
            "Label": ["BENIGN", "BENIGN", "DoS", "DoS"],
        }
    )
    df.to_csv(raw_dir / "flows.csv", index=False)

    def fake_split(index, **kwargs):
        return index[[0, 1]], index[[2, 3]]

    monkeypatch.setattr(pipeline_module, "train_test_split", fake_split)

    pipeline = PreprocessingPipeline()
    pipeline.run(
        raw_dir=raw_dir,
        processed_dir=tmp_path / "processed",
        artifacts_dir=tmp_path / "artifacts",
        reports_dir=tmp_path / "reports",
    )
    test = pipeline.test_final
    # the row that was NaN: scaled train median (15) -> (15 - 15) / 5 = 0.0
    assert np.isclose(test["numeric__Flow_Duration"].iloc[1], 0.0, atol=1e-9)


def test_pipeline_raw_data_not_modified(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    make_synthetic_flows().to_csv(raw_dir / "flows.csv", index=False)
    before = (raw_dir / "flows.csv").read_bytes()

    PreprocessingPipeline().run(
        raw_dir=raw_dir,
        processed_dir=tmp_path / "processed",
        artifacts_dir=tmp_path / "artifacts",
        reports_dir=tmp_path / "reports",
    )
    assert (raw_dir / "flows.csv").read_bytes() == before  # byte-identical


def test_pipeline_output_dimensions_consistent(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    make_synthetic_flows(n=300).to_csv(raw_dir / "flows.csv", index=False)

    pipeline = PreprocessingPipeline()
    summary = pipeline.run(
        raw_dir=raw_dir,
        processed_dir=tmp_path / "processed",
        artifacts_dir=tmp_path / "artifacts",
        reports_dir=tmp_path / "reports",
    )
    train = pipeline.train_final
    test = pipeline.test_final
    assert summary["records_after_cleaning"] == summary["train_size"] + summary["test_size"]
    assert len(pipeline.feature_cols) == summary["final_features"]
    assert list(train.columns) == list(test.columns)  # feature columns consistent
    assert set(pipeline.feature_cols) <= set(train.columns)
    # labels valid
    assert train["binary_label"].isin([0, 1]).all()
    assert test["binary_label"].isin([0, 1]).all()
    assert sorted(train["multiclass_label"].unique()) == [0, 1, 2]
