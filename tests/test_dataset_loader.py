"""Basic tests for dataset file validation, loading, missing-value
detection and label detection (Part 3).

Unit tests use tiny CSV files built in a temporary directory — this is
standard test practice, not fabricated dataset data. One test also runs
against the real development sample (data/sample/development_sample.csv)
and is skipped with an explanation if the sample does not exist yet.
"""

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.data.dataset_loader import (
    DatasetLoaderError,
    find_csv_files,
    load_csv,
    validate_file_exists,
)
from src.data.inspect_dataset import (
    count_duplicate_rows,
    count_infinite_values,
    count_missing_values,
    detect_label_column,
    normalize_column_names,
)

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "sample" / "development_sample.csv"


# --- dataset file validation -------------------------------------------

def test_validate_file_exists_returns_path(tmp_path):
    f = tmp_path / "data.csv"
    f.write_text("a,b\n1,2\n", encoding="utf-8")
    assert validate_file_exists(f) == f


def test_validate_file_exists_missing_raises(tmp_path):
    with pytest.raises(DatasetLoaderError, match="not found"):
        validate_file_exists(tmp_path / "missing.csv")


def test_validate_file_exists_directory_raises(tmp_path):
    with pytest.raises(DatasetLoaderError, match="not a regular file"):
        validate_file_exists(tmp_path)


def test_find_csv_files_lists_only_csv(tmp_path):
    (tmp_path / "a.csv").write_text("x\n1\n", encoding="utf-8")
    (tmp_path / "b.csv").write_text("x\n1\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not a csv", encoding="utf-8")
    found = find_csv_files(tmp_path)
    assert [p.name for p in found] == ["a.csv", "b.csv"]


# --- dataset loading ----------------------------------------------------

def test_load_csv_returns_dataframe(tmp_path):
    f = tmp_path / "tiny.csv"
    pd.DataFrame({"feature": [1, 2, 3], "Label": ["BENIGN", "BENIGN", "DoS"]}).to_csv(f, index=False)
    df = load_csv(f)
    assert isinstance(df, pd.DataFrame)
    assert df.shape == (3, 2)
    assert list(df.columns) == ["feature", "Label"]


def test_load_csv_missing_file_raises(tmp_path):
    with pytest.raises(DatasetLoaderError, match="not found"):
        load_csv(tmp_path / "nope.csv")


def test_load_csv_empty_file_raises(tmp_path):
    f = tmp_path / "empty.csv"
    f.write_text("", encoding="utf-8")
    with pytest.raises(DatasetLoaderError, match="empty"):
        load_csv(f)


# --- missing values, duplicates, infinite values ------------------------

def test_count_missing_values_detects_nan():
    df = pd.DataFrame({"a": [1.0, np.nan, 3.0], "b": [np.nan, np.nan, np.nan]})
    missing = count_missing_values(df)
    assert missing["a"] == 1
    assert missing["b"] == 3


def test_count_duplicate_rows():
    df = pd.DataFrame({"a": [1, 1, 2], "b": [2, 2, 3]})
    assert count_duplicate_rows(df) == 1


def test_count_infinite_values():
    df = pd.DataFrame({"a": [1.0, np.inf, 3.0], "b": [-np.inf, 2.0, 3.0]})
    inf = count_infinite_values(df)
    assert inf["a"] == 1
    assert inf["b"] == 1


# --- label detection ----------------------------------------------------

def test_detect_label_column_standard():
    df = pd.DataFrame({"Flow Duration": [1], "Label": ["BENIGN"]})
    assert detect_label_column(df) == "Label"


def test_detect_label_column_with_leading_space():
    df = pd.DataFrame({"Flow Duration": [1], " Label": ["BENIGN"]})
    assert detect_label_column(df) == " Label"


def test_detect_label_column_case_insensitive():
    df = pd.DataFrame({"LABEL": ["BENIGN"]})
    assert detect_label_column(df) == "LABEL"


def test_detect_label_column_missing_raises():
    with pytest.raises(DatasetLoaderError, match="label"):
        detect_label_column(pd.DataFrame({"a": [1]}))


def test_normalize_column_names_strips_whitespace():
    df = pd.DataFrame({" Label ": [1], "x ": [2]})
    normalized = normalize_column_names(df)
    assert list(normalized.columns) == ["Label", "x"]


# --- real development sample (skipped until the data exists) ------------

@pytest.mark.skipif(
    not SAMPLE_PATH.exists(),
    reason="data/sample/development_sample.csv not found - download the dataset subset "
    "into data/raw/ and run: python -m src.data.inspect_dataset",
)
def test_development_sample_loads_with_labels():
    df = pd.read_csv(SAMPLE_PATH)
    assert not df.empty
    assert "Label" in df.columns
    assert df["Label"].nunique() >= 2  # sample should contain multiple classes
