"""
SentinelAI — dataset inspection (Part 3).

Run from the project root:

    python -m src.data.inspect_dataset

Finds the raw CSV dataset files in data/raw/, inspects them WITHOUT
modifying the original files, and produces:

    * a console inspection report (rows, columns, column names, data
      types, missing values, duplicate rows, infinite values, label
      column, class distribution)
    * reports/dataset_summary.txt        — human-readable summary
    * reports/class_distribution.png     — class distribution chart
    * data/sample/development_sample.csv — small reproducible sample
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

from src.data.dataset_loader import DatasetLoaderError, find_csv_files, load_csv
from src.preprocessing.label_encoding import standardize_label_values

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
SAMPLE_DIR = PROJECT_ROOT / "data" / "sample"
REPORTS_DIR = PROJECT_ROOT / "reports"

SUMMARY_PATH = REPORTS_DIR / "dataset_summary.txt"
PLOT_PATH = REPORTS_DIR / "class_distribution.png"
SAMPLE_PATH = SAMPLE_DIR / "development_sample.csv"

RANDOM_SEED = 42  # fixed seed so the development sample is reproducible
DEFAULT_SAMPLE_SIZE = 5000  # total rows kept in the development sample
SUSPICIOUS_THRESHOLD = 1e15  # flag absolute values above this as suspicious

BANNER = "=" * 60


# ---------------------------------------------------------------
#  Data-quality check functions (report only — nothing is changed)
# ---------------------------------------------------------------

def detect_label_column(df: pd.DataFrame) -> str:
    """Return the label column name (case-insensitive, whitespace-tolerant).

    Some public datasets name this column " Label" with a leading
    space. Raises DatasetLoaderError when no label column is found.
    """
    for col in df.columns:
        if str(col).strip().lower() == "label":
            return col
    raise DatasetLoaderError("No label column found (expected a column named 'Label').")


def normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of the DataFrame with column names stripped of whitespace.

    Only the in-memory copy is changed — the raw file is untouched.
    """
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    return df


def count_missing_values(df: pd.DataFrame) -> pd.Series:
    """Return the number of missing (NaN) values per column."""
    return df.isna().sum()


def count_duplicate_rows(df: pd.DataFrame) -> int:
    """Return the number of fully duplicated rows."""
    return int(df.duplicated().sum())


def count_infinite_values(df: pd.DataFrame) -> pd.Series:
    """Return the number of infinite values per numeric column (only non-zero)."""
    numeric = df.select_dtypes(include="number")
    inf_counts = numeric.apply(lambda col: int(np.isinf(col).sum()))
    return inf_counts[inf_counts > 0]


def empty_columns(df: pd.DataFrame) -> list[str]:
    """Return columns where every value is missing."""
    return [str(c) for c in df.columns if df[c].isna().all()]


def constant_columns(df: pd.DataFrame) -> list[str]:
    """Return columns with at most one distinct non-null value."""
    return [str(c) for c in df.columns if df[c].nunique(dropna=True) <= 1]


def potential_type_issues(df: pd.DataFrame) -> list[str]:
    """Return non-label columns stored as object dtype (likely strings).

    These are reported for review, not fixed — e.g. a numeric column
    that pandas read as text because of odd values like "Infinity".
    """
    return [
        str(c)
        for c in df.columns
        if (pd.api.types.is_object_dtype(df[c]) or pd.api.types.is_string_dtype(df[c]))
        and str(c).strip().lower() != "label"
    ]


def suspicious_numeric_values(df: pd.DataFrame, threshold: float = SUSPICIOUS_THRESHOLD) -> pd.Series:
    """Return the number of values with absolute size above `threshold` per column."""
    numeric = df.select_dtypes(include="number")
    big = numeric.apply(lambda col: int((col.abs() > threshold).sum()))
    return big[big > 0]


# ---------------------------------------------------------------
#  Label analysis
# ---------------------------------------------------------------

def class_distribution(df: pd.DataFrame, label_col: str) -> pd.Series:
    """Return record counts per class, sorted from most to least frequent."""
    return df[label_col].value_counts(dropna=False)


def format_class_report(distribution: pd.Series) -> str:
    """Format a class distribution as '## Label  Count  Percentage' lines."""
    total = int(distribution.sum())
    lines = ["## Label              Count       Percentage"]
    for label, count in distribution.items():
        pct = (count / total * 100) if total else 0.0
        lines.append(f"{str(label):<25} {int(count):>10}   {pct:>9.2f}%")
    return "\n".join(lines)


# ---------------------------------------------------------------
#  Inspection
# ---------------------------------------------------------------

def inspect_dataframe(df: pd.DataFrame, name: str) -> dict:
    """Run all Part 3 quality checks on one DataFrame and return the results."""
    df = normalize_column_names(df)
    label_col = detect_label_column(df)
    distribution = class_distribution(df, label_col)

    return {
        "name": name,
        "records": int(len(df)),
        "features": int(len(df.columns)),
        "column_names": list(df.columns),
        "dtypes": {str(c): str(t) for c, t in df.dtypes.items()},
        "label_column": label_col,
        "classes": distribution.index.tolist(),
        "distribution": distribution,
        "missing": count_missing_values(df),
        "missing_total": int(df.isna().sum().sum()),
        "duplicates": count_duplicate_rows(df),
        "infinite": count_infinite_values(df),
        "empty_columns": empty_columns(df),
        "constant_columns": constant_columns(df),
        "type_issue_columns": potential_type_issues(df),
        "suspicious": suspicious_numeric_values(df),
        "numeric_columns": int(df.select_dtypes(include="number").shape[1]),
        "categorical_columns": int(df.select_dtypes(exclude="number").shape[1]),
    }


def print_console_report(result: dict) -> None:
    """Print the inspection results for one dataset file."""
    print(BANNER)
    print(f"File   : {result['name']}")
    print(f"Rows   : {result['records']}")
    print(f"Columns: {result['features']}")
    print(BANNER)
    print("Column names:")
    print(", ".join(result["column_names"]))
    print()
    print("Data types:")
    for col, dtype in result["dtypes"].items():
        print(f"  {col:<25} {dtype}")
    print()
    print(f"Missing values (total): {result['missing_total']}")
    if result["missing"].sum() > 0:
        print(result["missing"][result["missing"] > 0].to_string())
    print(f"Duplicate rows       : {result['duplicates']}")
    inf = result["infinite"]
    print(f"Infinite values      : {int(inf.sum()) if len(inf) else 0}")
    if len(inf):
        print(inf.to_string())
    print(f"Empty columns        : {result['empty_columns'] or 'none'}")
    print(f"Constant columns     : {result['constant_columns'] or 'none'}")
    print(f"Potential type issues: {result['type_issue_columns'] or 'none'}")
    susp = result["suspicious"]
    if len(susp):
        print("Suspiciously large numeric values (abs > 1e15):")
        print(susp.to_string())
    print(f"Label column         : {result['label_column']}")
    print(f"Number of classes    : {len(result['classes'])}")
    print("Class distribution:")
    print(format_class_report(result["distribution"]))
    print()


# ---------------------------------------------------------------
#  Summary, sample and chart
# ---------------------------------------------------------------

def build_summary(results: list[dict]) -> str:
    """Build the human-readable dataset summary text (actual computed values)."""
    parts = [
        "SentinelAI - Dataset Summary",
        "Generated by: python -m src.data.inspect_dataset",
        BANNER,
    ]
    for r in results:
        total = int(r["distribution"].sum())
        parts.append(f"Dataset name      : {r['name']}")
        parts.append(f"Number of records : {r['records']}")
        parts.append(f"Number of features: {r['features']}")
        parts.append(f"Label column      : {r['label_column']}")
        parts.append(f"Number of classes : {len(r['classes'])}")
        parts.append("Class distribution (count, percentage):")
        for label, count in r["distribution"].items():
            parts.append(f"    {str(label):<30} {int(count):>10}   {count / total * 100:>7.2f}%")
        parts.append(f"Missing values (total)   : {r['missing_total']}")
        parts.append(f"Duplicate records        : {r['duplicates']}")
        parts.append(f"Numeric columns          : {r['numeric_columns']}")
        parts.append(f"Categorical columns      : {r['categorical_columns']}")
        parts.append(BANNER)
    return "\n".join(parts) + "\n"


def create_development_sample(
    results: list[dict],
    dataframes: list[pd.DataFrame],
    *,
    size: int = DEFAULT_SAMPLE_SIZE,
    seed: int = RANDOM_SEED,
) -> pd.DataFrame:
    """Create a small, reproducible, multi-class development sample.

    For each source file, rows are drawn per class (proportionally,
    with at least one row per class) using a fixed random seed, then
    all files are combined and shuffled. The original dataset files
    are never modified.
    """
    frames = []
    per_file = max(1, size // max(1, len(dataframes)))
    for result, df in zip(results, dataframes):
        label_col = result["label_column"]
        parts = []
        for _, group in df.groupby(label_col):
            take = max(1, min(len(group), max(1, int(per_file * len(group) / len(df)))))
            parts.append(group.sample(n=take, random_state=seed))
        frames.append(pd.concat(parts, ignore_index=True))
    sample = pd.concat(frames, ignore_index=True)
    return sample.sample(frac=1, random_state=seed).reset_index(drop=True)


def plot_class_distribution(distribution: pd.Series, path: Path) -> None:
    """Save a simple bar chart of the class distribution (matplotlib).

    Single-series chart: no legend (the title names the series),
    default matplotlib colors (per project spec), rotated x labels.
    """
    import matplotlib

    matplotlib.use("Agg")  # headless-safe backend (no display needed)
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(12, 6))
    distribution.plot(kind="bar", ax=ax, width=0.8)
    ax.set_title("Class Distribution - SentinelAI (CIC-IDS2017 development subset)")
    ax.set_ylabel("Number of records")
    ax.set_xlabel("Class label")
    ax.tick_params(axis="x", rotation=45)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


# ---------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------

def main() -> int:
    """Inspect every raw CSV file and produce the summary, sample and chart."""
    print(f"Looking for raw CSV dataset files in: {RAW_DIR}")
    try:
        files = find_csv_files(RAW_DIR)
    except DatasetLoaderError as exc:
        print(f"ERROR: {exc}")
        print("See DEVELOPMENT.md, section 'Part 3 - Dataset' for download instructions.")
        return 1

    if not files:
        print("ERROR: no CSV files found in data/raw/.")
        print("See DEVELOPMENT.md, section 'Part 3 - Dataset' for download instructions.")
        return 1

    results: list[dict] = []
    dataframes: list[pd.DataFrame] = []
    for path in files:
        print(f"\nLoading {path} ...")
        try:
            df = normalize_column_names(load_csv(path))
            # In-memory label standardization only (raw file untouched):
            # some CIC-IDS2017 files store the en-dash as the double-encoded
            # control character U+0096 (e.g. "Web Attack \x96 Brute Force").
            label_col = detect_label_column(df)
            df[label_col] = standardize_label_values(df[label_col])
        except DatasetLoaderError as exc:
            print(f"  ERROR: {exc} - skipping this file.")
            continue
        try:
            result = inspect_dataframe(df, path.name)
        except DatasetLoaderError as exc:
            print(f"  ERROR: {exc} - skipping this file.")
            continue
        results.append(result)
        dataframes.append(df)
        print_console_report(result)

    if not results:
        print("ERROR: no dataset file could be loaded.")
        return 1

    # 1) Human-readable summary
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text(build_summary(results), encoding="utf-8")
    print(f"Dataset summary written to: {SUMMARY_PATH}")

    # 2) Development sample
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    sample = create_development_sample(results, dataframes)
    sample.to_csv(SAMPLE_PATH, index=False)
    print(
        f"Development sample written to: {SAMPLE_PATH} "
        f"({len(sample)} rows, {len(sample.columns)} columns)"
    )
    print("Sample class counts:")
    print(format_class_report(class_distribution(sample, detect_label_column(sample))))

    # 3) Class distribution chart (combined across files)
    combined = pd.concat([r["distribution"] for r in results]).groupby(level=0).sum()
    combined = combined.sort_values(ascending=False)
    plot_class_distribution(combined, PLOT_PATH)
    print(f"Class distribution chart written to: {PLOT_PATH}")

    print("\nInspection finished.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
