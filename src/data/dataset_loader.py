"""
SentinelAI — dataset loading utilities.

Reusable helpers for locating, validating and loading raw CSV dataset
files into pandas DataFrames.

No machine-learning preprocessing happens here — that is added in
later phases. These functions never modify the files on disk.
"""

from pathlib import Path

import pandas as pd


class DatasetLoaderError(Exception):
    """Raised when a dataset file cannot be found or loaded."""


def validate_file_exists(path: str | Path) -> Path:
    """Return `path` as a Path if it exists and is a regular file.

    Raises DatasetLoaderError with a helpful message otherwise.
    """
    p = Path(path)
    if not p.exists():
        raise DatasetLoaderError(f"Dataset file not found: {p}")
    if not p.is_file():
        raise DatasetLoaderError(f"Path is not a regular file: {p}")
    return p


def find_csv_files(directory: str | Path) -> list[Path]:
    """Return a sorted list of *.csv files directly inside `directory`.

    Raises DatasetLoaderError if the directory does not exist.
    """
    d = Path(directory)
    if not d.is_dir():
        raise DatasetLoaderError(f"Data directory not found: {d}")
    return sorted(p for p in d.iterdir() if p.is_file() and p.suffix.lower() == ".csv")


def load_csv(
    path: str | Path,
    *,
    nrows: int | None = None,
    low_memory: bool = True,
    encoding: str = "utf-8",
    **read_csv_kwargs,
) -> pd.DataFrame:
    """Load a CSV file into a pandas DataFrame.

    The file's existence is validated first, and common loading errors
    are converted into DatasetLoaderError with a readable message.
    If the file is not UTF-8 encoded, loading is retried with latin-1.

    The file itself is never modified.
    """
    path = validate_file_exists(path)
    try:
        return pd.read_csv(
            path, nrows=nrows, low_memory=low_memory, encoding=encoding, **read_csv_kwargs
        )
    except UnicodeDecodeError:
        # Some public datasets are not UTF-8. cp1252 covers the common
        # Windows-encoded variants (and is a superset of latin-1), e.g.
        # the en-dash in "Web Attack – Brute Force" as byte 0x96.
        return pd.read_csv(
            path, nrows=nrows, low_memory=low_memory, encoding="cp1252", **read_csv_kwargs
        )
    except pd.errors.EmptyDataError as exc:
        raise DatasetLoaderError(f"CSV file is empty: {path}") from exc
    except Exception as exc:  # turn any other loading error into our own type
        raise DatasetLoaderError(f"Failed to load CSV file {path}: {exc}") from exc
