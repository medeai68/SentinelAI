"""
SentinelAI — feature statistics and selection support (Part 4).

Part 4 removes only clearly invalid or unusable columns (documented in
cleaning.py) and keeps meaningful network traffic features. This module
provides the statistics used for those decisions and optional
correlation analysis — it does NOT drop features based on correlation
with the label (that would risk data leakage).
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def feature_statistics(
    df: pd.DataFrame, *, label_columns: list[str] | None = None
) -> pd.DataFrame:
    """Return per-feature statistics: dtype, missing values, missing ratio,
    unique values, and variance (numeric features only)."""
    label_columns = set(label_columns or [])
    rows = []
    for col in df.columns:
        series = df[col]
        rows.append(
            {
                "feature": col,
                "dtype": str(series.dtype),
                "role": "target" if col in label_columns else "feature",
                "missing_values": int(series.isna().sum()),
                "missing_ratio": float(series.isna().mean()),
                "unique_values": int(series.nunique(dropna=True)),
                "variance": float(series.var()) if pd.api.types.is_numeric_dtype(series) else None,
            }
        )
    return pd.DataFrame(rows)


def numeric_correlation_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Pearson correlation among numeric features (for inspection only)."""
    return df.select_dtypes(include="number").corr()


def highest_correlations(corr: pd.DataFrame, *, top_n: int = 10) -> pd.DataFrame:
    """Return the strongest feature-feature correlations (self-pairs excluded).

    Useful for spotting redundant features — reported, not auto-removed.
    """
    mask = np.triu(np.ones(corr.shape), k=1).astype(bool)
    pairs = corr.where(~mask).stack().reset_index()
    pairs.columns = ["feature_1", "feature_2", "correlation"]
    pairs["abs_corr"] = pairs["correlation"].abs()
    return (
        pairs.sort_values("abs_corr", ascending=False)
        .head(top_n)
        .drop(columns=["abs_corr"])
        .reset_index(drop=True)
    )
