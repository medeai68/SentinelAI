"""
SentinelAI — data cleaning utilities (Part 4).

Every function returns a NEW DataFrame or reports what it would
remove — the raw dataset files are never modified.

Column removals always carry a documented reason, because deleting a
potentially useful cybersecurity feature without justification is
forbidden in this project.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


# ---------------------------------------------------------------
#  Column names
# ---------------------------------------------------------------

def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy with stripped column names; spaces become underscores."""
    df = df.copy()
    df.columns = [str(c).strip().replace(" ", "_") for c in df.columns]
    return df


# ---------------------------------------------------------------
#  Rows
# ---------------------------------------------------------------

def remove_duplicate_rows(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Remove fully duplicated rows; return (cleaned_df, number_removed)."""
    before = len(df)
    cleaned = df.drop_duplicates().copy()
    return cleaned, before - len(cleaned)


# ---------------------------------------------------------------
#  Column removal (always with a documented reason)
# ---------------------------------------------------------------

def drop_columns(
    df: pd.DataFrame, columns: list[str], reason: str
) -> tuple[pd.DataFrame, list[dict]]:
    """Drop the given columns (missing names are ignored) and record decisions."""
    decisions = []
    df = df.copy()
    for col in columns:
        if col in df.columns:
            df = df.drop(columns=[col])
            decisions.append({"feature": col, "decision": "removed", "reason": reason})
    return df, decisions


def drop_empty_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, list[dict]]:
    """Drop columns that contain no non-null values at all, with reasons.

    Effect: removes columns that can never contribute to the model.
    Leakage risk: none — the column holds no information.
    """
    empty = [c for c in df.columns if df[c].isna().all()]
    return drop_columns(
        df,
        empty,
        "Column is empty (no non-null values) — it carries no information for the "
        "model. Detected on the training split and applied to both splits.",
    )


def drop_constant_columns(
    df: pd.DataFrame, *, ignore: list[str] | None = None
) -> tuple[pd.DataFrame, list[dict]]:
    """Drop columns with at most one distinct value, with reasons.

    Effect: removes columns that cannot discriminate between classes.
    Leakage risk: none — a constant column contains no target information
    and a model can never learn anything from it.
    """
    ignore = set(ignore or [])
    constant = [
        c
        for c in df.columns
        if c not in ignore and df[c].nunique(dropna=True) <= 1
    ]
    return drop_columns(
        df,
        constant,
        "Column is constant (a single distinct value) — a model can never learn "
        "anything from it, so removing it is safe and reduces noise. Detected on "
        "the training split and applied to both splits.",
    )


# ---------------------------------------------------------------
#  Values
# ---------------------------------------------------------------

def replace_infinite_with_nan(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Replace infinite values with NaN; return (new_df, number_replaced).

    NaN values are handled later by the imputer, which is fitted on the
    training split only — no value from the test set is used.
    """
    numeric = df.select_dtypes(include="number")
    inf_mask = np.isinf(numeric)
    count = int(inf_mask.sum().sum())
    df = df.copy()
    df[numeric.columns] = numeric.mask(inf_mask)
    return df, count


def coerce_numeric_columns(
    df: pd.DataFrame,
    *,
    exclude: list[str] | None = None,
    min_success_rate: float = 0.95,
) -> tuple[pd.DataFrame, list[dict]]:
    """Convert object columns that clearly contain numbers into numeric dtype.

    A column is converted only if at least `min_success_rate` of its
    non-null values parse as numbers (e.g. "Infinity" strings among
    real numbers). Values that fail to parse become NaN and are later
    handled by the imputer. Columns that stay non-numeric are treated
    as categorical features instead — this decision is recorded.
    """
    exclude = set(exclude or [])
    df = df.copy()
    decisions = []
    for col in df.columns:
        if col in exclude:
            continue
        dtype = df[col].dtype
        if pd.api.types.is_numeric_dtype(dtype) or pd.api.types.is_datetime64_any_dtype(dtype):
            continue
        if not (
            pd.api.types.is_object_dtype(dtype) or pd.api.types.is_string_dtype(dtype)
        ):
            continue
        try:
            converted = pd.to_numeric(df[col], errors="coerce")
        except (TypeError, ValueError):
            continue  # e.g. datetime strings — leave untouched
        non_null = df[col].notna()
        if non_null.sum() == 0:
            continue
        success_rate = float(converted[non_null].notna().mean())
        if success_rate >= min_success_rate:
            df[col] = converted
            decisions.append(
                {
                    "feature": col,
                    "decision": "converted to numeric",
                    "reason": f"Object column whose values are {success_rate:.1%} numeric "
                    "(non-numeric entries became NaN and are imputed later).",
                }
            )
        else:
            decisions.append(
                {
                    "feature": col,
                    "decision": "kept as categorical",
                    "reason": f"Only {success_rate:.1%} of its values parse as numbers — "
                    "treated as a categorical feature.",
                }
            )
    return df, decisions


# ---------------------------------------------------------------
#  Data-leakage prevention (documented per feature)
# ---------------------------------------------------------------

# Identifier / metadata columns of the CIC-IDS2017 schema that must NOT
# be used as model features. Each entry: normalized column name -> reason.
LEAKAGE_IDENTIFIER_COLUMNS: dict[str, str] = {
    "flow_id": (
        "Row identifier generated for dataset storage — unique per flow and carries "
        "no predictive information."
    ),
    "src_ip": (
        "Source IP address — high-cardinality identifier. In this dataset specific "
        "addresses belong to the attack infrastructure, so a model could memorize "
        "the attackers instead of learning traffic behaviour (data leakage)."
    ),
    "source_ip": "Alias of src_ip — same reasoning as src_ip.",
    "dst_ip": (
        "Destination IP address — high-cardinality identifier that names the attacked "
        "host; same leakage reasoning as src_ip."
    ),
    "destination_ip": "Alias of dst_ip — same reasoning as dst_ip.",
    "timestamp": (
        "Capture-time metadata — recorded after the fact and not available at "
        "real-time prediction time (post-event information)."
    ),
    "unnamed:_0": "Artifact index column from CSV export — not a network feature.",
}


def identify_leakage_columns(df: pd.DataFrame) -> list[dict]:
    """Return identifier/metadata columns present in the frame, with reasons.

    These are schema-level decisions (documented in reports/feature_decisions.md),
    not correlation-driven removals — features are never dropped just because
    they correlate with the label.
    """
    decisions = []
    lowered = {str(c).lower(): c for c in df.columns}
    for name, reason in LEAKAGE_IDENTIFIER_COLUMNS.items():
        if name in lowered:
            decisions.append(
                {"feature": lowered[name], "decision": "removed (leakage)", "reason": reason}
            )
    return decisions
