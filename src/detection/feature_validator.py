"""Input feature validation for the detection engine (Part 7).

Validation policy (documented in reports/detection_engine.md):

  * empty input                        -> FeatureValidationError
  * missing required feature columns   -> FeatureValidationError
  * extra/unexpected columns           -> dropped, warning returned
  * feature order                      -> reordered deterministically to the
                                         saved artifact order (not an error)
  * NaN values                         -> allowed; imputed by the fitted
                                         Part 4 preprocessing artifact
  * infinite values                    -> replaced with NaN, then imputed
                                         the same way (mirrors the Part 4
                                         cleaning strategy)
  * non-numeric feature columns        -> object columns that parse >= 95%
                                         numeric are coerced (failures become
                                         NaN and are imputed); anything else
                                         raises FeatureValidationError

No value is ever silently filled with an arbitrary number: the only
imputation is the fitted Part 4 artifact's median strategy.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.preprocessing.cleaning import clean_column_names


class FeatureValidationError(ValueError):
    """Raised when detection input does not match the required feature schema."""


def validate_features(
    df: pd.DataFrame, feature_cols: list[str]
) -> tuple[pd.DataFrame, list[str]]:
    """Validate detection input and return (prepared_df, warnings).

    Incoming column names are normalized with the SAME cleaning the Part 4
    pipeline applied before fitting the preprocessor (strip whitespace,
    spaces -> underscores), so raw dataset CSVs ("Flow Bytes/s") match the
    saved schema ("Flow_Bytes/s"). This mirrors the existing preprocessing
    design rather than introducing a second one.

    The prepared frame has exactly the saved artifact columns in the
    saved order. Raises FeatureValidationError for invalid input.
    """
    if df is None or len(df) == 0:
        raise FeatureValidationError("Input is empty (no rows).")

    df = clean_column_names(df)  # identical to the Part 4 cleaning step
    warnings: list[str] = []

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise FeatureValidationError(
            f"Missing required feature column(s): {missing}. "
            f"Expected exactly the {len(feature_cols)} features saved by the Part 4 pipeline."
        )

    extra = [c for c in df.columns if c not in feature_cols]
    if extra:
        warnings.append(f"Dropped unexpected column(s): {extra}")
        df = df.drop(columns=extra)

    # deterministic order: the artifact's saved feature order
    prepared = df[feature_cols].copy()

    # numeric dtype handling (mirrors Part 4's coercion strategy)
    for col in feature_cols:
        if pd.api.types.is_numeric_dtype(prepared[col]):
            continue
        converted = pd.to_numeric(prepared[col], errors="coerce")
        non_null = prepared[col].notna()
        if non_null.sum() and float(converted[non_null].notna().mean()) >= 0.95:
            prepared[col] = converted
            warnings.append(
                f"Column '{col}' coerced to numeric (unparseable values became "
                "NaN and are imputed by the fitted artifact)."
            )
        else:
            raise FeatureValidationError(
                f"Feature column '{col}' is not numeric (dtype {prepared[col].dtype})."
            )

    # infinite -> NaN (the Part 4 strategy; the artifact imputes them)
    numeric = prepared.select_dtypes(include="number")
    inf_mask = np.isinf(numeric)
    if inf_mask.any().any():
        n_cols = int(inf_mask.any(axis=0).sum())
        prepared[numeric.columns] = numeric.mask(inf_mask)
        warnings.append(
            f"Replaced infinite values with NaN in {n_cols} column(s) — imputed "
            "by the fitted Part 4 preprocessing artifact."
        )

    # NaN is allowed: the fitted artifact's median imputer handles it
    if prepared.isna().any().any():
        n_rows = int(prepared.isna().any(axis=1).sum())
        warnings.append(
            f"NaN values present in {n_rows} row(s) — imputed by the fitted "
            "Part 4 preprocessing artifact (no arbitrary fill values)."
        )

    return prepared, warnings
