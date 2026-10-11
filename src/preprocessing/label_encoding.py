"""
SentinelAI — target label standardization and encoding (Part 4).

Creates two target representations:

A. Binary target:   BENIGN -> 0, any attack -> 1
B. Multiclass target: each attack category gets its own encoded integer

Mappings are saved to reports/label_mapping.json so every encoded
number can be understood (and reversed) later.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.preprocessing import LabelEncoder

BENIGN_LABEL = "BENIGN"


def standardize_label_values(labels: pd.Series) -> pd.Series:
    """Normalize label strings: strip whitespace, unify dashes, collapse spaces.

    The dataset itself is never modified — this only standardizes the
    in-memory values (e.g. "Web Attack – Brute Force" becomes
    "Web Attack - Brute Force"). Missing labels become "UNKNOWN".
    """

    def normalize(value) -> str:
        if pd.isna(value):
            return "UNKNOWN"
        text = str(value).strip()
        for dash in (
            "–", "—", "−",        # en dash, em dash, minus sign
            "\u0096", "\u0097",   # cp1252 dash bytes mis-decoded as latin-1
            "�",             # Unicode replacement char (upstream lossy re-encoding)
        ):
            text = text.replace(dash, "-")
        return " ".join(text.split())

    return labels.map(normalize)


def build_binary_target(labels: pd.Series, *, benign_value: str = BENIGN_LABEL) -> pd.Series:
    """Return 0 for benign traffic and 1 for any attack.

    The benign marker is matched case-insensitively and whitespace-tolerant,
    so "BENIGN", "benign" and " benign " all count as benign.
    Raises ValueError when no benign records exist.
    """
    is_benign = labels.astype(str).str.strip().str.upper() == benign_value.upper()
    if not is_benign.any():
        raise ValueError(f"No benign records found (expected label '{benign_value}')")
    return is_benign.map({True: 0, False: 1}).astype("int64")


def build_multiclass_target(
    labels: pd.Series, encoder: LabelEncoder | None = None
) -> tuple[pd.Series, LabelEncoder, dict[str, int]]:
    """Encode each standardized label as its own integer (0..k-1).

    The classes are sorted alphabetically, so the mapping is
    deterministic. Returns (encoded_series, fitted_encoder, mapping).
    The encoder is reversible via encoder.inverse_transform().
    """
    labels = standardize_label_values(labels)
    if encoder is None:
        encoder = LabelEncoder()
    encoded = encoder.fit_transform(labels)
    mapping = {str(cls): int(idx) for idx, cls in enumerate(encoder.classes_)}
    return pd.Series(encoded, index=labels.index, name="multiclass_label"), encoder, mapping


def save_label_mapping(path: str | Path, binary_mapping: dict, multiclass_mapping: dict) -> None:
    """Save the binary and multiclass label mappings as JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"binary": binary_mapping, "multiclass": multiclass_mapping}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_label_mapping(path: str | Path) -> dict:
    """Load a label mapping previously saved with save_label_mapping()."""
    return json.loads(Path(path).read_text(encoding="utf-8"))
