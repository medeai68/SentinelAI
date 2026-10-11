"""
SentinelAI — model serialization utilities (Part 5).

Saving and loading scikit-learn models with joblib, plus a small
metadata sidecar that records how each model was produced.

Layout (all under models/):

    models/<name>.joblib              the fitted model
    models/metadata/<name>.json       its metadata

Errors are never silently ignored — missing or corrupt artifacts raise
ModelArtifactError with a readable message.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib

REQUIRED_METADATA_KEYS = {
    "model_name",
    "dataset",
    "target",
    "random_state",
    "feature_count",
    "training_samples",
}


class ModelArtifactError(Exception):
    """Raised when a model artifact is missing, corrupt, or invalid."""


def metadata_path_for(model_path: str | Path) -> Path:
    """Return the metadata path for a model artifact (models/metadata/<name>.json)."""
    model_path = Path(model_path)
    return model_path.parent / "metadata" / f"{model_path.stem}.json"


def save_model(model, path: str | Path, metadata: dict | None = None) -> Path:
    """Save a fitted model with joblib and, if given, its metadata JSON.

    Returns the path of the saved model file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    if metadata is not None:
        meta_path = metadata_path_for(path)
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    return path


def load_model(path: str | Path):
    """Load a model saved with save_model().

    Raises ModelArtifactError with a readable message when the file is
    missing, not a file, or cannot be deserialized.
    """
    path = Path(path)
    if not path.exists():
        raise ModelArtifactError(f"Model artifact not found: {path}")
    if not path.is_file():
        raise ModelArtifactError(f"Model artifact is not a file: {path}")
    try:
        return joblib.load(path)
    except Exception as exc:
        raise ModelArtifactError(f"Failed to load model artifact {path}: {exc}") from exc


def load_model_metadata(path: str | Path) -> dict:
    """Load and return the metadata JSON for a model artifact.

    Raises ModelArtifactError when the metadata file is missing or
    unreadable JSON.
    """
    meta_path = metadata_path_for(path)
    if not meta_path.exists():
        raise ModelArtifactError(
            f"Metadata file not found for model artifact {Path(path)}: {meta_path}"
        )
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ModelArtifactError(f"Corrupt metadata file {meta_path}: {exc}") from exc


def validate_model_artifact(path: str | Path) -> dict:
    """Validate a saved model artifact and return its metadata.

    Checks that both the model file and its metadata exist, that the
    metadata is readable JSON, and that all required keys are present.
    Raises ModelArtifactError otherwise.
    """
    path = Path(path)
    if not path.exists():
        raise ModelArtifactError(f"Model artifact not found: {path}")
    if not path.is_file():
        raise ModelArtifactError(f"Model artifact is not a file: {path}")
    metadata = load_model_metadata(path)
    missing = REQUIRED_METADATA_KEYS - set(metadata)
    if missing:
        raise ModelArtifactError(
            f"Metadata for {path} is missing required keys: {sorted(missing)}"
        )
    return metadata
