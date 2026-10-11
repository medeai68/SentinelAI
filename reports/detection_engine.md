# SentinelAI Threat Detection Engine

Architecture and behavior document for the Part 7 detection engine
(`src/detection/`). This document describes the implementation — it
contains no fabricated detection results.

## Architecture

```
Input (authorized network-flow CSV / DataFrame / dict)
        ↓
Feature validation          src/detection/feature_validator.py
  · required features, order, dtypes, NaN/inf policy
        ↓
Preprocessing artifact      models/preprocessing/preprocessor.joblib (Part 4)
  · loaded once, .transform() only — NEVER re-fitted at detection time
        ↓
Optimized ML model          models/<name>_optimized.joblib (Part 6)
  · loaded once, .predict() (+ .predict_proba() when supported)
        ↓
Prediction                  encoded class 0/1
        ↓
Probability                 P(ATTACK) when predict_proba exists, else None
        ↓
Severity                    configurable interpretation layer (see below)
        ↓
Output                      DetectionResult objects / standardized table
```

## Model

The engine loads the optimized model selected by the Part 6 experiment
(`python -m src.training.model_comparison`). At the time of writing,
Part 6 has not yet been run (the CIC-IDS2017 dataset download is
pending), so the model path is intentionally unset in
`config/detection_config.py` (`DEFAULT_MODEL_FILE = None`) — the engine
refuses to guess and reports exactly what is missing. Once Part 6 has
run, set `DEFAULT_MODEL_FILE` (or pass `--model` to the CLI).

Model capabilities are handled safely: `predict_proba` is used only
when the loaded model supports it; otherwise probabilities are `None`
and the severity rule degrades to MEDIUM for attack predictions.

## Input Features

The required features are the ones saved by the Part 4 pipeline in
`models/preprocessing/feature_columns.json` (the CIC-IDS2017 schema
minus the documented identifier/metadata columns — expected on the
order of 78 features; the exact count is determined by the artifact,
never hard-coded). Validation policy:

- missing required columns → clear validation error (nothing silently filled),
- unexpected extra columns → dropped with a logged warning,
- feature order → normalized deterministically to the artifact order,
- NaN values → imputed by the fitted artifact's median strategy,
- infinite values → converted to NaN first, then imputed (mirrors Part 4),
- non-numeric columns → coerced only when ≥95% of values parse as
  numbers; otherwise a validation error.

## Output Schema

One `DetectionResult` per input flow:

| Field | Meaning |
| --- | --- |
| timestamp | ISO timestamp of the detection run |
| flow_id | input row identity, or a deterministic generated id (`row_N`) when the input has none |
| prediction | encoded class (0 = BENIGN, 1 = ATTACK) |
| label | human-readable "BENIGN" / "ATTACK" (from the Part 4 label mapping) |
| is_attack | True when prediction == 1 |
| attack_probability | P(ATTACK) from `predict_proba`; None when unavailable |
| confidence | model probability for the PREDICTED class (model output — no calibration assumed) |
| severity | LOW / MEDIUM / HIGH per the configurable rule |
| model_name / model_version | from the model metadata |
| feature_count | number of features used |
| status | success / validation_error / prediction_error |
| errors | list of messages for non-success statuses |

## Error Handling

Invalid rows are never silently dropped: they become `DetectionResult`
objects with an error status and a clear message. Missing artifacts
stop the engine with an exact report of what is missing (no fake
artifacts are ever created).

## Limitations

- Detection is based on a public lab dataset (CIC-IDS2017); performance
  on other networks is unknown.
- The engine depends entirely on the Part 4/5/6 artifacts — no model,
  no detection.
- False positives and false negatives are inherent to ML detection; a
  BENIGN/ATTACK label is a model prediction, not ground truth.
- Probability is the model's output, not guaranteed threat certainty.
- Severity is a configurable interpretation layer with experimental
  defaults (`config/detection_config.py`) — HIGH means "high model
  attack probability", not a confirmed real-world compromise.
- No live network integration yet; no real-time capability; not
  production-ready.
