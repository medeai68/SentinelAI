"""
SentinelAI — detection engine configuration (Part 7).

All thresholds are EXPERIMENTAL DEFAULTS for a transparent defensive
interpretation layer. They are configurable here and documented in
reports/detection_engine.md.

HIGH severity does NOT mean a confirmed real-world compromise — it only
means the model assigned a high attack probability under this rule.
"""

# ---------------------------------------------------------------
#  Artifact resolution (project-relative; no machine-specific paths)
# ---------------------------------------------------------------
#  The optimized model file produced by Part 6. Set to the actual Part 6
#  winner: XGBoost (test F1 0.99824, recall 0.99868, ROC-AUC 0.99990 —
#  see reports/part6_model_comparison.md).
DEFAULT_MODEL_FILE = "xgboost_optimized.joblib"

DEFAULT_PREPROCESSOR_FILE = "models/preprocessing/preprocessor.joblib"
DEFAULT_FEATURES_FILE = "models/preprocessing/feature_columns.json"
DEFAULT_MAPPING_FILE = "reports/label_mapping.json"

# ---------------------------------------------------------------
#  Label fallbacks (used only when reports/label_mapping.json is absent)
# ---------------------------------------------------------------

BENIGN_LABEL = "BENIGN"
ATTACK_LABEL = "ATTACK"

# ---------------------------------------------------------------
#  Severity rule (experimental defaults — configurable)
# ---------------------------------------------------------------
#  BENIGN                      -> LOW
#  ATTACK, probability >= 0.8  -> HIGH
#  ATTACK, probability <  0.8  -> MEDIUM (also when probability is
#                                unavailable for the model)
#
#  Why 0.8: a conservative default so that only high-confidence attack
#  predictions are labelled HIGH. These values are experimental and
#  should be revisited using the Part 6 threshold analysis once the
#  dataset is available.
HIGH_ATTACK_PROBABILITY = 0.8
