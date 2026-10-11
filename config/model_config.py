"""
SentinelAI — Part 6 experiment configuration.

Central, reproducible configuration for the model-comparison
experiment. Training and evaluation modules import these values
instead of hard-coding them.

If the machine is slow, SEARCH_N_ITER may be reduced (e.g. 20) —
the experiment stays valid; the change must be documented in the
research report.
"""

# ---------------------------------------------------------------
#  Reproducibility
# ---------------------------------------------------------------

RANDOM_STATE = 42  # random seed for every randomized step

# ---------------------------------------------------------------
#  Cross-validation strategy for hyperparameter selection
# ---------------------------------------------------------------

CV_FOLDS = 5        # StratifiedKFold folds
CV_SHUFFLE = True   # shuffle before folding (reproducible via RANDOM_STATE)

# ---------------------------------------------------------------
#  Optimization metric
# ---------------------------------------------------------------
#  F1 for the ATTACK class (pos_label=1). F1 balances precision and
#  recall; for an intrusion-detection baseline we prioritize finding
#  attacks over raw accuracy, which is misleading on imbalanced data.

OPTIMIZATION_SCORING = "f1"

# ---------------------------------------------------------------
#  Search strategy
# ---------------------------------------------------------------

# RandomizedSearchCV iterations per model.
# REDUCED from 30 to 10 for the real CIC-IDS2017 run (662,486 training
# rows): 30 candidates x 3 models x 5 CV folds would take many hours on
# this development machine. The reduction keeps the experiment valid
# (same grids, same scoring, same CV) and is documented in
# reports/part6_model_comparison.md.
SEARCH_N_ITER = 10
SEARCH_CV = 5        # CV folds inside the search (matches CV_FOLDS)
# CV folds run SEQUENTIALLY in-process (1, not -1): running folds as
# parallel workers makes each worker hold its own copy of the 662k-row
# training frame while the model inside also uses all cores, which
# exhausted this machine's 15.9 GB RAM during the first real run
# (numpy _ArrayMemoryError). Each individual model fit still uses all
# cores (n_jobs=-1 in the estimators), so fits stay fast without the
# memory blow-up. Documented in reports/part6_model_comparison.md.
SEARCH_N_JOBS = 1

# ---------------------------------------------------------------
#  Threshold analysis (training data only — never the test set)
# ---------------------------------------------------------------

THRESHOLD_VALIDATION_SIZE = 0.2  # slice of the TRAINING set held out for threshold selection
THRESHOLD_GRID = [i / 100 for i in range(1, 100)]  # 0.01 .. 0.99
THRESHOLD_METRIC = "f1"  # threshold selected on validation F1 (ATTACK)

# ---------------------------------------------------------------
#  Parameter search spaces (small, controlled)
# ---------------------------------------------------------------

LOGISTIC_PARAM_GRID = {
    "C": [0.01, 0.1, 1.0, 10.0],
    "solver": ["liblinear", "lbfgs"],  # both compatible with binary + balanced weights
    "class_weight": ["balanced", None],
}

RANDOM_FOREST_PARAM_GRID = {
    "n_estimators": [100, 200, 400],
    "max_depth": [None, 10, 20, 30],
    "min_samples_split": [2, 5],
    "min_samples_leaf": [1, 2],
    "max_features": ["sqrt", "log2"],
    "class_weight": ["balanced", "balanced_subsample"],
}

XGBOOST_PARAM_GRID = {
    "n_estimators": [100, 200, 400],
    "max_depth": [3, 6, 10],
    "learning_rate": [0.01, 0.1, 0.3],
    "subsample": [0.8, 1.0],
    "colsample_bytree": [0.8, 1.0],
    "min_child_weight": [1, 5],
}

# ---------------------------------------------------------------
#  Class-imbalance strategy
# ---------------------------------------------------------------
#  Logistic Regression / Random Forest: class_weight as searched above.
#  XGBoost: scale_pos_weight computed once from the full training set
#  (benign_count / attack_count) and passed to every candidate — it is
#  not part of the search, and this strategy is documented in the
#  research report.
