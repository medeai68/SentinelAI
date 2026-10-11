# Part 6 — Advanced Model Comparison

## Research Question

Which supervised machine-learning model provides the best balance between
attack detection capability and false-positive control on the prepared
network intrusion dataset?

## Experimental Setup

- Dataset: CIC-IDS2017 development subset (processed by Part 4 pipeline)
- Target: binary_label (BENIGN=0, ATTACK=1)
- Features: 70 (the Part 4 processed features, reused unchanged)
- Training samples: 662486 | Test samples: 165622
- Training class distribution (0=BENIGN, 1=ATTACK): {0: 653421, 1: 9065}
- Train/test strategy: the Part 4 80/20 stratified split (random_state=42),
  reused as-is — no new split was created.
- CV strategy for tuning: StratifiedKFold(n_splits=5, shuffle=True, random_state=42) inside RandomizedSearchCV.
- Optimization metric: F1 for the ATTACK class.
  F1 balances precision and recall; it is chosen over accuracy because the
  data is imbalanced and an IDS must find attacks, not just look accurate.
- Models: Logistic Regression, Random Forest, XGBoost
- Imbalance handling: LR/RF use class_weight (searched); XGBoost uses
  scale_pos_weight computed from the training set (documented in BASELINE_PARAMS).

## Baseline Results

Baseline configurations (documented parameters only):

- logistic_regression: {'max_iter': 2000, 'class_weight': 'balanced'}
- random_forest: {'n_estimators': 200, 'class_weight': 'balanced_subsample'}
- xgboost: {'n_estimators': 200, 'max_depth': 6, 'learning_rate': 0.3, 'subsample': 1.0, 'colsample_bytree': 1.0, 'min_child_weight': 1, 'imbalance': 'scale_pos_weight computed from the training set'}

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR |
| ----- | -------- | --------- | ------ | -- | ------- | --- | --- |
| logistic_regression | 0.9666 | 0.2899 | 0.9921 | 0.4487 | 0.9972 | 0.0337 | 0.0079 |
| random_forest | 0.9999 | 0.9991 | 0.9934 | 0.9962 | 0.9998 | 0.0000 | 0.0066 |
| xgboost | 1.0000 | 0.9982 | 0.9987 | 0.9985 | 1.0000 | 0.0000 | 0.0013 |

Note: baseline metrics were measured on the test set as a pre-tuning reference
snapshot, as prescribed by the experiment design; the final comparison below is
the authoritative evaluation, and using the test set for both is recorded as a
limitation.

## Optimization

- Search method: RandomizedSearchCV (n_iter=10, cv=5, scoring='f1', random_state=42)
- Full per-parameter-combination CV results: reports/cv_results/*.csv

| Model | Best parameters | Best CV score (F1) | Duration (s) |
| ----- | --------------- | ------------------ | ------------ |
| logistic_regression | {'solver': 'liblinear', 'class_weight': None, 'C': 10.0} | 0.8676 | 9055.3 |
| random_forest | {'n_estimators': 200, 'min_samples_split': 5, 'min_samples_leaf': 1, 'max_features': 'sqrt', 'max_depth': 30, 'class_weight': 'balanced'} | 0.9975 | 4776.3 |
| xgboost | {'subsample': 0.8, 'n_estimators': 200, 'min_child_weight': 1, 'max_depth': 3, 'learning_rate': 0.3, 'colsample_bytree': 1.0} | 0.9989 | 403.7 |

## Optimized Results (final test-set evaluation)

Each selected configuration was re-fitted on the complete training set, then
evaluated once on the untouched test set.

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR | TP | TN | FP | FN |
| ----- | -------- | --------- | ------ | -- | ------- | --- | --- | -- | -- | -- | -- |
| logistic_regression | 0.9967 | 0.9640 | 0.7908 | 0.8688 | 0.9976 | 0.0004 | 0.2092 | 1792 | 163289 | 67 | 474 |
| random_forest | 0.9999 | 0.9982 | 0.9951 | 0.9967 | 0.9998 | 0.0000 | 0.0049 | 2255 | 163352 | 4 | 11 |
| xgboost | 1.0000 | 0.9978 | 0.9987 | 0.9982 | 0.9999 | 0.0000 | 0.0013 | 2263 | 163351 | 5 | 3 |

## Model Comparison

Attack recall: logistic_regression 0.7908, random_forest 0.9951, xgboost 0.9987
Attack F1: logistic_regression 0.8688, random_forest 0.9967, xgboost 0.9982
False positives on the test set: logistic_regression 67, random_forest 4, xgboost 5
False negatives on the test set: logistic_regression 474, random_forest 11, xgboost 3

The experiment suggests that, on this development subset, **xgboost**
offers the best balance under the stated criterion: highest attack F1 on the test set, with attack recall and then false-positive rate as tie-breakers.
This is a baseline-stage finding on a lab dataset — not a proof of
superiority in production.

## Model Agreement (exploratory)

- Samples compared: 165622
- All three models agree on 99.7% of samples
- logistic_regression vs random_forest: 99.7% agreement
- logistic_regression vs xgboost: 99.7% agreement
- random_forest vs xgboost: 100.0% agreement
Disagreement is exploratory — it is not a ranking signal.

## Threshold Analysis (training-only data)

- logistic_regression: best validation-F1 threshold = 0.16 (validation F1 = 0.8756)
- random_forest: best validation-F1 threshold = 0.52 (validation F1 = 0.9964)
- xgboost: best validation-F1 threshold = 0.38 (validation F1 = 0.9975)
The default 0.5 threshold was kept for the final test evaluation; the selected
thresholds above are reported for later deployment phases. Full sweep:
reports/threshold_analysis.csv.

## Feature Importance

These features contributed most strongly to the fitted models according to
their feature-importance measure. This is model-specific association, NOT
proof of causation. See reports/feature_importance_random_forest.csv and
reports/feature_importance_xgboost.csv.

## Limitations

- Public-dataset limitations: CIC-IDS2017 was captured in a lab in 2017; the
  traffic may not match other networks.
- Possible class imbalance: the subset is dominated by BENIGN traffic; class
  weighting mitigates but does not remove the problem.
- Overfitting risk: CV-based selection reduces it, but the test set is a single
  holdout from the same capture — no external validation yet.
- The test set was used for the baseline reference snapshot before tuning,
  which slightly reduces its strictness as a holdout (recorded, not hidden).
- No real-time traffic validation yet.
- Hyperparameter search spaces are deliberately small (baseline-stage).

## Reproducibility

```powershell
.venv\Scripts\Activate.ps1
python -m src.preprocessing.pipeline        # once: Part 4 processed data
python -m src.training.train_binary         # Part 5 baselines (optional)
python -m src.training.model_comparison     # Part 6: baselines -> tuning -> final eval
python -m pytest tests -q
```

Configuration: config/model_config.py (random_state=42, 5-fold stratified CV,
scoring=F1, search spaces). All metrics above are actual measured values.
