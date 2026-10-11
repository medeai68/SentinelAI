# Part 5 — First ML Models

## Objective

Can basic machine-learning models distinguish benign network traffic from
malicious network traffic using the prepared network-flow features?
This part trains and evaluates two binary-classification baselines
(BENIGN -> 0, ATTACK -> 1) on the Part 4 processed data.

## Dataset

- Training samples: 662486
- Test samples: 165622
- Number of features: 70
- Training class distribution (0=BENIGN, 1=ATTACK): {0: 653421, 1: 9065}
- Test class distribution (0=BENIGN, 1=ATTACK): {0: 163356, 1: 2266}
- Split: the Part 4 80/20 stratified split (random_state=42), reused unchanged.
- Class weighting: class weights were used (logistic regression: 'balanced', random forest: 'balanced_subsample') — the data
  is imbalanced, and this is recorded rather than hidden.

## Models

- **Logistic Regression** — linear baseline, class_weight='balanced', max_iter=2000.
- **Random Forest** — 200 trees, class_weight='balanced_subsample', random_state=42.

## Evaluation Metrics

Computed on the test set only. Precision/recall/F1 are for the ATTACK class (1).

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | TP | TN | FP | FN |
| ----- | -------- | --------- | ------ | -- | ------- | -- | -- | -- | -- |
| logistic_regression | 0.9666 | 0.2899 | 0.9921 | 0.4487 | 0.9972 | 2248 | 157850 | 5506 | 18 |
| random_forest | 0.9999 | 0.9991 | 0.9934 | 0.9962 | 0.9998 | 2251 | 163354 | 2 | 15 |

## Cybersecurity Interpretation

The numbers above are the actual measured values. Interpretations are kept
cautious: these are baseline models on a development subset of a public
dataset, not production detectors.

- Attack recall: logistic regression 0.9921, random forest 0.9934. The experiment suggests that (on this subset) the higher-recall model misses fewer attacks.
- False positives on the test set: 5506 (logistic regression), 2 (random forest). In a real IDS every false positive costs analyst time.
- False negatives on the test set: 18 (logistic regression), 15 (random forest). A false negative is a missed attack — the most serious error for an IDS.
- Accuracy alone would be misleading here because the data is imbalanced:
a model that always predicts BENIGN would still look accurate while
detecting nothing. F1, recall and the confusion matrix are the relevant
measures.
- Random Forest feature importance (see reports/random_forest_feature_importance.csv)
indicates which flow features the MODEL relies on most within this fitted
model. It does not prove that any feature causes an attack.

## Limitations

- Public-dataset limitations: CIC-IDS2017 was captured in a lab in 2017; its
traffic may not match other networks.
- Possible dataset bias: known label noise and duplicate flows exist in the
original data (documented in the literature and in Part 3 inspection).
- Class imbalance: the subset is dominated by BENIGN traffic.
- Baseline hyperparameters: no tuning beyond the documented defaults.
- No real-time traffic evaluation yet, and no external validation dataset.
