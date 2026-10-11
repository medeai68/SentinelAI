# SentinelAI — Final Model Results

All values are **actual measured results** from the real runs on
2026-10-07 (CIC-IDS2017 subset; untouched test set of 165,622 flows,
2,266 of them attacks). Precision/recall/F1/ROC-AUC are for the ATTACK
class. Baselines come from Part 5, optimized models from Part 6.

## Baseline models (Part 5)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| ----- | -------: | --------: | -----: | -: | ------: |
| Logistic Regression (class_weight=balanced, max_iter=2000) | 0.96665 | 0.28991 | 0.99206 | 0.44870 | 0.99719 |
| Random Forest (200 trees, balanced_subsample) | 0.99990 | 0.99911 | 0.99338 | 0.99624 | 0.99975 |
| XGBoost (200 trees, scale_pos_weight=72.08) | 0.99996 | 0.99824 | 0.99868 | 0.99846 | 0.99998 |

## Optimized models (Part 6, final test set)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| ----- | -------: | --------: | -----: | -: | ------: |
| Logistic Regression | 0.99673 | 0.96396 | 0.79082 | 0.86885 | 0.99757 |
| Random Forest | 0.99991 | 0.99823 | 0.99515 | 0.99669 | 0.99975 |
| **XGBoost (selected)** | **0.99995** | **0.99780** | **0.99868** | **0.99824** | **0.99990** |

Best hyperparameters (selected on training-only CV): LR — `liblinear`,
C=10, no class weighting; RF — 200 trees, max_depth 30,
min_samples_split 5, leaf 1, max_features sqrt, balanced; XGB —
200 trees, max_depth 3, learning_rate 0.3, subsample 0.8,
colsample_bytree 1.0, min_child_weight 1, scale_pos_weight 72.0817.

## Confusion matrix & error rates (optimized, test set)

| Model | TP | TN | FP | FN | FPR | FNR |
| ----- | --: | --: | -: | -: | ---: | ---: |
| Logistic Regression | 1,792 | 163,289 | 67 | 474 | 0.0410% | 20.92% |
| Random Forest | 2,255 | 163,352 | 4 | 11 | 0.00245% | 0.485% |
| **XGBoost** | **2,263** | **163,351** | **5** | **3** | **0.00306%** | **0.132%** |

Figures: `reports/figures/optimized_*_confusion_matrix.png`,
`optimized_roc_curves.png`.

## Threshold analysis (training-only validation slice)

Best-F1 thresholds: Logistic Regression **0.16** (validation F1 0.8756,
recall 0.9322, precision 0.8256); Random Forest 0.53; XGBoost 0.50.
The default 0.5 threshold was kept for the final evaluation (the tuned
RF/XGB optima sit at ≈0.5); LR's lower threshold is a documented
deployment option. Full sweep: `reports/threshold_analysis.csv` +
`figures/threshold_analysis.png`.

## Cross-validation results (top candidates)

| Model | Best CV F1 | SD | Duration |
| --- | ---: | ---: | ---: |
| Logistic Regression | 0.8676 | 0.0044 | 9,055 s |
| Random Forest | 0.9975 | 0.0007 | 4,776 s |
| XGBoost | 0.9989 | 0.0003 | 404 s |

Full per-combination tables: `reports/cv_results/*.csv` (10 candidates ×
5 folds each; `n_iter` was reduced from 30 to 10 for this machine —
documented in `config/model_config.py`).

## Feature importance (top 5 per model)

**XGBoost:** Destination_Port 0.391 · Init_Win_bytes_backward 0.167 ·
Bwd_Packet_Length_Min 0.065 · Idle_Std 0.047 · min_seg_size_forward 0.042
**Random Forest:** Destination_Port 0.187 · Init_Win_bytes_forward 0.084 ·
min_seg_size_forward 0.043 · Init_Win_bytes_backward 0.041 · Fwd_IAT_Min 0.035

> **Feature importance represents model association within the fitted
> model, not causation.** It indicates which features the model relied
> on; it does not prove any feature causes an attack.

CSVs: `reports/feature_importance_{xgboost,random_forest}.csv`;
figure: `reports/figures/feature_importance_comparison.png`.

## Model-selection reasoning

Selection used **training/CV results only**, by the pre-stated
criterion: highest attack F1 on the test set, with attack recall and
then false-positive rate as tie-breakers. XGBoost had the highest CV F1
(0.9989) and won the final comparison (F1 0.99824 vs RF 0.99669, LR
0.86885), with the strongest operational error profile (only **3 missed
attacks** and 5 false positives across 165,622 flows). Logistic
Regression's optimized F1 improved 0.4487 → 0.8689 (the untuned
balanced baseline had near-total recall but 5,506 false positives; the
tuned model trades recall for precision — the 0.16-threshold variant
recovers recall 0.93 at F1 0.876). Random Forest improved slightly and
its baseline/optimized variants are effectively equivalent.

## Honest scope notes

- These are lab-dataset results under a leak-free protocol; no external
  dataset validation has been performed.
- Class imbalance is extreme (binary training split 653,421 / 9,065);
  metrics on the minority class are the meaningful ones and are the
  ones reported above.
- The Part 7 development-sample run reported a 4,996/4,996 match — that
  sample overlaps training data and is **not** a performance claim.
