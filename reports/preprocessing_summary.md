# Preprocessing Summary

Reproducibility record for the Part 4 preprocessing run.

## Dataset

- Source files: Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv, Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv, Tuesday-WorkingHours.pcap_ISCX.csv
- Source: CIC-IDS2017 (Canadian Institute for Cybersecurity / UNB), official subset
- Random seed (all random operations): `random_state = 42`

## Train/test split

- Split: 80% training / 20% testing
- Stratification: multiclass
- Training records: 662486
- Test records: 165622
- Records after cleaning: 828108
- Duplicates removed: 76769
- Infinite values replaced with NaN (then imputed): 841

## Record and feature counts

- Raw records: 904877
- Raw features (columns): 79
- Final features after preprocessing: 70
- Numeric features: 70
- Categorical features: 0

## Label encoding

- Binary target: `BENIGN` -> 0 `ATTACK` -> 1
- Multiclass target:
  - `BENIGN` -> 0
  - `FTP-Patator` -> 1
  - `Infiltration` -> 2
  - `SSH-Patator` -> 3
  - `Web Attack - Brute Force` -> 4
  - `Web Attack - Sql Injection` -> 5
  - `Web Attack - XSS` -> 6

## Cleaning / feature-selection / encoding decisions

| Feature | Decision | Reason |
|---------|----------|--------|
| Bwd_PSH_Flags | removed | Column is constant (a single distinct value) — a model can never learn anything from it, so removing it is safe and reduces noise. Detected on the training split and applied to both splits. |
| Bwd_URG_Flags | removed | Column is constant (a single distinct value) — a model can never learn anything from it, so removing it is safe and reduces noise. Detected on the training split and applied to both splits. |
| Fwd_Avg_Bytes/Bulk | removed | Column is constant (a single distinct value) — a model can never learn anything from it, so removing it is safe and reduces noise. Detected on the training split and applied to both splits. |
| Fwd_Avg_Packets/Bulk | removed | Column is constant (a single distinct value) — a model can never learn anything from it, so removing it is safe and reduces noise. Detected on the training split and applied to both splits. |
| Fwd_Avg_Bulk_Rate | removed | Column is constant (a single distinct value) — a model can never learn anything from it, so removing it is safe and reduces noise. Detected on the training split and applied to both splits. |
| Bwd_Avg_Bytes/Bulk | removed | Column is constant (a single distinct value) — a model can never learn anything from it, so removing it is safe and reduces noise. Detected on the training split and applied to both splits. |
| Bwd_Avg_Packets/Bulk | removed | Column is constant (a single distinct value) — a model can never learn anything from it, so removing it is safe and reduces noise. Detected on the training split and applied to both splits. |
| Bwd_Avg_Bulk_Rate | removed | Column is constant (a single distinct value) — a model can never learn anything from it, so removing it is safe and reduces noise. Detected on the training split and applied to both splits. |

## Missing values and scaling

- Numeric features: missing values imputed with the TRAINING-set median,
  then standardized with StandardScaler fitted on the TRAINING set only.
- Test data is only transformed — never used for fitting (no data leakage).

## Saved artifacts
- train: F:\vs 1\SentinelAI\data\processed\train.csv
- test: F:\vs 1\SentinelAI\data\processed\test.csv
- preprocessor: F:\vs 1\SentinelAI\models\preprocessing\preprocessor.joblib
- label_encoder: F:\vs 1\SentinelAI\models\preprocessing\label_encoder.joblib
- label_mapping: F:\vs 1\SentinelAI\reports\label_mapping.json

## Validation

- Problems found: 0
- Label encoder reversibility: verified during the run
