# Class Imbalance Analysis

Computed from the cleaned dataset (all raw CSV files loaded by the
pipeline). NO oversampling, undersampling or SMOTE is applied in
Part 4 - this report only documents the problem.

| Class | Count | Percentage |
|-------|-------|------------|
| BENIGN | 816777 | 98.63% |
| FTP-Patator | 5933 | 0.72% |
| SSH-Patator | 3219 | 0.39% |
| Web Attack - Brute Force | 1470 | 0.18% |
| Web Attack - XSS | 652 | 0.08% |
| Infiltration | 36 | 0.00% |
| Web Attack - Sql Injection | 21 | 0.00% |

- Total records analysed: 828108
- Majority class: BENIGN (816777 records)
- Minority class(es): Web Attack - Sql Injection (21 records)
- Imbalance ratio (majority / minority): 38894.1 : 1

## Why class imbalance matters for an intrusion detection system

Attacks are rare compared with benign traffic — exactly what the numbers
above show. A model trained on imbalanced data can achieve high overall
accuracy by simply predicting 'benign' for every flow, while missing nearly
every attack, which is the entire point of an IDS. Later phases must
therefore evaluate with precision, recall and F1 (especially on the minority
attack classes) and must not rely on accuracy alone. Handling the imbalance
(resampling, class weights) is deliberately deferred to later phases.
