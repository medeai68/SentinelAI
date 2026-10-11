# SentinelAI — Executive Summary

**SentinelAI: an AI-powered network intrusion detection and threat
analysis system — research prototype, defensive-only, validated
2026-10-07.**

## Problem & motivation

Network intrusions are rare events buried in overwhelming amounts of
benign traffic. Building a machine-learning intrusion detector is easy
to do badly: leakage, imbalanced-data pitfalls, and "accuracy theatre"
routinely produce models that look excellent and detect almost nothing.
At the same time, automated *response* is the riskiest part of any
defensive stack, so a research prototype must demonstrate detection
capability without ever risking a real network action.

## Proposed system

SentinelAI implements the complete defensive chain — dataset → ML
training → detection → controlled response → storage → dashboard —
under a strict no-fabrication and defensive-only policy. The response
layer is **simulation-first**: the default and only shipped mode is
DRY_RUN, and any real action requires an explicitly supplied, isolated
adapter that this project does not contain.

## Methodology & dataset

Public benchmark **CIC-IDS2017** (official per-day CSVs; three files,
904,877 raw flows, 7 classes). Preprocessing removed 76,769 duplicates,
handled the dataset's known infinite values with training-only median
imputation, and produced an 80/20 stratified split (662,486 / 165,622)
with seed 42. Preprocessing was fitted **only** on training data; the
test set was touched once, at the end.

## Models & winner

Logistic Regression, Random Forest and XGBoost were evaluated as
baselines, then tuned by stratified 5-fold cross-validation scored on
attack F1 (class imbalance handled with class weights /
`scale_pos_weight`). **XGBoost won** and achieved, on the untouched
test set:

**Accuracy 0.99995 · Precision 0.99780 · Recall 0.99868 · F1 0.99824 ·
ROC-AUC 0.99990 · TP 2,263 · TN 163,351 · FP 5 · FN 3 · FNR 0.13%.**

These numbers describe a lab dataset under a careful protocol; they are
not a generalization guarantee.

## Detection architecture

The detection engine validates input against the fitted preprocessor's
own schema, transforms (never refits), predicts with the saved XGBoost
artifact, and emits structured results (prediction, attack probability,
severity, model, timestamp, flow id).

## Controlled response (simulation)

A configurable policy maps detections to `NO_ACTION`, `ALERT_ONLY`,
`DRY_RUN_BLOCK`, or `BLOCK_REQUESTED` using validated thresholds (0.50
detection; 0.80 high-confidence). **DRY_RUN is the default:** it
simulates and logs what a response *would* do. A real PCAP-driven run
verifies this end-to-end: 73 high-confidence attacks → 73
`DRY_RUN_BLOCK`/**SIMULATED**, zero block requests.

## PCAP capability

An offline analyzer reads authorized local captures, reconstructs
bidirectional flows, extracts 13 reliable features, and applies an
honest compatibility gate. **Limitation (documented, not hidden): 11 of
those features overlap the model's 70-feature schema, so complete
inference from arbitrary PCAPs is not currently possible** — such runs
end with `INCOMPLETE` and no forced predictions.

## Validation

251 tests pass (unit + integration + security/safety scans); 65%
coverage; leakage, reproducibility, artifact-integrity, database,
dashboard, portability, dependency and git audits all pass; the real
database (4,996 detections) and the model artifact hash are unchanged
through validation.

## Limitations & future work

Single lab dataset, no external validation; extreme class imbalance;
the PCAP gate above; local dashboard without authentication (not
browser-visually tested); Windows-tested only (Linux untested);
pickle-based model artifacts (trusted-local loading only). Future work:
external validation, a CICFlowMeter-compatible extractor to close the
PCAP gate, browser tests, retention policy, Linux CI, and stronger
artifact trust.
