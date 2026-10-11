"""
SentinelAI — Part 4 report generation.

Every number written into a report is computed from the actual data
during the run — nothing is invented or hardcoded.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"


def write_feature_decisions(
    decisions: list[dict], path: Path = REPORTS_DIR / "feature_decisions.md"
) -> Path:
    """Write the table of every feature removed/converted and why."""
    lines = [
        "# Feature Decisions",
        "",
        "Every column removed or converted during Part 4 preprocessing, with the",
        "reason and leakage assessment. No feature is removed without justification.",
        "Empty and constant columns are detected on the TRAINING split only; the",
        "same columns are then dropped from the test split (no test-set leakage).",
        "",
        "| Feature | Decision | Reason |",
        "|---------|----------|--------|",
    ]
    for d in decisions:
        lines.append(f"| {d['feature']} | {d['decision']} | {d['reason']} |")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_feature_summary(
    stats: pd.DataFrame, decisions: list[dict], path: Path = REPORTS_DIR / "feature_summary.md"
) -> Path:
    """Write the per-feature overview (type, missing, unique, role, decision)."""
    decision_map = {d["feature"]: d for d in decisions}
    lines = [
        "# Feature Summary",
        "",
        "Statistics are computed after loading and cleaning, before the train/test",
        "split. Removal decisions for empty/constant columns are derived from the",
        "TRAINING split only and then applied to both splits (no test-set leakage).",
        "",
        "| Feature | Data type | Missing values | Missing ratio | Unique values | Variance | Role | Decision |",
        "|---------|-----------|----------------|---------------|---------------|----------|------|----------|",
    ]
    for _, row in stats.iterrows():
        decision = decision_map.get(row["feature"], {}).get("decision", "kept")
        variance = f"{row['variance']:.4g}" if not pd.isna(row["variance"]) else "-"
        lines.append(
            f"| {row['feature']} | {row['dtype']} | {int(row['missing_values'])} | "
            f"{row['missing_ratio']:.2%} | {int(row['unique_values'])} | {variance} | "
            f"{row['role']} | {decision} |"
        )
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_class_imbalance(
    labels: pd.Series, path: Path = REPORTS_DIR / "class_imbalance.md"
) -> Path:
    """Write the class imbalance analysis (computed, no resampling applied)."""
    counts = labels.value_counts(dropna=False)
    total = int(counts.sum())
    majority = counts.idxmax()
    minority_labels = [str(x) for x in counts[counts == counts.min()].index]
    ratio = float(counts.max() / counts.min())

    lines = [
        "# Class Imbalance Analysis",
        "",
        "Computed from the cleaned dataset (all raw CSV files loaded by the",
        "pipeline). NO oversampling, undersampling or SMOTE is applied in",
        "Part 4 - this report only documents the problem.",
        "",
        "| Class | Count | Percentage |",
        "|-------|-------|------------|",
    ]
    for label, count in counts.items():
        lines.append(f"| {label} | {int(count)} | {count / total * 100:.2f}% |")
    lines += [
        "",
        f"- Total records analysed: {total}",
        f"- Majority class: {majority} ({int(counts.max())} records)",
        f"- Minority class(es): {', '.join(minority_labels)} ({int(counts.min())} records)",
        f"- Imbalance ratio (majority / minority): {ratio:.1f} : 1",
        "",
        "## Why class imbalance matters for an intrusion detection system",
        "",
        "Attacks are rare compared with benign traffic — exactly what the numbers",
        "above show. A model trained on imbalanced data can achieve high overall",
        "accuracy by simply predicting 'benign' for every flow, while missing nearly",
        "every attack, which is the entire point of an IDS. Later phases must",
        "therefore evaluate with precision, recall and F1 (especially on the minority",
        "attack classes) and must not rely on accuracy alone. Handling the imbalance",
        "(resampling, class weights) is deliberately deferred to later phases.",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_preprocessing_summary(
    summary: dict, decisions: list[dict], path: Path = REPORTS_DIR / "preprocessing_summary.md"
) -> Path:
    """Write the reproducibility record of the preprocessing run."""
    binary = summary["binary_mapping"]
    multiclass = summary["multiclass_mapping"]
    lines = [
        "# Preprocessing Summary",
        "",
        "Reproducibility record for the Part 4 preprocessing run.",
        "",
        "## Dataset",
        "",
        "- Source files: " + ", ".join(summary["source_files"]),
        "- Source: CIC-IDS2017 (Canadian Institute for Cybersecurity / UNB), official subset",
        f"- Random seed (all random operations): `random_state = {summary['random_state']}`",
        "",
        "## Train/test split",
        "",
        f"- Split: {int((1 - summary['test_fraction']) * 100)}% training / "
        f"{int(summary['test_fraction'] * 100)}% testing",
        f"- Stratification: {summary['stratification']}",
        f"- Training records: {summary['train_size']}",
        f"- Test records: {summary['test_size']}",
        f"- Records after cleaning: {summary['records_after_cleaning']}",
        f"- Duplicates removed: {summary['duplicates_removed']}",
        f"- Infinite values replaced with NaN (then imputed): {summary['infinite_replaced_with_nan']}",
        "",
        "## Record and feature counts",
        "",
        f"- Raw records: {summary['raw_records']}",
        f"- Raw features (columns): {summary['raw_features']}",
        f"- Final features after preprocessing: {summary['final_features']}",
        f"- Numeric features: {summary['numeric_features']}",
        f"- Categorical features: {summary['categorical_features']}",
        "",
        "## Label encoding",
        "",
        "- Binary target: " + " ".join(f"`{k}` -> {v}" for k, v in binary.items()),
        "- Multiclass target:",
    ]
    for label, idx in multiclass.items():
        lines.append(f"  - `{label}` -> {idx}")
    lines += [
        "",
        "## Cleaning / feature-selection / encoding decisions",
        "",
        "| Feature | Decision | Reason |",
        "|---------|----------|--------|",
    ]
    for d in decisions:
        lines.append(f"| {d['feature']} | {d['decision']} | {d['reason']} |")
    lines += [
        "",
        "## Missing values and scaling",
        "",
        "- Numeric features: missing values imputed with the TRAINING-set median,",
        "  then standardized with StandardScaler fitted on the TRAINING set only.",
        "- Test data is only transformed — never used for fitting (no data leakage).",
        "",
        "## Saved artifacts",
    ]
    for key, value in summary["artifacts"].items():
        lines.append(f"- {key}: {value}")
    lines += [
        "",
        "## Validation",
        "",
        f"- Problems found: {len(summary['validation_problems'])}",
        "- Label encoder reversibility: verified during the run",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
