# Feature Decisions

Every column removed or converted during Part 4 preprocessing, with the
reason and leakage assessment. No feature is removed without justification.
Empty and constant columns are detected on the TRAINING split only; the
same columns are then dropped from the test split (no test-set leakage).

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
