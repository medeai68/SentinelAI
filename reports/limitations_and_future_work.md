# SentinelAI — Limitations & Future Work

## Current limitations (verified, honest)

### Dataset & models
- **Single lab dataset:** all results come from a CIC-IDS2017 subset
  (three per-day files, 7 classes). **No external dataset validation**
  has been performed; the measured metrics are not a generalization
  guarantee.
- **Extreme class imbalance:** BENIGN is 98.63% of the cleaned data
  (majority/minority 38,894:1). Class weights mitigate but do not
  remove the problem; minority-class metrics remain the meaningful
  ones.
- **Dataset coverage:** the subset excludes the full dataset's DDoS,
  Botnet, DoS and Heartbleed days.
- **Threshold caution:** the 0.5 default was kept for the final
  evaluation; the tuning-optimal thresholds (e.g. LR 0.16) are
  documented, not universally applied.

### PCAP capability
- **Feature compatibility limitation (explicit):** the PCAP pipeline
  extracts **13 reliable features**, **11 of which overlap the model's
  70-feature schema**. Complete inference from arbitrary PCAPs is
  therefore **not currently possible**; such runs end with the honest
  `INCOMPLETE` result and no predictions are forced.

### Infrastructure
- **SQLite single-writer:** fine for research and the local dashboard,
  not for concurrent multi-user workloads; no retention/rotation
  policy exists yet.
- **Dashboard:** local, single-user, **no authentication**; it was
  validated headlessly (health + HTTP + bare-mode page execution) but
  **no browser-visual testing** was performed.
- **Platform:** **Windows 11 was tested; Linux was not.** Portability
  is supported by structure (no absolute paths in code, `pathlib`
  everywhere) but unverified on other platforms.
- **Model artifacts:** `joblib` is pickle-based — trusted-local loading
  only (see `reports/security.md`).
- **Coverage:** 65% overall; the experiment drivers and report/chart
  writers are exercised by real runs rather than unit tests.

## Future work (from the validated Part 11 list)

1. **External validation dataset** — test the selected model on an
   independent capture/dataset before any operational claim.
2. **Validated CICFlowMeter-compatible feature extraction** — close the
   PCAP compatibility gate so end-to-end PCAP inference becomes
   possible with the real model.
3. **Browser-based UI testing** — automated visual checks plus manual
   screenshots before publication.
4. **Database retention policy** — archival/rotation for long-running
   deployments.
5. **Linux CI** — run the suite on Linux to verify cross-platform
   behavior.
6. **Higher unit coverage** — experiment drivers, report writers,
   dashboard page functions.
7. **Stronger model serialization/trust strategy** — e.g.
   ONNX or signed artifacts instead of pickle-based joblib.
8. **Broader validation** — more attack categories, per-class metrics
   over the full CIC-IDS2017 set, and drift evaluation.
9. **Richer host/context features** — beyond flow-level statistics
   (carefully, with leakage controls).

## Scope that will NOT be added

Live packet capture, real firewall/network blocking, automated
incident response, attack generation, scanning, injection, malware or
offensive tooling — outside the project's defensive research scope by
design.
