# Dataset Attribution — CIC-IDS2017

## Source

**CIC-IDS2017** — Canadian Institute for Cybersecurity (CIC),
University of New Brunswick (UNB), Canada.

- Official page: <https://www.unb.ca/cic/datasets/ids-2017.html>
- Distribution: downloads are provided through CIC's registration
  portal (~short form: name, email, organization, country), reached via
  the official page's "Download this dataset" link
  (`cicresearch.ca/CICDataset/CIC-IDS-2017/`). The legacy direct
  S3 links are defunct (verified HTTP 301 → 403 in Part 3).

## Required citation

> Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).
> *Toward Generating a New Intrusion Detection Dataset and Intrusion
> Traffic Characterization.* Proceedings of the 4th International
> Conference on Information Systems Security and Privacy (ICISSP),
> Portugal, January 2018.

## Files actually used in this project

| File (official name) | Rows | Size |
| --- | ---: | ---: |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 445,909 | 128.82 MB |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 170,366 | 49.61 MB |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 288,602 | 79.25 MB |

Total: **904,877 flows × 79 columns** (78 flow features + Label).
(Note: the official filename really contains the misspelling
"Infilteration".)

## Labels observed (actual inspection)

BENIGN, FTP-Patator, SSH-Patator, Web Attack - Brute Force, Web Attack
- XSS, Web Attack - Sql Injection, Infiltration. BENIGN dominates
(98.63% of the cleaned data; majority/minority ratio 38,894:1 — see
`reports/class_imbalance.md`). Web-Attack labels arrive with a
lossy-encoded en-dash (U+FFFD in the files); the project normalizes it
to "-" in memory and documents this.

## Dataset limitations (documented in this project)

- Captured in a CIC lab in July 2017; traffic patterns may not match
  other networks (no external validation has been performed).
- Known data-quality issues: duplicate rows (76,769 removed here),
  "Infinity" literals in `Flow Bytes/s` / `Flow Packets/s` (handled),
  label correctness caveats discussed in the literature.
- Extreme class imbalance; the development subset used here covers 7 of
  the full dataset's attack categories (no DDoS/Botnet days included).

## Licensing / terms (only what was verified)

The official page states the dataset is **publicly available for
researchers** and that users **must cite the related paper** (text
verified in Part 3 research). **No formal license text or SPDX
identifier is stated on the official page** — none is asserted here,
and none should be assumed. Re-check the official page for current
terms before redistribution. The dataset itself is **not** included in
this repository.
