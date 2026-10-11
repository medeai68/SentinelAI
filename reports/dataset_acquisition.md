# Dataset Acquisition — CIC-IDS2017

Status update 2026-10-07: **acquired** — the three small per-day CSV
files were downloaded manually from the official source and placed in
`F:\vs 1\SentinelAI\data\raw\`:

- `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` (79.25 MB)
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (49.61 MB)
- `Tuesday-WorkingHours.pcap_ISCX.csv` (128.82 MB)

Measured dataset values are in `reports/dataset_inspection.md`.

Original 2026-10-06 notes (still accurate about the source):

## Source status (verified today)

- The official Canadian Institute for Cybersecurity (CIC/UNB) page for
  the dataset is <https://www.unb.ca/cic/datasets/ids-2017.html>.
- The legacy direct S3 links (`cic-ids-2017.s3.ca-central-1.amazonaws.com/...`,
  e.g. `MachineLearningCSV.zip` and the per-day CSV files) return
  **HTTP 301 → 403 AccessDenied** — automated download from the
  official host is blocked (re-verified 2026-10-06 with fresh HEAD and
  range requests).
- The official distribution now goes through a **registration form**:
  on the official page click **"Download this dataset"**, which leads
  to the CIC download portal (`cicresearch.ca/CICDataset/CIC-IDS-2017/`).
  The form asks for name, email, organization, and country (the portal
  states the information is used only for internal CIC statistics).
- Filling the form submits personal information, so it must be done by
  the project owner, not by an automated assistant.
- License: free for researchers; the dataset paper must be cited:
  Sharafaldin, Habibi Lashkari & Ghorbani, *"Toward Generating a New
  Intrusion Detection Dataset and Intrusion Traffic Characterization"*,
  ICISSP 2018.

## Exact manual download steps

1. Open <https://www.unb.ca/cic/datasets/ids-2017.html>.
2. Click **"Download this dataset"** and complete the short form.
3. Download **only** these small per-day CSV files (the portal may list
   them individually; otherwise download `MachineLearningCSV.zip` and
   extract just these three):
   - `Tuesday-WorkingHours.pcap_ISCX.csv` (benign + Brute Force FTP/SSH)
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (benign + Web Attacks)
   - `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
     (benign + Infiltration — the official filename contains the
     misspelling "Infilteration")
4. Place the three CSV files **directly in** `F:\vs 1\SentinelAI\data\raw\`
   (that is the layout the existing pipeline expects — it scans
   `data/raw/*.csv`; a `data/raw/CIC-IDS2017/` subfolder would require a
   pipeline change and was therefore not used).

## Expected file layout (what the pipeline reads)

- `data/raw/*.csv` — the per-day flow CSVs (git-ignored, verified:
  `git check-ignore data/raw/...` matches everything under `data/raw/`).
- The pipeline concatenates every CSV found there and derives the label
  column, feature list and 80/20 stratified split (seed 42).

## What happens after the files are placed (run in this order)

```powershell
python -m src.data.inspect_dataset          # Part 3 inspection + summary + sample + chart
python -m src.preprocessing.pipeline        # Part 4 processed data + artifacts
python -m src.training.train_binary         # Part 5 baselines
python -m src.training.model_comparison     # Part 6 tuning + optimized models + report
# then set DEFAULT_MODEL_FILE in config/detection_config.py to the Part 6 winner
python -m src.detection.detector --input <csv> --output reports\detection_sample.csv
python -m src.network.pcap_pipeline --input <authorized.pcap>   # Part 10 (optional)
python -m pytest tests -q
```

## Git safety

- `.gitignore` line 25 (`data/raw/*`, with `!data/raw/.gitkeep`) ignores
  the entire raw dataset directory; `data/processed/*` likewise.
- Nothing is committed or pushed; the repository has no commits at all.
