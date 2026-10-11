# Part 10 — Offline PCAP & Network Analysis Finalization

**MODE: OFFLINE · AUTHORIZED FILES ONLY · RESPONSE MODE: DRY_RUN**

Status: complete. All results below are actual measurements from
2026-10-07. The pipeline analyzes local PCAP files; it never captures
live traffic, never touches the network, and never performs a real
response.

## 1. PCAP architecture

```
Authorized PCAP file
  ↓ pcap_reader.py       safe, streaming file reading (untrusted data)
  ↓ flow_extractor.py    bidirectional 5-tuple flow reconstruction
  ↓ feature_extractor.py reliably computable CIC-named feature subset
  ↓ compatibility gate   vs the optimized model's actual schema + metadata
  ↓ (only if COMPATIBLE) Part 7 ThreatDetector → DetectionResult
  ↓ Part 7 ResponseEngine (reused — DRY_RUN default)
  ↓ optional Part 8 Repository storage (detections + responses)
```

No second ML implementation and no PCAP-specific response mechanism
exist — both are the existing Part 7 components (enforced by a safety
test).

## 2. Reader validation

`validate_pcap_path` / `read_packets` check: file exists, `.pcap`/
`.pcapng` extension, readable magic bytes (both endiannesses + pcapng),
non-empty, and a configurable maximum size (default 200 MB). Reading is
**streaming** (PcapReader/PcapNgReader — file readers only) so large
captures are not loaded into memory. Truncated captures are handled
gracefully (scapy warns; the reader does not crash). Packet contents are
strictly data: nothing is executed, payloads are never logged or stored.

## 3. Flow reconstruction

Flows are bidirectional exchanges keyed by the canonical 5-tuple
(source, destination, source port, destination port, protocol). Both
directions merge into ONE flow via lexicographic canonical ordering;
forward direction is deterministic (not arrival-order). Non-IP packets
are ignored. Flow IDs are deterministic first-seen indices
(`flow_000000`, `flow_000001`, …). Only per-flow counters are kept.

## 4. Feature extraction

13 reliably computable features under exact CIC-IDS2017 names
(Flow_Duration, Total_Fwd/Backward_Packets, Total_Length_of_Fwd/Bwd,
Flow_Bytes/s, Flow_Packets/s, Source/Destination_Port, Protocol,
Packet_Length_Mean/Variance, Average_Packet_Size). Zero-packet /
zero-duration flows are guarded (no division errors). No fabricated
values.

## 5. Model compatibility (actual measurements)

- The optimized model's schema comes from its own artifacts:
  `models/preprocessing/feature_columns.json`
  (`input_feature_columns`, 70 names) and the model metadata
  (`feature_count = 70`), cross-checked at analysis time.
- **Overlap (measured): 11 of the 13 extractable features exist in the
  model's 70-feature schema** (`Protocol` and `Source_Port` are not —
  they were dropped during Part 4 training as non-informative/constant
  on the development subset).
- **Real-model run (actual):** a 5,000-packet benign capture →
  `Packets processed: 5000 | Flows extracted: 50 | Flows compatible: 0
  | Flows incompatible: 50 | Feature compatibility: INCOMPLETE
  (59 of 70 required features missing) | Model feature count
  (metadata): 70 | Detection counts: none (no predictions forced) |
  Responses: none (detection not executed)`.
- A feature-count disagreement between the model metadata and the saved
  feature list is itself treated as INCOMPLETE with a clear reason
  (tested). Missing features are never filled with fabricated values
  and the model is never retrained.

## 6. Detection integration

Only a fully compatible feature set reaches the existing Part 7
`ThreatDetector` (existing preprocessing artifact, transform-only;
`models/xgboost_optimized.joblib`). Output fields match Part 7 exactly
(prediction, attack probability, severity, model name/version,
timestamp, flow id). A flow is reported as "analyzed" only when the
model actually produced a prediction — compatible-without-model runs
report zero analyzed flows.

## 7. Response integration

Compatible detected attacks flow through the existing Part 7
`ResponseEngine` (default DRY_RUN policy). Verified by tests with a
deterministic attack fixture: **attack → DRY_RUN_BLOCK → SIMULATED**,
mode DRY_RUN, for every flow; `block_requested`/`authorized` remain 0.
No executor is ever invoked in DRY_RUN, and no PCAP-specific response
mechanism exists.

## 8. Database integration

Stored through the existing Part 8 `Repository` (no second database, no
bypass): `DetectionRecord.from_detection_and_response(...)` writes
detections WITH their response fields (`--store`). Verified against a
temporary database: 2 rows with `response_action=DRY_RUN_BLOCK`,
`response_mode=DRY_RUN`, `response_status=SIMULATED`; repository stats
`dry_run_block_count == simulated_count == 2`, `block_requested == 0`,
`authorized == 0`. Source distinction reuses the existing flow-id
convention (PCAP flows are `flow_NNNNNN`; detection-CLI flows are
`row_N`) — no schema change was necessary. Database failures during
storage are reported cleanly (exit 1) without crashing the analysis.
Tests use temporary databases only; the real database is untouched
(4,996 rows before and after all Part 10 work).

## 9. CLI / API

```
analyze_pcap(path, *, max_bytes, features_path, detector_kwargs) -> dict
```

returns: packets · flows · compatible_flows · incompatible_flows ·
analyzed · rejected · errors · detections · simulated_responses ·
response_mode · response_results · compatibility · frame ·
detection_results · detector.

CLI: `python -m src.network.pcap_pipeline --input <authorized.pcap>
[--output flows.csv] [--store] [--model ...]` — prints an explicit
`MODE: OFFLINE | RESPONSE MODE: DRY_RUN` banner, per-stage counts,
response counts, and writes the compatibility report. No live capture,
sniffing, injection, blocking or firewall options exist.

## 10. Security boundaries

Automated scans (in the suite) assert `src/network/` contains no
`sniff(`/AsyncSniffer/send/sr/arping/L2socket/L3socket, no `socket`
usage, no subprocess/os.system, no requests/urllib, no firewall tooling
(`iptables`/`netsh`/`ufw`/`firewall-cmd`/`pfctl`); the reader uses only
file-based scapy readers; and the pipeline contains no `fit(` or
`predict_proba` calls (it reuses the Part 7 engine rather than
reimplementing ML). PCAP input is validated before any parsing, and
payloads are never retained.

## 11. Performance measurements (actual, 5,000-packet benign capture, 50 flows)

| Stage | Time |
| --- | --- |
| PCAP reading (streaming, 5,000 packets) | 651 ms (~7,700 packets/s) |
| Flow extraction | 137 ms |
| Feature extraction | 5.3 ms |
| `analyze_pcap` total (re-reads + compatibility + reporting) | 925 ms |

Adequate for offline analysis. **This is an offline pipeline — no
real-time performance is claimed.**

## 12. Tests

`python -m pytest tests -q` → **249 passed, 0 failed** (was 237 after
Part 9; +12 Part 10 tests). Coverage added: deterministic flow IDs and
empty captures; guarded empty-flow features; wrong feature count /
wrong feature names / unavailable schema; compatible-without-model
no-prediction behavior; model-metadata count mismatch rejection;
attack → simulated DRY_RUN responses end-to-end; response fields
persisted to a temporary database with honest statistics; CLI offline
banner; and the PCAP safety scans above.

## 13. Limitations

- The extractable feature subset (11 of the model's 70 schema names)
  cannot feed the optimized model on its own — full CICFlowMeter
  reconstruction was deliberately not attempted, so real PCAP analysis
  currently ends at the INCOMPLETE gate (the honest, spec-required
  behavior). Completing it is future work with a dedicated feature
  pipeline validated against CICFlowMeter.
- No PCAP sample ships with the project; users supply authorized files.
- Scapy prints a harmless "no libpcap provider" notice on this machine
  (only affects live capture, which this project does not do).
- Detection metrics are never claimed for PCAP runs unless the gate
  passes and the actual model executed.
