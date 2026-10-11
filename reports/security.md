# SentinelAI — Security Documentation

SentinelAI is a **defensive research system**. This document records its
security posture, the boundaries that are enforced by automated tests,
and the honest residual risks.

## Defensive-only scope

The project processes public benchmark data (CIC-IDS2017) and
authorized local files only. It contains no attack tooling, no malware,
no credential handling, no scanning, no packet injection, no evasion,
and no persistence mechanisms.

## Enforced boundaries (automated tests)

`tests/validation/` scans the operational code on every run:

| Boundary | Enforcement |
| --- | --- |
| No real firewall/network blocking | Response module contains no `subprocess`, `os.system`, `socket`, `netsh`, `iptables`, `ufw`, `firewall-cmd`, `pfctl`; DRY_RUN never calls an executor (tested across the probability grid); AUTHORIZED refuses to construct without an explicitly supplied isolated adapter (none is shipped) |
| No live packet capture | `src/network/` contains no `sniff(`/`AsyncSniffer`/raw sockets; only file-based scapy readers (`PcapReader`/`PcapNgReader`) |
| No packet injection / send | No `send(`/`sendp(`/`sr(`/`sr1(`/`arping(`/`L2socket`/`L3socket` |
| No dynamic execution | No `eval()`/`exec()`/`__import__()`/`pickle.load` in operational code |
| No external communication | No `requests`/`urllib`/`http` client imports anywhere |
| No write-SQL in the dashboard | Dashboard sources contain no `INSERT/UPDATE/DELETE/DROP/ALTER`; it is read-only and has no blocking controls |
| Untrusted PCAP handling | Files validated (existence, extension, magic bytes, size) before parsing; streaming reads; packet payloads never executed, logged, or stored; nothing from a packet is evaluated |
| Parameterized SQL only | Repository SQL is scanned: values never interpolated; the only interpolations are code-constant column/placeholder strings; an injection-shaped value is stored literally (tested) |
| No secrets in code | Scans for password/API-key/secret/token literals: none; a credential-free `.env.example` template exists |

## Response staging (the safety core)

Four concepts are deliberately separate and never conflated:
detection (model output) → recommended response (policy) → simulated
response (`DRY_RUN_BLOCK`/SIMULATED, nothing changes) → actual
authorized response (`BLOCK_REQUESTED`, reachable only via an
explicitly supplied adapter in AUTHORIZED mode).

**SentinelAI does not perform real firewall or network blocking in the
current implementation.** In the default DRY_RUN mode the policy can
only simulate and log. Verified in the real end-to-end run: 73
high-confidence attacks produced 73 SIMULATED dry-run blocks, 0 block
requests, 0 authorized actions.

## Database security

SQLite file, project-relative path, git-ignored (real records never
committed). Foreign keys enforced; insert-time integrity validation
(probability ∈ [0,1], validated response states, action/status
consistency); transactional batches (no partial writes); migrations
are additive-only and idempotent.

## Residual risks (honest)

- **Model artifact trust:** `joblib` deserialization is pickle-based —
  loading untrusted artifact files could execute code. Only load
  artifacts produced by this project from trusted local storage; a
  safer serialization format is listed as future work.
- **Dashboard authentication:** the Streamlit dashboard has no
  authentication and is single-user/local by design. Do not expose it
  to untrusted networks.
- **Local data sensitivity:** PCAP files and datasets can contain
  sensitive network information — they are git-ignored, never uploaded,
  and payloads are never retained, but operators should still treat
  local captures confidentially.
- **Input robustness:** malformed inputs are handled gracefully (tested
  for truncated/garbage PCAPs), but no fuzzing campaign has been run.
