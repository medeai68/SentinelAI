# SentinelAI PCAP Analysis (Part 10)

## Authorized-use requirement

This component analyzes **local, explicitly authorized PCAP files only**.
It performs no live capture, no scanning, and no network activity of any
kind. PCAP contents are treated strictly as untrusted input: nothing in
a packet is ever executed, payloads are never logged or stored, and
nothing is sent to external services.

## Architecture

```
Authorized PCAP
  ↓ pcap_reader.py     safe, streaming reader (size/format validation)
  ↓ flow_extractor.py  bidirectional flow identification (5-tuple)
  ↓ feature_extractor.py  reliably computable feature subset
  ↓ feature validation / compatibility check
  ↓ (only when fully compatible) Part 7 Threat Detection Engine
  ↓ optional SQLite storage (Part 8 repository)
```

## Flow definition

A flow is a bidirectional exchange identified by the canonical 5-tuple
(source address, destination address, source port, destination port,
protocol). For TCP/UDP the ports are part of the key; for other
protocols (e.g. ICMP) ports are `None` (0 in output). The two directions
of one exchange are merged into ONE flow by ordering the (address, port)
sides lexicographically — the canonical orientation defines the forward
direction deterministically (not packet arrival order). Non-IP packets
are ignored. The flow key is ONLY a grouping mechanism — it is never
treated as an attack indicator.

Memory stays constant for large captures: packets are read in a stream
and only per-flow counters are kept.

## Feature extraction

Only features computable reliably from raw packets are extracted, using
the exact CIC-IDS2017 column names:

`Flow_Duration`, `Total_Fwd_Packets`, `Total_Backward_Packets`,
`Total_Length_of_Fwd_Packets`, `Total_Length_of_Bwd_Packets`,
`Flow_Bytes/s`, `Flow_Packets/s`, `Source_Port`, `Destination_Port`,
`Protocol`, `Packet_Length_Mean`, `Packet_Length_Variance`,
`Average_Packet_Size`.

## Compatibility

The CIC-IDS2017 model expects ~78 CICFlowMeter features. Most of them
(inter-arrival-time statistics, TCP flag counts, subflow and idle
statistics, …) require the full CICFlowMeter implementation and are
deliberately NOT approximated — fabricating them would corrupt the
model input. The pipeline compares the extractable subset against the
saved feature list (`models/preprocessing/feature_columns.json`):

- fully compatible → the Part 7 engine runs with the existing
  preprocessing artifact and optimized model (no retraining, no
  refitting);
- not compatible → predictions are NOT forced; every flow is reported
  with status `feature set incomplete`, and the comparison is written
  to `reports/pcap_feature_compatibility.md`.

Current state: the model feature list does not exist yet (Part 4 has
not run — dataset pending), so all real runs report INCOMPLETE, which
is the correct honest behavior.

## Limitations

- The extracted feature subset cannot drive the CIC-IDS2017 model on
  its own (documented above).
- Flows are derived from offline captures only; timing and ordering
  reflect the capture file.
- No live capture is implemented — deliberately (later phase, and only
  for authorized networks).
- No sample PCAP is bundled; users provide their own authorized files.
