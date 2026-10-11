# PCAP Feature Compatibility

Comparison between the features the CIC-IDS2017 model requires and the
features the Part 10 PCAP pipeline can compute reliably from raw packets.

- Verdict: **INCOMPLETE — predictions are NOT forced**
- Model-required features: 0
- PCAP-extractable features: 13

## Extractable features (exact CIC-IDS2017 names)

Average_Packet_Size, Destination_Port, Flow_Bytes/s, Flow_Duration, Flow_Packets/s, Packet_Length_Mean, Packet_Length_Variance, Protocol, Source_Port, Total_Backward_Packets, Total_Fwd_Packets, Total_Length_of_Bwd_Packets, Total_Length_of_Fwd_Packets

## Missing features (cannot be reconstructed reliably from raw packets)

- (model feature list unavailable)

Most missing features are CICFlowMeter statistics (inter-arrival-time
means/std, TCP flag counts, subflow and idle statistics, ...) that require
the full CICFlowMeter implementation. They are deliberately not
approximated with fake values — fabricating them would corrupt the model
input. Flows are therefore reported with status 'feature set incomplete'.

## Unsupported extracted features (not needed by the model)

none

## How to provide an authorized PCAP

Place a locally captured (authorized) PCAP file anywhere on this machine
and run:

    python -m src.network.pcap_pipeline --input <authorized.pcap>

Live capture is intentionally NOT implemented in this phase.
