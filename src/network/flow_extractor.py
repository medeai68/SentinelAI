"""SentinelAI — flow identification from packets (Part 10).

A flow is a bidirectional exchange identified by the canonical 5-tuple
(source address, destination address, source port, destination port,
protocol). The flow key is ONLY a grouping mechanism — it is never
treated as an attack indicator.

Documented approach (reports/pcap_analysis.md):

  * for TCP/UDP the ports are part of the key,
  * for other protocols (e.g. ICMP) ports are None (0 in output),
  * the two directions of one exchange are merged into ONE flow by
    ordering the (address, port) pairs lexicographically — the
    canonical orientation defines the forward direction
    deterministically (not packet arrival order),
  * non-IP packets are ignored (they cannot produce flow features).

Memory stays constant for large captures: only per-flow counters are
kept, never the packets themselves.
"""

from __future__ import annotations

from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


@dataclass
class FlowRecord:
    """Aggregated counters for one bidirectional flow."""

    src: str
    dst: str
    sport: int | None
    dport: int | None
    protocol: int
    first_seen: float
    last_seen: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    length_sum: int = 0
    length_sq_sum: int = 0

    @property
    def packet_count(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def byte_count(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def duration(self) -> float:
        """Duration in seconds."""
        return max(0.0, self.last_seen - self.first_seen)

    def to_flow_id(self, index: int) -> str:
        """Deterministic flow identifier for a batch index."""
        return f"flow_{index:06d}"


def packet_flow_key(packet: Packet) -> tuple[tuple, bool] | None:
    """Return ((canonical 5-tuple), is_forward) for an IP packet, or None.

    The canonical tuple orders the two (address, port) sides
    lexicographically, so both directions of one exchange map to the
    same key.
    """
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip is None:
        return None
    sport = dport = None
    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    if tcp is not None:
        sport, dport = int(tcp.sport), int(tcp.dport)
    elif udp is not None:
        sport, dport = int(udp.sport), int(udp.dport)

    side_a = (ip.src, sport or 0)
    side_b = (ip.dst, dport or 0)
    if side_a <= side_b:
        return (ip.src, ip.dst, sport, dport, int(ip.proto)), True
    return (ip.dst, ip.src, dport, sport, int(ip.proto)), False


def packet_timestamp(packet: Packet) -> float:
    """Packet capture timestamp in seconds (0.0 when unavailable)."""
    try:
        return float(packet.time) if packet.time is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def extract_flows(packets) -> list[FlowRecord]:
    """Aggregate a packet stream into bidirectional flows.

    Flows are returned in first-seen order (deterministic). Only
    counters are kept — packet payloads are never stored.
    """
    flows: dict[tuple, FlowRecord] = {}
    order: list[tuple] = []

    for packet in packets:
        keyed = packet_flow_key(packet)
        if keyed is None:
            continue  # non-IP packets cannot produce flow features (documented)
        key, is_forward = keyed
        timestamp = packet_timestamp(packet)
        length = int(len(packet))

        if key not in flows:
            src, dst, sport, dport, proto = key
            flows[key] = FlowRecord(
                src=src,
                dst=dst,
                sport=sport,
                dport=dport,
                protocol=proto,
                first_seen=timestamp,
                last_seen=timestamp,
            )
            order.append(key)

        record = flows[key]
        record.first_seen = min(record.first_seen, timestamp)
        record.last_seen = max(record.last_seen, timestamp)
        record.length_sum += length
        record.length_sq_sum += length * length
        if is_forward:
            record.fwd_packets += 1
            record.fwd_bytes += length
        else:
            record.bwd_packets += 1
            record.bwd_bytes += length

    return [flows[key] for key in order]
