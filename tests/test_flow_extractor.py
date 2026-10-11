"""Tests for Part 10 flow identification.

Packets are tiny benign synthetic fixtures — no attack traffic.
"""

from scapy.all import ARP, Ether, ICMP, IP, TCP, UDP

from src.network.flow_extractor import extract_flows, packet_flow_key


def _tcp(src, dst, sport, dport, t):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport)
    pkt.time = t
    return pkt


def _udp(src, dst, sport, dport, t):
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    pkt.time = t
    return pkt


def _icmp(src, dst, t):
    pkt = Ether() / IP(src=src, dst=dst) / ICMP()
    pkt.time = t
    return pkt


def test_same_tuple_groups_into_one_flow():
    packets = [
        _tcp("10.0.0.1", "192.168.0.1", 12345, 80, 1000.0),
        _tcp("10.0.0.1", "192.168.0.1", 12345, 80, 1001.0),
        _tcp("10.0.0.1", "192.168.0.1", 12345, 80, 1002.0),
    ]
    flows = extract_flows(packets)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.packet_count == 3
    assert flow.fwd_packets == 3
    assert flow.bwd_packets == 0
    assert flow.duration == 2.0


def test_bidirectional_packets_merge_into_one_flow():
    packets = [
        _tcp("192.168.0.1", "10.0.0.1", 12345, 80, 1000.0),
        _tcp("10.0.0.1", "192.168.0.1", 80, 12345, 1000.5),
        _tcp("10.0.0.1", "192.168.0.1", 80, 12345, 1001.0),
        _tcp("192.168.0.1", "10.0.0.1", 12345, 80, 1001.5),
    ]
    flows = extract_flows(packets)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.fwd_packets == 2
    assert flow.bwd_packets == 2
    assert flow.packet_count == 4
    assert flow.byte_count == sum(len(p) for p in packets)


def test_different_ports_create_different_flows():
    packets = [
        _tcp("192.168.0.1", "10.0.0.1", 12345, 80, 1000.0),
        _tcp("192.168.0.1", "10.0.0.1", 12346, 443, 1001.0),
    ]
    assert len(extract_flows(packets)) == 2


def test_icmp_flows_have_no_ports():
    packets = [
        _icmp("192.168.0.1", "10.0.0.1", 1000.0),
        _icmp("10.0.0.1", "192.168.0.1", 1000.5),
    ]
    flows = extract_flows(packets)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.sport is None and flow.dport is None
    assert flow.fwd_packets == 1 and flow.bwd_packets == 1


def test_non_ip_packets_are_ignored():
    arp = Ether() / ARP(
        op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.0.1",
        hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.0.1",
    )
    arp.time = 999.0
    packets = [
        arp,  # no IP layer
        _tcp("192.168.0.1", "10.0.0.1", 12345, 80, 1000.0),
    ]
    flows = extract_flows(packets)
    assert len(flows) == 1


def test_flow_key_canonicalizes_direction():
    a = _tcp("192.168.0.1", "10.0.0.1", 12345, 80, 1000.0)
    b = _tcp("10.0.0.1", "192.168.0.1", 80, 12345, 1000.5)
    key_a, fwd_a = packet_flow_key(a)
    key_b, fwd_b = packet_flow_key(b)
    assert key_a == key_b
    # canonical order: "10.0.0.1" < "192.168.0.1", so the packet FROM
    # 10.0.0.1 is forward and the packet FROM 192.168.0.1 is backward
    assert fwd_a is False and fwd_b is True


def test_extraction_is_deterministic():
    packets = [
        _tcp("192.168.0.1", "10.0.0.1", 12345, 80, 1000.0),
        _udp("172.16.0.1", "10.0.0.2", 53, 53, 1000.1),
    ]
    first = [(f.src, f.dst, f.sport, f.dport, f.protocol) for f in extract_flows(packets)]
    second = [(f.src, f.dst, f.sport, f.dport, f.protocol) for f in extract_flows(packets)]
    assert first == second


def test_flow_ids_are_deterministic_first_seen_order():
    from src.network.feature_extractor import features_frame

    packets = [
        _tcp("192.168.0.1", "10.0.0.1", 12345, 80, 1000.0),
        _udp("172.16.0.1", "10.0.0.2", 53, 53, 1000.1),
        _tcp("192.168.0.1", "10.0.0.1", 12345, 80, 1000.2),
    ]
    frames_a = features_frame(extract_flows(packets))
    frames_b = features_frame(extract_flows(packets))
    assert frames_a["flow_id"].tolist() == ["flow_000000", "flow_000001"]
    assert frames_a["flow_id"].tolist() == frames_b["flow_id"].tolist()
    assert frames_a["src"].tolist() == frames_b["src"].tolist()


def test_empty_capture_extracts_no_flows():
    assert extract_flows([]) == []
