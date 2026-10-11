"""Tests for Part 10 safe PCAP reading.

Fixtures are tiny benign captures built with scapy — no attack traffic
is generated anywhere in this project.
"""

import struct

import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from src.network.pcap_reader import (
    PcapInputError,
    read_packets,
    validate_pcap_path,
)


def _write_pcap(path, packets):
    for i, pkt in enumerate(packets):
        pkt.time = 1000.0 + i
    wrpcap(str(path), packets)


@pytest.fixture
def benign_packets():
    return [
        Ether() / IP(src="192.168.0.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
        Ether() / IP(src="192.168.0.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
        Ether() / IP(src="10.0.0.1", dst="192.168.0.1") / TCP(sport=80, dport=12345),
    ]


def test_valid_pcap_reads_packets(tmp_path, benign_packets):
    path = tmp_path / "benign.pcap"
    _write_pcap(path, benign_packets)
    assert validate_pcap_path(path) == path
    packets = list(read_packets(path))
    assert len(packets) == 3


def test_missing_file_raises(tmp_path):
    with pytest.raises(PcapInputError, match="not found"):
        validate_pcap_path(tmp_path / "missing.pcap")


def test_invalid_extension_raises(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_bytes(b"hello")
    with pytest.raises(PcapInputError, match="extension"):
        validate_pcap_path(f)


def test_empty_file_raises(tmp_path):
    f = tmp_path / "empty.pcap"
    f.write_bytes(b"")
    with pytest.raises(PcapInputError, match="empty"):
        validate_pcap_path(f)


def test_garbage_file_raises(tmp_path):
    f = tmp_path / "garbage.pcap"
    f.write_bytes(b"this is not a capture" * 10)
    with pytest.raises(PcapInputError, match="not a readable PCAP"):
        validate_pcap_path(f)


def test_too_large_file_raises(tmp_path, benign_packets):
    path = tmp_path / "big.pcap"
    _write_pcap(path, benign_packets)
    with pytest.raises(PcapInputError, match="too large"):
        validate_pcap_path(path, max_bytes=10)


def test_truncated_capture_is_handled_gracefully(tmp_path):
    # valid global header, then a packet header promising 100 bytes but
    # only 10 bytes of data follow. scapy warns and yields the truncated
    # packet — the reader must not crash and must not execute anything.
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 0, 0, 100, 100)
    path = tmp_path / "truncated.pcap"
    path.write_bytes(header + packet_header + b"\x00" * 10)
    packets = list(read_packets(path))  # must not raise
    assert len(packets) <= 1


def test_empty_capture_yields_no_packets(tmp_path):
    path = tmp_path / "nocapture.pcap"
    _write_pcap(path, [])
    assert validate_pcap_path(path) == path
    assert list(read_packets(path)) == []
