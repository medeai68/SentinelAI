"""Safety validation for the Part 10 PCAP subsystem (read-only scans).

The PCAP pipeline must remain OFFLINE and defensive: no live capture, no
network sockets, no packet injection, no shell execution, no firewall
commands, no external communication. Packet payloads are treated as
untrusted data (never executed, logged, or stored).
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.validation

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
NETWORK_DIR = PROJECT_ROOT / "src" / "network"

# APIs that would enable live capture, injection, or networking.
FORBIDDEN_LIVE_CAPTURE = [
    re.compile(r"\bsniff\s*\("),          # scapy live capture
    re.compile(r"\bAsyncSniffer\b"),
    re.compile(r"\bsendp?\s*\("),         # packet transmission
    re.compile(r"\bsr1?\s*\("),           # send/receive
    re.compile(r"\barping\s*\("),
    re.compile(r"\bL2socket\b|\bL3socket\b"),
    re.compile(r"\bsocket\b"),            # raw python sockets
    re.compile(r"^\s*(import|from)\s+subprocess\b", re.MULTILINE),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"^\s*(import|from)\s+requests\b", re.MULTILINE),
    re.compile(r"^\s*(import|from)\s+urllib\b", re.MULTILINE),
    re.compile(r"iptables|netsh|\bufw\b|firewall-cmd|pfctl"),
]


def _network_sources():
    files = sorted(NETWORK_DIR.rglob("*.py"))
    assert files, "network module not found (test broken)"
    return files


def test_no_live_capture_or_network_apis_in_pcap_subsystem():
    hits = []
    for path in _network_sources():
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_LIVE_CAPTURE:
            if pattern.search(text):
                hits.append(f"{path.name}: {pattern.pattern}")
    assert hits == [], f"live-capture/network APIs found in src/network: {hits}"


def test_reader_uses_only_file_based_scapy_readers():
    """The reader must use PcapReader/PcapNgReader (file readers) only."""
    text = (NETWORK_DIR / "pcap_reader.py").read_text(encoding="utf-8")
    assert "PcapReader" in text and "PcapNgReader" in text
    assert "sniff" not in text


def test_cli_declares_offline_and_dry_run_modes():
    """The CLI output contract must state OFFLINE analysis and DRY_RUN."""
    text = (NETWORK_DIR / "pcap_pipeline.py").read_text(encoding="utf-8")
    assert "MODE: OFFLINE" in text
    assert "RESPONSE MODE:" in text and "DEFAULT_RESPONSE_MODE" in text


def test_pcap_subsystem_reuses_part7_engine_not_a_second_implementation():
    """Detection and response must come from the existing Part 7 modules —
    no independent model or response logic may exist in src/network."""
    text = (NETWORK_DIR / "pcap_pipeline.py").read_text(encoding="utf-8")
    assert "ThreatDetector" in text          # existing detection engine
    assert "ResponseEngine" in text           # existing response engine
    assert "predict_proba" not in text        # no bespoke model calls
    assert "fit(" not in text                 # never trains/refits anything
