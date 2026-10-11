"""SentinelAI — safe PCAP reading (Part 10).

Defensive analysis of LOCAL, explicitly authorized PCAP files only.
Security rules enforced here:

  * packet data is treated strictly as untrusted input,
  * nothing contained in packets is ever executed,
  * packet payloads are never logged or stored,
  * PCAP contents are never sent to external services.

Packets are read in a STREAMING fashion, so large captures are not
loaded into memory at once.
"""

from __future__ import annotations

from pathlib import Path

from scapy.utils import PcapNgReader, PcapReader

MAX_PCAP_BYTES = 200 * 1024 * 1024  # reject larger captures (configurable here)
SUPPORTED_EXTENSIONS = (".pcap", ".pcapng")

# classic + nanosecond magic numbers, both endiannesses
_PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0b\x0a"


class PcapInputError(ValueError):
    """Raised when a PCAP input is missing, unreadable, or malformed."""


def _first_bytes(path: Path, n: int = 4) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def validate_pcap_path(path: str | Path, *, max_bytes: int = MAX_PCAP_BYTES) -> Path:
    """Validate a local PCAP input path; raises PcapInputError otherwise.

    Checks: exists, is a file, supported extension, readable format
    (magic bytes), non-empty, and a reasonable file size.
    """
    p = Path(path)
    if not p.exists():
        raise PcapInputError(f"PCAP file not found: {p}")
    if not p.is_file():
        raise PcapInputError(f"Path is not a file: {p}")
    if p.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise PcapInputError(
            f"Unsupported file extension: {p.suffix} (expected {SUPPORTED_EXTENSIONS})"
        )
    size = p.stat().st_size
    if size == 0:
        raise PcapInputError(f"PCAP file is empty: {p}")
    if size > max_bytes:
        raise PcapInputError(f"PCAP file is too large: {size} bytes (limit {max_bytes} bytes)")
    magic = _first_bytes(p)
    if not any(magic.startswith(m) for m in _PCAP_MAGICS) and not magic.startswith(_PCAPNG_MAGIC):
        raise PcapInputError(f"File is not a readable PCAP capture: {p}")
    return p


def read_packets(path: str | Path, *, max_bytes: int = MAX_PCAP_BYTES):
    """Yield packets from a validated PCAP file (streaming).

    Raises PcapInputError with context when the capture is malformed
    mid-file. Nothing from the packets is logged or executed.
    """
    path = validate_pcap_path(path, max_bytes=max_bytes)
    is_pcapng = _first_bytes(path).startswith(_PCAPNG_MAGIC)
    reader_cls = PcapNgReader if is_pcapng else PcapReader
    count = 0
    try:
        with reader_cls(str(path)) as reader:
            for packet in reader:
                count += 1
                yield packet
    except PcapInputError:
        raise
    except Exception as exc:
        raise PcapInputError(
            f"Failed while parsing {path} (after {count} packet(s)): {exc}"
        ) from exc
