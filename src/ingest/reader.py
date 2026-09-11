"""
Ingest Layer — Read-only PCAP/flow reader.

PRD §5, rules.md R1: This module MUST NOT contain any outbound network calls.
No socket.connect, no requests, no urllib, no DNS resolution.
It reads from files/pipes in one direction only.

Architectural constraint verification:
    - This module imports ONLY: scapy (for pcap parsing), dataclasses, typing,
      logging, pathlib — nothing that enables outbound network writes.
    - Run tests/test_ingest_isolation.py to verify.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

from scapy.all import PcapReader as ScapyPcapReader
from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.packet import Packet

logger = logging.getLogger(__name__)


@dataclass
class RawPacket:
    """
    Parsed representation of a single packet extracted from PCAP.
    Contains only fields derivable from a one-way tap (rules.md R1).
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str  # "tcp", "udp", "icmp", "other"
    length: int
    flags: str = ""  # TCP flags string, e.g. "S", "SA", "A", "FA"
    dns_query: str = ""  # DNS query name if applicable
    dns_qtype: str = ""  # DNS query type, e.g. "A", "TXT", "NULL"
    tls_ja3: str = ""  # JA3 fingerprint from TLS ClientHello (Tier 2)
    payload_size: int = 0


def _extract_tcp_flags(tcp_layer: TCP) -> str:
    """Extract TCP flags as a human-readable string."""
    flag_map = {
        0x02: "S",   # SYN
        0x10: "A",   # ACK
        0x12: "SA",  # SYN-ACK
        0x01: "F",   # FIN
        0x04: "R",   # RST
        0x08: "P",   # PSH
        0x18: "PA",  # PSH-ACK
        0x11: "FA",  # FIN-ACK
    }
    flags_int = int(tcp_layer.flags)
    return flag_map.get(flags_int, hex(flags_int))


def _extract_dns_info(packet: Packet) -> tuple[str, str]:
    """Extract DNS query name and type if present."""
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        qr = packet[DNSQR]
        qname = qr.qname.decode("utf-8", errors="ignore").rstrip(".")
        qtype_map = {1: "A", 2: "NS", 5: "CNAME", 10: "NULL", 15: "MX",
                     16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
        qtype = qtype_map.get(qr.qtype, str(qr.qtype))
        return qname, qtype
    return "", ""


def _parse_packet(packet: Packet) -> RawPacket | None:
    """
    Parse a scapy Packet into a RawPacket.
    Returns None for non-IP packets (we only analyse IP traffic per PRD §1).
    """
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    timestamp = float(packet.time)
    src_ip = ip.src
    dst_ip = ip.dst
    length = len(packet)

    src_port = 0
    dst_port = 0
    proto = "other"
    flags = ""
    payload_size = 0

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        proto = "tcp"
        flags = _extract_tcp_flags(tcp)
        payload_size = len(tcp.payload) if tcp.payload else 0
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        proto = "udp"
        payload_size = len(udp.payload) if udp.payload else 0

    dns_query, dns_qtype = _extract_dns_info(packet)

    # TLS JA3 extraction — Tier 2 feature, best-effort
    tls_ja3 = ""
    try:
        if packet.haslayer(TLSClientHello):
            # Scapy can compute JA3 if tls module is loaded
            tls_ja3 = getattr(packet[TLSClientHello], "ja3", "")
            if callable(tls_ja3):
                tls_ja3 = tls_ja3()
            tls_ja3 = str(tls_ja3) if tls_ja3 else ""
    except Exception:
        tls_ja3 = ""

    return RawPacket(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        length=length,
        flags=flags,
        dns_query=dns_query,
        dns_qtype=dns_qtype,
        tls_ja3=tls_ja3,
        payload_size=payload_size,
    )


def read_pcap_batch(pcap_path: Path) -> list[RawPacket]:
    """
    Read an entire PCAP file into memory and return parsed packets.
    Suitable for small/medium files.

    Args:
        pcap_path: Path to a .pcap or .pcapng file.

    Returns:
        List of RawPacket objects (non-IP packets filtered out).
    """
    logger.info("Reading PCAP file (batch): %s", pcap_path)
    packets = rdpcap(str(pcap_path))
    results: list[RawPacket] = []
    for pkt in packets:
        parsed = _parse_packet(pkt)
        if parsed is not None:
            results.append(parsed)
    logger.info("Parsed %d IP packets from %s", len(results), pcap_path)
    return results


def read_pcap_stream(pcap_path: Path) -> Generator[RawPacket, None, None]:
    """
    Stream packets from a PCAP file one at a time.
    Memory-efficient for large files.

    Args:
        pcap_path: Path to a .pcap or .pcapng file.

    Yields:
        RawPacket objects (non-IP packets filtered out).
    """
    logger.info("Streaming PCAP file: %s", pcap_path)
    count = 0
    with ScapyPcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            parsed = _parse_packet(pkt)
            if parsed is not None:
                count += 1
                yield parsed
    logger.info("Streamed %d IP packets from %s", count, pcap_path)
