"""
Traffic Generator — Synthetic benign + attack PCAP generation.

Generates realistic network traffic for testing all 6 threat detectors.
Uses scapy to craft packets and write PCAP files.

PRD §4: hping3, Slowloris, dnscat2/iodine, iperf3, DGArchive samples.
This module provides a *software* equivalent for demo/testing purposes
when those external tools aren't available.

rules.md R7.3: Traffic generation scripts live in traffic/.
"""

from __future__ import annotations

import logging
import os
import random
import string
import sys
import time
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).parent.parent / "samples"


def _random_ip() -> str:
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_port() -> int:
    return random.randint(1024, 65535)


# =====================================================================
# Benign Traffic
# =====================================================================

def generate_benign_web(count: int = 200) -> list:
    """Generate normal HTTP/HTTPS-like web browsing flows."""
    packets = []
    base_time = time.time()

    for i in range(count):
        src_ip = f"192.168.1.{random.randint(2, 50)}"
        dst_ip = _random_ip()
        src_port = _random_port()
        dst_port = random.choice([80, 443, 8080, 8443])

        # TCP handshake + data
        t = base_time + i * random.uniform(0.01, 0.5)
        syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
        syn.time = t
        packets.append(syn)

        synack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA")
        synack.time = t + 0.02
        packets.append(synack)

        ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A")
        ack.time = t + 0.04
        packets.append(ack)

        # Data packets with varying sizes
        for j in range(random.randint(2, 8)):
            data_size = random.randint(100, 1400)
            data = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA") / Raw(load=os.urandom(data_size))
            data.time = t + 0.05 + j * random.uniform(0.01, 0.1)
            packets.append(data)

    logger.info("Generated %d benign web packets", len(packets))
    return packets


def generate_benign_dns(count: int = 100) -> list:
    """Generate normal DNS queries for legitimate domains."""
    packets = []
    base_time = time.time()

    legit_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com",
        "wikipedia.org", "twitter.com", "reddit.com", "netflix.com",
        "linkedin.com", "github.com", "stackoverflow.com", "microsoft.com",
        "apple.com", "cloudflare.com", "mail.google.com", "drive.google.com",
    ]

    for i in range(count):
        src_ip = f"192.168.1.{random.randint(2, 50)}"
        dst_ip = "8.8.8.8"
        domain = random.choice(legit_domains)

        pkt = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=_random_port(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        pkt.time = base_time + i * random.uniform(0.1, 2.0)
        packets.append(pkt)

    logger.info("Generated %d benign DNS packets", len(packets))
    return packets


# =====================================================================
# Attack Traffic — DDoS (PRD §7 row 1)
# =====================================================================

def generate_syn_flood(count: int = 500, target_ip: str = "10.0.0.1") -> list:
    """
    Generate SYN flood attack traffic.

    Characteristics:
    - Many SYN packets, very few ACKs → high SYN/ACK ratio
    - Spoofed source IPs (random) → variable source IP entropy
    - Uniform packet sizes → high packet_size_uniformity
    - High flow rate
    """
    packets = []
    base_time = time.time()

    for i in range(count):
        src_ip = _random_ip()  # Spoofed
        src_port = _random_port()
        dst_port = random.choice([80, 443, 22, 25])

        syn = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
        syn.time = base_time + i * 0.001  # Very fast rate
        packets.append(syn)

    logger.info("Generated %d SYN flood packets targeting %s", len(packets), target_ip)
    return packets


def generate_udp_amplification(count: int = 300, target_ip: str = "10.0.0.1") -> list:
    """
    Generate UDP amplification attack traffic.

    Characteristics:
    - Large UDP packets from few sources → low source entropy
    - Uniform large packet sizes
    - Very high flow rate
    """
    packets = []
    base_time = time.time()
    amplifiers = [_random_ip() for _ in range(5)]  # Few amplifier IPs

    for i in range(count):
        src_ip = random.choice(amplifiers)
        pkt = (
            IP(src=src_ip, dst=target_ip)
            / UDP(sport=53, dport=_random_port())
            / Raw(load=os.urandom(1400))  # Large uniform payload
        )
        pkt.time = base_time + i * 0.002
        packets.append(pkt)

    logger.info("Generated %d UDP amplification packets", len(packets))
    return packets


# =====================================================================
# Attack Traffic — Recon / Port Scan (PRD §7 row 2)
# =====================================================================

def generate_port_scan(target_ip: str = "10.0.0.1", port_range: int = 100) -> list:
    """
    Generate horizontal port scan (one host, many ports).

    Characteristics:
    - Single source → many destination ports
    - Very small packets (SYN only, no data)
    - Sequential or semi-sequential port pattern
    """
    packets = []
    base_time = time.time()
    src_ip = "192.168.1.100"

    for i in range(port_range):
        port = 1 + i
        syn = IP(src=src_ip, dst=target_ip) / TCP(sport=_random_port(), dport=port, flags="S")
        syn.time = base_time + i * 0.01
        packets.append(syn)

    logger.info("Generated %d port scan packets (%s → %s)", len(packets), src_ip, target_ip)
    return packets


def generate_host_sweep(subnet: str = "10.0.0", port: int = 22, count: int = 50) -> list:
    """
    Generate vertical host sweep (one port, many hosts).

    Characteristics:
    - Single source → many destination hosts
    - One destination port
    - Small SYN packets
    """
    packets = []
    base_time = time.time()
    src_ip = "192.168.1.100"

    for i in range(count):
        dst_ip = f"{subnet}.{i + 1}"
        syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=_random_port(), dport=port, flags="S")
        syn.time = base_time + i * 0.02
        packets.append(syn)

    logger.info("Generated %d host sweep packets on port %d", len(packets), port)
    return packets


# =====================================================================
# Attack Traffic — C2 Beaconing (PRD §7 row 3)
# =====================================================================

def generate_c2_beaconing(
    beacon_interval: float = 60.0,
    jitter: float = 0.05,
    beacon_count: int = 30,
    c2_server: str = "203.0.113.42",
) -> list:
    """
    Generate C2 beaconing traffic with periodic check-ins.

    Characteristics:
    - Regular inter-arrival times → low variance, high periodicity
    - Few destination IPs (C2 server)
    - Small packets (status check-in)
    - Low jitter
    """
    packets = []
    base_time = time.time()
    src_ip = "192.168.1.30"

    for i in range(beacon_count):
        # Add small jitter to the interval
        actual_interval = beacon_interval * (1 + random.uniform(-jitter, jitter))
        t = base_time + i * actual_interval

        # Outbound beacon (small data)
        pkt = (
            IP(src=src_ip, dst=c2_server)
            / TCP(sport=_random_port(), dport=443, flags="PA")
            / Raw(load=os.urandom(random.randint(40, 120)))
        )
        pkt.time = t
        packets.append(pkt)

    logger.info(
        "Generated %d C2 beaconing packets (interval=%.1fs, jitter=%.1f%%)",
        len(packets), beacon_interval, jitter * 100,
    )
    return packets


# =====================================================================
# Attack Traffic — DGA / DNS Tunnelling (PRD §7 row 4)
# =====================================================================

def _generate_dga_domain() -> str:
    """Generate a random DGA-like domain name with high entropy."""
    length = random.randint(12, 25)
    chars = string.ascii_lowercase + string.digits
    name = "".join(random.choice(chars) for _ in range(length))
    tld = random.choice([".com", ".net", ".org", ".info", ".xyz", ".top"])
    return name + tld


def generate_dga_dns(count: int = 80) -> list:
    """
    Generate DGA-style DNS queries.

    Characteristics:
    - High entropy domain names (random characters)
    - Low n-gram likelihood (not English-like)
    - Many unique domains queried
    """
    packets = []
    base_time = time.time()
    src_ip = "192.168.1.40"

    for i in range(count):
        domain = _generate_dga_domain()
        pkt = (
            IP(src=src_ip, dst="8.8.8.8")
            / UDP(sport=_random_port(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        pkt.time = base_time + i * random.uniform(0.5, 3.0)
        packets.append(pkt)

    logger.info("Generated %d DGA DNS queries", len(packets))
    return packets


def generate_dns_tunnel(count: int = 50) -> list:
    """
    Generate DNS tunnelling traffic.

    Characteristics:
    - Very long domain names (encoded data in subdomain)
    - TXT and NULL record queries
    - High query rate to single domain
    """
    packets = []
    base_time = time.time()
    src_ip = "192.168.1.45"
    tunnel_domain = "t.evil-tunnel.com"

    for i in range(count):
        # Encode fake data as hex in subdomain
        data = os.urandom(random.randint(20, 60)).hex()
        subdomain = f"{data}.{tunnel_domain}"
        qtype = random.choice(["TXT", "NULL", "A"])
        qtype_int = {"TXT": 16, "NULL": 10, "A": 1}[qtype]

        pkt = (
            IP(src=src_ip, dst="8.8.8.8")
            / UDP(sport=_random_port(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=subdomain, qtype=qtype_int))
        )
        pkt.time = base_time + i * random.uniform(0.1, 1.0)
        packets.append(pkt)

    logger.info("Generated %d DNS tunnel packets", len(packets))
    return packets


# =====================================================================
# Main — Generate combined PCAP
# =====================================================================

def generate_demo_pcap(output_path: Path | None = None) -> Path:
    """
    Generate a combined PCAP file with benign + all attack types.
    This is the primary demo/test dataset.
    """
    if output_path is None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = OUTPUT_DIR / "demo_traffic.pcap"

    all_packets = []

    # Benign traffic
    all_packets.extend(generate_benign_web(200))
    all_packets.extend(generate_benign_dns(100))

    # Tier 1 attacks
    all_packets.extend(generate_syn_flood(500))
    all_packets.extend(generate_udp_amplification(300))
    all_packets.extend(generate_port_scan())
    all_packets.extend(generate_host_sweep())
    all_packets.extend(generate_c2_beaconing())
    all_packets.extend(generate_dga_dns())
    all_packets.extend(generate_dns_tunnel())

    # Sort by timestamp
    all_packets.sort(key=lambda p: float(p.time))

    # Write PCAP
    wrpcap(str(output_path), all_packets)
    logger.info(
        "Demo PCAP written: %s (%d packets, %.1f KB)",
        output_path, len(all_packets), output_path.stat().st_size / 1024,
    )

    return output_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    path = generate_demo_pcap()
    print(f"\n✅ Demo PCAP generated: {path}")
    print(f"   Packets: {sum(1 for _ in open(str(path), 'rb'))}")
