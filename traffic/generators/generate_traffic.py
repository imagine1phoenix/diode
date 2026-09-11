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

def generate_syn_flood(count: int = 400, target_ip: str = "10.0.0.1", base_time: float | None = None) -> list:
    """
    Generate SYN flood attack traffic.
    Arrives rapidly within a 6-second burst to exceed window flow rate threshold.
    """
    packets = []
    t0 = base_time if base_time is not None else (time.time() - 28.0)

    for i in range(count):
        src_ip = _random_ip()  # Distributed spoofed bot sources
        src_port = _random_port()
        dst_port = random.choice([80, 443, 8080])

        syn = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
        syn.time = t0 + (i / count) * 3.0  # >100 flows/sec
        packets.append(syn)

    logger.info("Generated %d SYN flood packets targeting %s", len(packets), target_ip)
    return packets


def generate_udp_amplification(count: int = 250, target_ip: str = "10.0.0.2", base_time: float | None = None) -> list:
    """
    Generate UDP amplification attack traffic.
    """
    packets = []
    t0 = base_time if base_time is not None else (time.time() - 14.0)
    amplifiers = [_random_ip() for _ in range(4)]

    for i in range(count):
        src_ip = random.choice(amplifiers)
        pkt = (
            IP(src=src_ip, dst=target_ip)
            / UDP(sport=53, dport=_random_port())
            / Raw(load=os.urandom(1400))
        )
        pkt.time = t0 + (i / count) * 5.0
        packets.append(pkt)

    logger.info("Generated %d UDP amplification packets", len(packets))
    return packets


# =====================================================================
# Attack Traffic — Recon / Port Scan (PRD §7 row 2)
# =====================================================================

def generate_port_scan(
    target_ip: str = "10.0.0.1",
    port_range: int = 60,
    src_ip: str = "192.168.1.100",
    base_time: float | None = None,
) -> list:
    """
    Generate horizontal port scan (one host probing many ports).
    """
    packets = []
    t0 = base_time if base_time is not None else (time.time() - 160.0)

    for i in range(port_range):
        port = 1 + i * 2
        syn = IP(src=src_ip, dst=target_ip) / TCP(sport=_random_port(), dport=port, flags="S")
        syn.time = t0 + i * 0.05
        packets.append(syn)

    logger.info("Generated %d port scan packets (%s → %s)", len(packets), src_ip, target_ip)
    return packets


def generate_host_sweep(
    subnet: str = "10.0.0",
    port: int = 22,
    count: int = 35,
    src_ip: str = "192.168.1.105",
    base_time: float | None = None,
) -> list:
    """
    Generate vertical host sweep (one port scanned across many subnet hosts).
    """
    packets = []
    t0 = base_time if base_time is not None else (time.time() - 90.0)

    for i in range(count):
        dst_ip = f"{subnet}.{i + 1}"
        syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=_random_port(), dport=port, flags="S")
        syn.time = t0 + i * 0.08
        packets.append(syn)

    logger.info("Generated %d host sweep packets on port %d (%s)", len(packets), port, src_ip)
    return packets


# =====================================================================
# Attack Traffic — C2 Beaconing (PRD §7 row 3)
# =====================================================================

def generate_c2_beaconing(
    beacon_interval: float = 18.0,
    jitter: float = 0.05,
    beacon_count: int = 12,
    src_ip: str = "192.168.1.30",
    c2_server: str = "203.0.113.42",
    dport: int = 443,
    base_time: float | None = None,
) -> list:
    """
    Generate C2 beaconing traffic with periodic check-ins.
    """
    packets = []
    t0 = base_time if base_time is not None else (time.time() - 180.0)

    for i in range(beacon_count):
        actual_interval = beacon_interval * (1 + random.uniform(-jitter, jitter))
        t = t0 + i * actual_interval

        pkt = (
            IP(src=src_ip, dst=c2_server)
            / TCP(sport=_random_port(), dport=dport, flags="PA")
            / Raw(load=os.urandom(random.randint(40, 120)))
        )
        pkt.time = t
        packets.append(pkt)

    logger.info(
        "Generated %d C2 beaconing packets (%s → %s, interval=%.1fs)",
        len(packets), src_ip, c2_server, beacon_interval,
    )
    return packets


# =====================================================================
# Attack Traffic — DGA / DNS Tunnelling (PRD §7 row 4)
# =====================================================================

def _generate_dga_domain() -> str:
    """Generate a random DGA-like domain name with high entropy."""
    length = random.randint(12, 22)
    chars = string.ascii_lowercase + string.digits
    name = "".join(random.choice(chars) for _ in range(length))
    tld = random.choice([".com", ".net", ".org", ".info", ".xyz", ".top"])
    return name + tld


def generate_dga_dns(
    count: int = 6,
    src_ip: str = "192.168.1.40",
    base_time: float | None = None,
) -> list:
    """
    Generate DGA-style DNS queries for algorithmic domains.
    """
    packets = []
    t0 = base_time if base_time is not None else (time.time() - 120.0)

    for i in range(count):
        domain = _generate_dga_domain()
        pkt = (
            IP(src=src_ip, dst="8.8.8.8")
            / UDP(sport=_random_port(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        pkt.time = t0 + i * 2.5
        packets.append(pkt)

    logger.info("Generated %d DGA DNS queries for host %s", len(packets), src_ip)
    return packets


def generate_dns_tunnel(
    count: int = 12,
    src_ip: str = "192.168.1.45",
    base_time: float | None = None,
) -> list:
    """
    Generate DNS tunnelling traffic.
    """
    packets = []
    t0 = base_time if base_time is not None else (time.time() - 50.0)
    tunnel_domain = "t.evil-tunnel.com"

    for i in range(count):
        data = os.urandom(random.randint(16, 32)).hex()
        subdomain = f"{data}.{tunnel_domain}"
        qtype = random.choice(["TXT", "A"])
        qtype_int = {"TXT": 16, "A": 1}[qtype]

        pkt = (
            IP(src=src_ip, dst="8.8.8.8")
            / UDP(sport=_random_port(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=subdomain, qtype=qtype_int))
        )
        pkt.time = t0 + i * 1.5
        packets.append(pkt)

    logger.info("Generated %d DNS tunnel packets for host %s", len(packets), src_ip)
    return packets


# =====================================================================
# Attack Traffic — Data Exfiltration (PRD §7 row 6)
# =====================================================================

def generate_exfiltration(
    count: int = 120,
    src_ip: str = "192.168.1.55",
    exfil_server: str = "198.51.100.77",
    base_time: float | None = None,
) -> list:
    """
    Generate asymmetric large-volume outbound exfiltration flow.
    """
    packets = []
    t0 = base_time if base_time is not None else (time.time() - 220.0)
    sport = _random_port()
    dport = 443

    syn = IP(src=src_ip, dst=exfil_server) / TCP(sport=sport, dport=dport, flags="S")
    syn.time = t0
    packets.append(syn)

    synack = IP(src=exfil_server, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA")
    synack.time = t0 + 0.05
    packets.append(synack)

    for i in range(count):
        t = t0 + 0.1 + (i / count) * 120.0
        data = (
            IP(src=src_ip, dst=exfil_server)
            / TCP(sport=sport, dport=dport, flags="PA")
            / Raw(load=os.urandom(1400))
        )
        data.time = t
        packets.append(data)

    logger.info("Generated %d exfiltration packets (%s → %s)", len(packets), src_ip, exfil_server)
    return packets


# =====================================================================
# Attack Traffic — Encrypted Malware (PRD §7 row 5, Tier 2)
# =====================================================================

def generate_encrypted_malware(
    count: int = 25,
    src_ip: str = "192.168.1.88",
    dst_ip: str = "185.220.101.5",
    ja3_hash: str = "a0e9f5d64349fb13191bc781f81f42e1",
    base_time: float | None = None,
) -> list:
    """
    Generate TLS session matching known malicious JA3 fingerprint.
    """
    packets = []
    t0 = base_time if base_time is not None else (time.time() - 75.0)
    sport = _random_port()
    dport = 443

    # Handshake SYN
    syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S")
    syn.time = t0
    packets.append(syn)

    # Handshake SYN-ACK
    synack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA")
    synack.time = t0 + 0.02
    packets.append(synack)

    # ClientHello with JA3 signature tag in TLS record payload
    hello_payload = b"\x16\x03\x01\x00\xa0" + ja3_hash.encode("ascii") + b"\x00" * 32
    hello = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=hello_payload)
    hello.time = t0 + 0.04
    packets.append(hello)

    for i in range(count):
        data = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=os.urandom(random.randint(120, 650)))
        data.time = t0 + 0.08 + i * 0.05
        packets.append(data)

    logger.info("Generated %d encrypted malware packets (%s → %s, ja3=%s)", len(packets), src_ip, dst_ip, ja3_hash)
    return packets


# =====================================================================
# Main — Generate combined or scenario-targeted PCAP
# =====================================================================

def generate_demo_pcap(output_path: Path | None = None, scenario: str = "all") -> Path:
    """
    Generate a PCAP file containing benign background traffic plus
    targeted attack vectors according to `scenario`.

    Supported scenarios:
        - "all": Full suite covering all 6 threat classes with realistic IP diversity
        - "ddos": Volumetric SYN flood & UDP amplification
        - "recon_scan" / "scan": Port scan and horizontal host sweep
        - "c2_beaconing" / "c2": Botnet C2 periodic beaconing check-ins
        - "dga_dns" / "dga": Algorithmically generated domains & DNS tunnel
        - "exfiltration" / "exfil": Asymmetric large-payload outbound flows
        - "encrypted_malware" / "malware": TLS sessions with malicious JA3 signatures
    """
    if output_path is None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        filename = "demo_traffic.pcap" if scenario == "all" else f"simulate_{scenario}.pcap"
        output_path = OUTPUT_DIR / filename

    all_packets = []
    norm = scenario.lower().replace("-", "_").strip()
    now = time.time()

    # Always inject standard benign background traffic so baseline is realistic
    all_packets.extend(generate_benign_web(60))
    all_packets.extend(generate_benign_dns(30))

    if norm in ("all", "ddos"):
        # Volumetric SYN flood on 10.0.0.1 (Web Portal) and amplification on 10.0.0.2 (DNS Core)
        all_packets.extend(generate_syn_flood(400, target_ip="10.0.0.1", base_time=now - 28.0))
        all_packets.extend(generate_udp_amplification(250, target_ip="10.0.0.2", base_time=now - 14.0))

    if norm in ("all", "recon_scan", "scan", "recon"):
        # Multi-scanner reconnaissance across different internal subnets
        all_packets.extend(generate_port_scan(target_ip="10.0.0.1", port_range=60, src_ip="192.168.1.100", base_time=now - 160.0))
        all_packets.extend(generate_host_sweep(subnet="10.0.0", port=22, count=35, src_ip="192.168.1.105", base_time=now - 90.0))

    if norm in ("all", "c2_beaconing", "c2", "beaconing"):
        # Multiple distinct infected endpoints beaconing to external C2 nodes
        all_packets.extend(generate_c2_beaconing(
            beacon_interval=16.0, jitter=0.04, beacon_count=10,
            src_ip="192.168.1.30", c2_server="203.0.113.42", dport=443, base_time=now - 180.0
        ))
        all_packets.extend(generate_c2_beaconing(
            beacon_interval=22.0, jitter=0.06, beacon_count=8,
            src_ip="192.168.1.33", c2_server="198.51.100.19", dport=8443, base_time=now - 200.0
        ))

    if norm in ("all", "dga_dns", "dga", "dns"):
        # Varied infected hosts querying distinct algorithmic domains
        all_packets.extend(generate_dga_dns(count=5, src_ip="192.168.1.40", base_time=now - 140.0))
        all_packets.extend(generate_dga_dns(count=4, src_ip="192.168.1.44", base_time=now - 110.0))
        all_packets.extend(generate_dga_dns(count=4, src_ip="192.168.1.48", base_time=now - 75.0))
        # Covert DNS tunnel channel from host 192.168.1.45
        all_packets.extend(generate_dns_tunnel(count=12, src_ip="192.168.1.45", base_time=now - 50.0))

    if norm in ("all", "exfiltration", "exfil"):
        # Multiple exfiltration channels from database and workstation hosts
        all_packets.extend(generate_exfiltration(
            count=110, src_ip="192.168.1.55", exfil_server="198.51.100.77", base_time=now - 220.0
        ))
        all_packets.extend(generate_exfiltration(
            count=80, src_ip="192.168.1.62", exfil_server="203.0.113.99", base_time=now - 130.0
        ))

    if norm in ("all", "encrypted_malware", "malware"):
        # Encrypted sessions matching known threat actor JA3 signatures
        all_packets.extend(generate_encrypted_malware(
            count=25, src_ip="192.168.1.88", dst_ip="185.220.101.5",
            ja3_hash="a0e9f5d64349fb13191bc781f81f42e1", base_time=now - 80.0
        ))
        all_packets.extend(generate_encrypted_malware(
            count=20, src_ip="192.168.1.92", dst_ip="194.26.29.112",
            ja3_hash="6734f37431670b3ab4292b8f60f29984", base_time=now - 40.0
        ))

    # Sort packets strictly by timestamp
    all_packets.sort(key=lambda p: float(p.time))

    # Write PCAP
    wrpcap(str(output_path), all_packets)
    logger.info(
        "Simulation PCAP written [%s]: %s (%d packets, %.1f KB)",
        norm, output_path, len(all_packets), output_path.stat().st_size / 1024,
    )

    return output_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    path = generate_demo_pcap()
    print(f"\n✅ Demo PCAP generated: {path}")
    print(f"   Packets: {sum(1 for _ in open(str(path), 'rb'))}")
