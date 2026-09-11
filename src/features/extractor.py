"""
Feature Extractor — Computes all PRD §7 features from FlowRecords.

This module is the bridge between raw flows (from ingest) and detectors.
It computes ALL features specified in PRD §7 in a single pass, grouped by
threat class but returned as a unified FlowFeatures dataclass.

rules.md R5: Features match PRD §7 exactly — no invented features.
rules.md R6.1: Sits between Ingest and Detectors in the pipeline.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field

import numpy as np

from src.features.entropy import (
    domain_entropy,
    ip_set_entropy,
    ngram_likelihood,
    shannon_entropy,
)
from src.features.periodicity import (
    coefficient_of_variation,
    inter_arrival_variance,
    periodicity_score,
)
from src.ingest.flow_assembler import FlowRecord

logger = logging.getLogger(__name__)


@dataclass
class FlowFeatures:
    """
    All features for a single flow, organized by threat class.
    Every field maps to a specific entry in PRD §7.
    """

    # --- Identity (from FlowRecord) ---
    flow_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    proto: str = ""

    # --- DDoS features (PRD §7 row 1) ---
    # Note: flow_rate_per_sec and source_ip_entropy are WINDOW-level features
    # computed by WindowFeatures, not per-flow.
    syn_ack_ratio: float = 0.0
    packet_size_uniformity: float = 0.0
    packet_count: int = 0
    total_bytes: int = 0

    # --- Recon / Port Scan features (PRD §7 row 2) ---
    # Note: distinct_dst_ports_per_src and distinct_dst_hosts_per_src are
    # WINDOW-level features computed by WindowFeatures.
    bytes_per_flow: float = 0.0

    # --- C2 Beaconing features (PRD §7 row 3) ---
    inter_arrival_time_variance: float = 0.0
    inter_arrival_cv: float = 0.0
    destination_set_size: int = 0  # Window-level, but also per-flow for a src
    periodicity_score_value: float = 0.0

    # --- DGA / DNS Tunnelling features (PRD §7 row 4) ---
    domain_name_entropy: float = 0.0
    ngram_likelihood_score: float = 0.0
    query_length: int = 0
    txt_null_record_ratio: float = 0.0
    has_dns: bool = False
    dns_query: str = ""

    # --- Encrypted Malware features (Tier 2, PRD §7 row 5) ---
    ja3_fingerprint: str = ""
    packet_size_sequence: list[int] = field(default_factory=list)
    timing_sequence: list[float] = field(default_factory=list)

    # --- Exfiltration features (Tier 2, PRD §7 row 6) ---
    outbound_inbound_byte_ratio: float = 0.0  # Backward-compatible proxy: average payload bytes per packet
    egress_payload_density: float = 0.0       # Ratio of payload bytes to total wire bytes [0.0, 1.0]
    mean_payload_bytes_per_packet: float = 0.0 # Average payload size per packet
    flow_duration: float = 0.0



@dataclass
class WindowFeatures:
    """
    Window-level aggregate features computed across multiple flows.
    Some PRD §7 features are inherently per-window, not per-flow.
    """

    window_start: float = 0.0
    window_end: float = 0.0
    total_flows: int = 0

    # --- DDoS window features ---
    flow_rate_per_sec: float = 0.0
    source_ip_entropy: float = 0.0

    # --- Recon window features ---
    # Maps: src_ip -> set of dst_ports seen
    dst_ports_per_src: dict[str, set[int]] = field(default_factory=dict)
    # Maps: src_ip -> set of dst_ips seen
    dst_hosts_per_src: dict[str, set[str]] = field(default_factory=dict)

    # --- C2 window features ---
    # Maps: src_ip -> set of dst_ips contacted
    destinations_per_src: dict[str, set[str]] = field(default_factory=dict)
    # Maps: (src_ip, dst_ip) -> list of start_times of flows between host pair
    host_pair_connection_times: dict[tuple[str, str], list[float]] = field(default_factory=dict)


def extract_flow_features(flow: FlowRecord) -> FlowFeatures:
    """
    Extract per-flow features from a single FlowRecord.

    Args:
        flow: A completed FlowRecord from the flow assembler.

    Returns:
        FlowFeatures with all per-flow fields populated.
    """
    features = FlowFeatures(
        flow_id=flow.flow_id,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        proto=flow.proto,
    )

    # --- DDoS per-flow features ---
    if flow.ack_count > 0:
        features.syn_ack_ratio = flow.syn_count / flow.ack_count
    elif flow.syn_count > 0:
        features.syn_ack_ratio = float(flow.syn_count)  # All SYN, no ACK

    if flow.packet_sizes:
        sizes = np.array(flow.packet_sizes, dtype=float)
        if np.mean(sizes) > 0:
            # Uniformity = 1 - (std/mean). High uniformity → uniform packet sizes
            features.packet_size_uniformity = 1.0 - min(
                float(np.std(sizes) / np.mean(sizes)), 1.0
            )
        else:
            features.packet_size_uniformity = 1.0

    features.packet_count = flow.packet_count
    features.total_bytes = flow.total_bytes

    # --- Recon per-flow features ---
    features.bytes_per_flow = float(flow.total_bytes)

    # --- C2 Beaconing per-flow features ---
    if flow.timestamps:
        features.inter_arrival_time_variance = inter_arrival_variance(flow.timestamps)
        features.inter_arrival_cv = coefficient_of_variation(flow.timestamps)
        features.periodicity_score_value = periodicity_score(flow.timestamps)
        features.timing_sequence = flow.timestamps

    # --- DGA / DNS per-flow features ---
    if flow.dns_queries:
        features.has_dns = True
        # Use the first (or most common) query for entropy analysis
        query = flow.dns_queries[0]
        features.dns_query = query
        features.domain_name_entropy = domain_entropy(query)
        features.ngram_likelihood_score = ngram_likelihood(query)
        features.query_length = len(query)

        # TXT/NULL record ratio
        if flow.dns_qtypes:
            type_counts = Counter(flow.dns_qtypes)
            special = type_counts.get("TXT", 0) + type_counts.get("NULL", 0)
            features.txt_null_record_ratio = special / len(flow.dns_qtypes)

    # --- Encrypted Malware (Tier 2) ---
    if flow.tls_ja3_fingerprints:
        features.ja3_fingerprint = flow.tls_ja3_fingerprints[0]
    features.packet_size_sequence = flow.packet_sizes

    # --- Exfiltration (Tier 2, PRD §7 row 6) ---
    # Data Diode Physical Constraint: On an optical unidirectional tap (rules.md R1),
    # return/inbound traffic physically cannot traverse the diode. Exfiltration is
    # determined via egress payload density, MTU saturation, and sustained duration.
    if flow.total_bytes > 0 and flow.payload_sizes:
        total_payload = sum(s for s in flow.payload_sizes if s > 0)
        features.egress_payload_density = total_payload / flow.total_bytes
        features.mean_payload_bytes_per_packet = total_payload / max(flow.packet_count, 1)
        features.outbound_inbound_byte_ratio = features.mean_payload_bytes_per_packet
    features.flow_duration = flow.duration


    return features


def extract_window_features(flows: list[FlowRecord]) -> WindowFeatures:
    """
    Extract window-level aggregate features across multiple flows.

    These are features from PRD §7 that are inherently per-window:
      - flow_rate_per_sec (DDoS)
      - source_ip_entropy (DDoS)
      - distinct_dst_ports_per_src (Recon)
      - distinct_dst_hosts_per_src (Recon)

    Args:
        flows: List of FlowRecords in the current analysis window.

    Returns:
        WindowFeatures with all window-level fields populated.
    """
    wf = WindowFeatures()

    if not flows:
        return wf

    wf.total_flows = len(flows)

    # Compute window time bounds
    all_starts = [f.start_time for f in flows if f.start_time > 0]
    all_ends = [f.end_time for f in flows if f.end_time > 0]
    if all_starts and all_ends:
        wf.window_start = min(all_starts)
        wf.window_end = max(all_ends)

    # --- DDoS window features ---
    window_duration = wf.window_end - wf.window_start
    if window_duration > 0:
        wf.flow_rate_per_sec = len(flows) / window_duration

    src_ips = [f.src_ip for f in flows]
    wf.source_ip_entropy = ip_set_entropy(src_ips)

    # --- Recon window features ---
    for f in flows:
        # Distinct destination ports per source
        if f.src_ip not in wf.dst_ports_per_src:
            wf.dst_ports_per_src[f.src_ip] = set()
        wf.dst_ports_per_src[f.src_ip].add(f.dst_port)

        # Distinct destination hosts per source
        if f.src_ip not in wf.dst_hosts_per_src:
            wf.dst_hosts_per_src[f.src_ip] = set()
        wf.dst_hosts_per_src[f.src_ip].add(f.dst_ip)

    # --- C2 window features ---
    for f in flows:
        if f.src_ip not in wf.destinations_per_src:
            wf.destinations_per_src[f.src_ip] = set()
        wf.destinations_per_src[f.src_ip].add(f.dst_ip)

        # Host-pair connection arrival times for multi-connection C2 beaconing
        if f.start_time > 0:
            pair = (f.src_ip, f.dst_ip)
            wf.host_pair_connection_times.setdefault(pair, []).append(f.start_time)

    return wf
