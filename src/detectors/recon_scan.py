"""
Reconnaissance / Port Scan Detector.

PRD §7 row 2 — Tier 1 (must ship, demo-ready).

Features used:
    - distinct_dst_ports_per_src in window (window-level)
    - distinct_dst_hosts_per_src in window (window-level)
    - bytes_per_flow (per-flow, low bytes = probe)

Approach: Fan-out counting + threshold.
    Rule-based, no ML needed. Fast and reliable.

Evidence populated:
    - features_triggered: which fan-out thresholds were exceeded
    - supporting_stats: actual counts, port/host lists, byte volumes

Known false-positive scenarios (R8.4):
    - Service discovery tools (e.g., Consul, mDNS) touching many ports
    - CDN edge nodes reaching many backend hosts
    - Monitoring systems polling multiple endpoints
"""

from __future__ import annotations

import logging

import config
from src.alert.schema import Severity, ThreatClass
from src.detectors.base import BaseDetector, RawDetection
from src.features.extractor import FlowFeatures, WindowFeatures

logger = logging.getLogger(__name__)


class ReconScanDetector(BaseDetector):
    """
    Detects port scanning and host reconnaissance using fan-out
    counting and low-byte thresholds.

    Two scan types detected:
    1. Horizontal scan: one source → many destination ports on one host
    2. Vertical scan: one source → one port across many hosts
    """

    @property
    def name(self) -> str:
        return "Reconnaissance / Port Scan Detector"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.RECON_SCAN

    def detect(
        self,
        flow_features: FlowFeatures,
        window_features: WindowFeatures,
    ) -> list[RawDetection]:
        """
        Analyse fan-out patterns for scan indicators.

        Detection logic:
        1. Count distinct destination ports this source has contacted (window)
        2. Count distinct destination hosts this source has contacted (window)
        3. Check if per-flow byte volume is low (probe-like behavior)
        4. Score based on fan-out magnitude and low-byte correlation
        """
        src_ip = flow_features.src_ip
        triggered: list[str] = []
        stats: dict[str, object] = {}
        score = 0.0

        # --- Feature 1: Distinct destination ports per source (window) ---
        dst_ports = window_features.dst_ports_per_src.get(src_ip, set())
        num_dst_ports = len(dst_ports)

        if num_dst_ports > config.RECON_DST_PORTS_THRESHOLD:
            triggered.append("distinct_dst_ports_per_src")
            # Score proportional to fan-out
            ratio = num_dst_ports / config.RECON_DST_PORTS_THRESHOLD
            score += min(ratio / 5.0, 0.4)
            stats["distinct_dst_ports"] = num_dst_ports
            stats["dst_ports_threshold"] = config.RECON_DST_PORTS_THRESHOLD
            stats["scan_type"] = "horizontal_port_scan"

        # --- Feature 2: Distinct destination hosts per source (window) ---
        dst_hosts = window_features.dst_hosts_per_src.get(src_ip, set())
        num_dst_hosts = len(dst_hosts)

        if num_dst_hosts > config.RECON_DST_HOSTS_THRESHOLD:
            triggered.append("distinct_dst_hosts_per_src")
            ratio = num_dst_hosts / config.RECON_DST_HOSTS_THRESHOLD
            score += min(ratio / 5.0, 0.4)
            stats["distinct_dst_hosts"] = num_dst_hosts
            stats["dst_hosts_threshold"] = config.RECON_DST_HOSTS_THRESHOLD
            if "scan_type" in stats:
                stats["scan_type"] = "combined_scan"
            else:
                stats["scan_type"] = "vertical_host_sweep"

        # --- Feature 3: Low bytes per flow (per-flow) ---
        if (
            flow_features.bytes_per_flow < config.RECON_LOW_BYTES_THRESHOLD
            and flow_features.bytes_per_flow > 0
        ):
            triggered.append("low_bytes_per_flow")
            score += 0.2
            stats["bytes_per_flow"] = round(flow_features.bytes_per_flow, 2)
            stats["low_bytes_threshold"] = config.RECON_LOW_BYTES_THRESHOLD

        # --- Emit detection if any features triggered ---
        if not triggered:
            return []

        confidence = min(score, 1.0)
        severity = self._map_severity(confidence)

        stats["source_ip"] = src_ip

        logger.info(
            "Recon scan detected: src=%s confidence=%.2f triggered=%s",
            src_ip, confidence, triggered,
        )

        return [
            self._make_detection(
                flow_id=flow_features.flow_id,
                confidence=confidence,
                severity=severity,
                features_triggered=triggered,
                supporting_stats=stats,
            )
        ]

    @staticmethod
    def _map_severity(confidence: float) -> Severity:
        """Map confidence score to severity level."""
        if confidence >= 0.8:
            return Severity.HIGH
        if confidence >= 0.5:
            return Severity.MEDIUM
        return Severity.LOW
