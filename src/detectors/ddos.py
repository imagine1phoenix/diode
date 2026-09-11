"""
DDoS Detector — Volumetric / Protocol DDoS detection.

PRD §7 row 1 — Tier 1 (must ship, demo-ready).

Features used:
    - flow_rate_per_sec (window-level)
    - source_ip_entropy (window-level)
    - syn_ack_ratio (per-flow)
    - packet_size_uniformity (per-flow)

Approach: Statistical thresholds + entropy scoring.
    No ML required — rule-based detection is fast and explainable.

Evidence populated:
    - features_triggered: list of which thresholds were exceeded
    - supporting_stats: actual values vs thresholds

Known false-positive scenarios (R8.4):
    - Flash crowds (legitimate traffic surges) can trigger flow_rate threshold
    - Load-balancer health checks may show uniform packet sizes
    - CDN traffic may have low source-IP entropy from shared egress IPs
"""

from __future__ import annotations

import logging

import config
from src.alert.schema import Severity, ThreatClass
from src.detectors.base import BaseDetector, RawDetection
from src.features.extractor import FlowFeatures, WindowFeatures

logger = logging.getLogger(__name__)


class DDoSDetector(BaseDetector):
    """
    Detects volumetric and protocol-level DDoS attacks using
    statistical thresholds and entropy scoring.
    """

    @property
    def name(self) -> str:
        return "DDoS Detector"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.DDOS

    def detect(
        self,
        flow_features: FlowFeatures,
        window_features: WindowFeatures,
    ) -> list[RawDetection]:
        """
        Analyse flow and window features for DDoS indicators.

        Detection logic:
        1. Check window-level flow rate against threshold
        2. Check source-IP entropy for distribution anomalies
        3. Check per-flow SYN/ACK ratio for SYN floods
        4. Check packet-size uniformity for amplification attacks

        Confidence = weighted sum of triggered feature scores.
        Severity = mapped from confidence value.
        """
        triggered: list[str] = []
        stats: dict[str, object] = {}
        score = 0.0

        # --- Feature 1: Flow rate (window-level) ---
        if window_features.flow_rate_per_sec > config.DDOS_FLOW_RATE_THRESHOLD:
            triggered.append("high_flow_rate")
            # Score proportional to how much it exceeds threshold
            ratio = window_features.flow_rate_per_sec / config.DDOS_FLOW_RATE_THRESHOLD
            score += min(ratio / 5.0, 0.35)  # Max contribution: 0.35
            stats["flow_rate_per_sec"] = round(window_features.flow_rate_per_sec, 2)
            stats["flow_rate_threshold"] = config.DDOS_FLOW_RATE_THRESHOLD

        # --- Feature 2: Source-IP entropy (window-level) ---
        # Low entropy with high flow rate → fewer unique sources → DDoS pattern
        if (
            window_features.source_ip_entropy < config.DDOS_SRC_ENTROPY_LOW
            and window_features.flow_rate_per_sec > config.DDOS_FLOW_RATE_THRESHOLD * 0.5
        ):
            triggered.append("source_ip_entropy_low")
            score += 0.25
            stats["source_ip_entropy"] = round(window_features.source_ip_entropy, 4)
            stats["entropy_threshold"] = config.DDOS_SRC_ENTROPY_LOW

        # --- Feature 3: SYN/ACK ratio (per-flow) ---
        if flow_features.syn_ack_ratio > config.DDOS_SYN_ACK_RATIO_THRESHOLD:
            triggered.append("syn_ack_ratio")
            ratio = flow_features.syn_ack_ratio / config.DDOS_SYN_ACK_RATIO_THRESHOLD
            score += min(ratio / 5.0, 0.25)
            stats["syn_ack_ratio"] = round(flow_features.syn_ack_ratio, 2)
            stats["syn_ack_threshold"] = config.DDOS_SYN_ACK_RATIO_THRESHOLD

        # --- Feature 4: Packet-size uniformity (per-flow) ---
        if flow_features.packet_size_uniformity > config.DDOS_PKT_SIZE_UNIFORMITY_THRESHOLD:
            triggered.append("packet_size_uniformity")
            score += 0.15
            stats["packet_size_uniformity"] = round(
                flow_features.packet_size_uniformity, 4
            )
            stats["uniformity_threshold"] = config.DDOS_PKT_SIZE_UNIFORMITY_THRESHOLD

        # --- Require primary DDoS indicator (rate, entropy, or SYN flood) ---
        has_primary = any(t in triggered for t in ["high_flow_rate", "source_ip_entropy_low", "syn_ack_ratio"])
        if not has_primary or score < 0.40:
            return []

        confidence = min(score, 1.0)
        severity = self._map_severity(confidence)

        stats["total_packets"] = flow_features.packet_count
        stats["total_bytes"] = flow_features.total_bytes

        logger.info(
            "DDoS detected: flow=%s confidence=%.2f severity=%s triggered=%s",
            flow_features.flow_id, confidence, severity.value, triggered,
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
        """Map confidence score to standardized severity level (PRD §6)."""
        if confidence >= 0.88:
            return Severity.CRITICAL
        if confidence >= 0.72:
            return Severity.HIGH
        if confidence >= 0.55:
            return Severity.MEDIUM
        return Severity.LOW

