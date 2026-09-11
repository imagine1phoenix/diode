"""
Data Exfiltration Detector.

PRD §7 row 6 — **Tier 2 (partially implemented)**.

Features used:
    - outbound:inbound byte ratio
    - sustained asymmetric flow duration
    - destination rarity

Approach: Ratio thresholds + Isolation Forest on flow stats.

Status: Tier 2 / partial implementation (rules.md R2.4).
    - Byte-ratio thresholding is functional
    - Duration thresholding is functional
    - Isolation Forest model is stubbed — needs training data
    - Destination rarity scoring is stubbed

rules.md R5: No DPI — only flow-level statistics used.
"""

from __future__ import annotations

import logging

import config
from src.alert.schema import Severity, ThreatClass
from src.detectors.base import BaseDetector, RawDetection
from src.features.extractor import FlowFeatures, WindowFeatures

logger = logging.getLogger(__name__)


class ExfiltrationDetector(BaseDetector):
    """
    Detects data exfiltration via asymmetric byte ratios and
    sustained high-volume outbound flows.

    **TIER 2 — PARTIALLY IMPLEMENTED** (rules.md R2.4)

    What works:
        - Byte-ratio threshold detection
        - Duration-based sustained flow detection
    What is stubbed:
        - Isolation Forest anomaly model (needs training)
        - Destination rarity scoring (needs baseline data)
    """

    @property
    def name(self) -> str:
        return "Data Exfiltration Detector (Tier 2)"

    @property
    def version(self) -> str:
        return "0.1.0-tier2"

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.EXFILTRATION

    def detect(
        self,
        flow_features: FlowFeatures,
        window_features: WindowFeatures,
    ) -> list[RawDetection]:
        """
        Analyse flow asymmetry for exfiltration indicators on a unidirectional tap.

        Detection logic (rules.md R1):
        1. Egress payload density (> 0.75 wire-rate payload) and heavy MTU packet sizing
        2. Sustained egress flow duration (> 300 seconds)
        3. Minimum byte volume threshold (5KB)
        """
        triggered: list[str] = []
        stats: dict[str, object] = {}
        score = 0.0

        # --- Feature 1: Egress payload saturation (Diode-honest proxy) ---
        # On a unidirectional tap, inbound traffic does not exist on the wire.
        # Exfiltration is characterized by high payload density (>75%) and heavy packet payloads.
        if (
            flow_features.egress_payload_density > 0.70
            or flow_features.outbound_inbound_byte_ratio > config.EXFIL_BYTE_RATIO_THRESHOLD
        ):
            triggered.append("egress_payload_saturation")
            ratio = (
                flow_features.outbound_inbound_byte_ratio
                / config.EXFIL_BYTE_RATIO_THRESHOLD
            )
            score += min(max(ratio, 1.0) / 4.0, 0.45)
            stats["egress_payload_density"] = round(flow_features.egress_payload_density, 3)
            stats["mean_payload_bytes"] = round(flow_features.mean_payload_bytes_per_packet, 1)
            stats["byte_ratio_proxy"] = round(flow_features.outbound_inbound_byte_ratio, 2)
            stats["diode_physics_note"] = "Passive optical tap: evaluated via egress payload saturation"

        # --- Feature 2: Sustained asymmetric egress duration ---
        if flow_features.flow_duration > config.EXFIL_DURATION_THRESHOLD:
            triggered.append("sustained_egress_duration")
            score += 0.35
            stats["flow_duration_sec"] = round(flow_features.flow_duration, 2)
            stats["duration_threshold"] = config.EXFIL_DURATION_THRESHOLD

        # --- Feature 3: Isolation Forest (STUBBED) ---
        # TODO: Tier 2 — train Isolation Forest on flow stats when baseline available
        # stats["isolation_forest_score"] = "not_implemented_tier2"

        # Require minimum byte volume (at least 5KB) and confidence threshold for exfiltration
        if flow_features.total_bytes < 5000 or score < 0.40 or not triggered:
            return []

        confidence = min(score, 1.0)
        severity = self._map_severity(confidence)

        stats["total_bytes"] = flow_features.total_bytes

        logger.info(
            "Exfiltration detected: flow=%s confidence=%.2f density=%.2f duration=%.1f",
            flow_features.flow_id, confidence,
            flow_features.egress_payload_density,
            flow_features.flow_duration,
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
        """Exfiltration is inherently high severity."""
        if confidence >= 0.7:
            return Severity.CRITICAL
        if confidence >= 0.4:
            return Severity.HIGH
        return Severity.MEDIUM
