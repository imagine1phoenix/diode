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
        Analyse flow asymmetry for exfiltration indicators.

        Detection logic:
        1. Check outbound:inbound byte ratio (high = suspicious)
        2. Check sustained flow duration (long + asymmetric = exfil)
        3. Isolation Forest scoring (STUBBED)
        """
        triggered: list[str] = []
        stats: dict[str, object] = {}
        score = 0.0

        # --- Feature 1: Outbound/inbound byte ratio ---
        if flow_features.outbound_inbound_byte_ratio > config.EXFIL_BYTE_RATIO_THRESHOLD:
            triggered.append("outbound_inbound_byte_ratio")
            ratio = (
                flow_features.outbound_inbound_byte_ratio
                / config.EXFIL_BYTE_RATIO_THRESHOLD
            )
            score += min(ratio / 5.0, 0.4)
            stats["byte_ratio"] = round(
                flow_features.outbound_inbound_byte_ratio, 2
            )
            stats["byte_ratio_threshold"] = config.EXFIL_BYTE_RATIO_THRESHOLD

        # --- Feature 2: Sustained asymmetric flow duration ---
        if flow_features.flow_duration > config.EXFIL_DURATION_THRESHOLD:
            triggered.append("sustained_asymmetric_duration")
            score += 0.3
            stats["flow_duration_sec"] = round(flow_features.flow_duration, 2)
            stats["duration_threshold"] = config.EXFIL_DURATION_THRESHOLD

        # --- Feature 3: Isolation Forest (STUBBED) ---
        # TODO: Tier 2 — train Isolation Forest on flow stats when baseline available
        # stats["isolation_forest_score"] = "not_implemented_tier2"

        # --- Feature 4: Destination rarity (STUBBED) ---
        # TODO: Tier 2 — build destination frequency baseline for rarity scoring
        # stats["destination_rarity"] = "not_implemented_tier2"

        if not triggered:
            return []

        confidence = min(score, 1.0)
        severity = self._map_severity(confidence)

        stats["total_bytes"] = flow_features.total_bytes

        logger.info(
            "Exfiltration detected: flow=%s confidence=%.2f ratio=%.2f duration=%.1f",
            flow_features.flow_id, confidence,
            flow_features.outbound_inbound_byte_ratio,
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
