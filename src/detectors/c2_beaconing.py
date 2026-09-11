"""
C2 Beaconing Detector — Command & Control communication detection.

PRD §7 row 3 — Tier 1 (must ship, demo-ready).

Features used:
    - inter_arrival_time_variance (per-flow)
    - destination_set_size (window-level)
    - periodicity (FFT or autocorrelation on timestamps) (per-flow)

Approach: Periodicity/regularity scoring.
    Detects regular check-in patterns characteristic of botnet C2 channels.

Evidence populated:
    - features_triggered: which periodicity metrics were anomalous
    - supporting_stats: variance values, periodicity scores, destination counts

Known false-positive scenarios (R8.4):
    - NTP clients with regular sync intervals
    - Heartbeat/keepalive connections (e.g., database pools)
    - Scheduled cron-like HTTP polling (monitoring, RSS readers)

rules.md R5: No DNS-based detection here — that belongs to DGA detector.
"""

from __future__ import annotations

import logging

import config
from src.alert.schema import Severity, ThreatClass
from src.detectors.base import BaseDetector, RawDetection
from src.features.extractor import FlowFeatures, WindowFeatures

logger = logging.getLogger(__name__)


class C2BeaconingDetector(BaseDetector):
    """
    Detects C2 beaconing by analysing the regularity of connection
    timing patterns using FFT/autocorrelation periodicity scoring.
    """

    @property
    def name(self) -> str:
        return "C2 Beaconing Detector"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.C2_BEACONING

    def detect(
        self,
        flow_features: FlowFeatures,
        window_features: WindowFeatures,
    ) -> list[RawDetection]:
        """
        Analyse timing regularity for C2 beaconing indicators.

        Detection logic:
        1. Check periodicity score from FFT/autocorrelation
        2. Check inter-arrival time variance (low variance = regular)
        3. Check coefficient of variation (low CV = beaconing)
        4. Check destination set size (C2 typically talks to few servers)
        5. Require minimum number of connections for statistical validity
        """
        triggered: list[str] = []
        stats: dict[str, object] = {}
        score = 0.0

        # Need minimum connections for meaningful periodicity analysis
        if flow_features.packet_count < config.C2_MIN_CONNECTIONS:
            return []

        # --- Feature 1: Periodicity score (FFT/autocorrelation) ---
        if flow_features.periodicity_score_value > config.C2_PERIODICITY_THRESHOLD:
            triggered.append("periodicity_score")
            # Strong periodicity → higher score
            excess = (
                flow_features.periodicity_score_value - config.C2_PERIODICITY_THRESHOLD
            )
            normalized = excess / (1.0 - config.C2_PERIODICITY_THRESHOLD)
            score += min(normalized * 0.4, 0.4)
            stats["periodicity_score"] = round(
                flow_features.periodicity_score_value, 4
            )
            stats["periodicity_threshold"] = config.C2_PERIODICITY_THRESHOLD

        # --- Feature 2: Inter-arrival time variance ---
        # Low variance indicates regular timing → beaconing
        if flow_features.inter_arrival_cv < config.C2_LOW_JITTER_THRESHOLD:
            triggered.append("inter_arrival_time_variance")
            score += 0.3
            stats["inter_arrival_variance"] = round(
                flow_features.inter_arrival_time_variance, 6
            )
            stats["coefficient_of_variation"] = round(
                flow_features.inter_arrival_cv, 4
            )
            stats["jitter_threshold"] = config.C2_LOW_JITTER_THRESHOLD

        # --- Feature 3: Destination set size (window-level) ---
        # C2 typically contacts very few unique servers
        src_ip = flow_features.src_ip
        destinations = window_features.destinations_per_src.get(src_ip, set())
        dest_count = len(destinations)

        if dest_count <= 3 and dest_count > 0:
            # Few unique destinations combined with periodic timing → C2
            if triggered:  # Only counts if already showing periodicity
                triggered.append("low_destination_set_size")
                score += 0.2
                stats["destination_set_size"] = dest_count

        # --- Emit detection if features triggered ---
        if not triggered:
            return []

        confidence = min(score, 1.0)
        severity = self._map_severity(confidence)

        stats["packet_count"] = flow_features.packet_count
        stats["flow_duration_sec"] = round(flow_features.flow_duration, 2)

        logger.info(
            "C2 beaconing detected: flow=%s confidence=%.2f periodicity=%.3f cv=%.4f",
            flow_features.flow_id, confidence,
            flow_features.periodicity_score_value,
            flow_features.inter_arrival_cv,
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
        """Map confidence to severity. C2 is inherently high-severity."""
        if confidence >= 0.7:
            return Severity.CRITICAL
        if confidence >= 0.5:
            return Severity.HIGH
        if confidence >= 0.3:
            return Severity.MEDIUM
        return Severity.LOW
