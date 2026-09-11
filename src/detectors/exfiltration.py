"""
Data Exfiltration Detector.

PRD §7 row 6 — Production Unsupervised ML Anomaly Detection.

Features used:
    - outbound:inbound byte ratio (measured when return tap mirrored; proxy on simplex)
    - mean payload bytes proxy (honest density proxy)
    - egress payload density (payload / wire volume)
    - sustained asymmetric flow duration
    - Isolation Forest unsupervised anomaly scoring (sklearn.ensemble.IsolationForest)

Approach: Statistical thresholding + Isolation Forest on flow statistics.

rules.md R5: No DPI — only flow-level statistics used.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib

import config
from src.alert.schema import Severity, ThreatClass
from src.detectors.base import BaseDetector, RawDetection
from src.features.extractor import FlowFeatures, WindowFeatures

logger = logging.getLogger(__name__)


class ExfiltrationDetector(BaseDetector):
    """
    Detects unauthorized data exfiltration using an unsupervised Isolation Forest
    alongside directional byte ratios, payload saturation, and duration thresholding.
    """

    def __init__(self) -> None:
        super().__init__()
        self.iforest_model = None
        self.feature_fields: list[str] = [
            "egress_payload_density",
            "mean_payload_bytes_per_packet",
            "flow_duration",
            "total_bytes",
            "packet_count",
        ]
        self._load_model()

    def _load_model(self) -> None:
        """Load trained Isolation Forest model defensively."""
        model_path = config.MODELS_DIR / "exfil_isolation_forest.joblib"
        if not model_path.exists():
            fallback_path = config.MODELS_DIR / "isolation_forest_exfil.joblib"
            if fallback_path.exists():
                model_path = fallback_path

        if not model_path.exists():
            logger.warning(
                "Isolation Forest model artifact not found at %s", model_path
            )
            return

        try:
            loaded = joblib.load(model_path)
            if isinstance(loaded, dict):
                self.iforest_model = loaded.get("model")
                self.feature_fields = loaded.get("feature_fields", self.feature_fields)
            else:
                self.iforest_model = loaded
                if hasattr(loaded, "feature_fields"):
                    self.feature_fields = loaded.feature_fields
            logger.info(
                "Loaded Isolation Forest exfiltration model from %s (features: %s)",
                model_path,
                self.feature_fields,
            )
        except Exception as e:
            logger.warning("Failed to load Isolation Forest exfil model from %s: %s", model_path, e)

    @property
    def name(self) -> str:
        return "Data Exfiltration Detector (Isolation Forest)"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.EXFILTRATION

    def detect(
        self,
        flow_features: FlowFeatures,
        window_features: WindowFeatures,
    ) -> list[RawDetection]:
        """
        Analyse flow asymmetry and anomaly score for exfiltration indicators on a unidirectional tap.

        Detection pipeline:
        1. Egress payload saturation & directional byte ratio (honest proxy)
        2. Sustained egress flow duration (> 300 seconds)
        3. Unsupervised Isolation Forest anomaly scoring on flow vector
        4. Minimum byte volume threshold (5KB)
        """
        triggered: list[str] = []
        stats: dict[str, object] = {}
        score = 0.0

        # --- Feature 1: Egress payload saturation & byte asymmetry ---
        # On a unidirectional tap, inbound traffic does not exist on the monitored wire.
        # Exfiltration is characterized by high payload density (>70%) or high outbound ratio.
        is_high_density = flow_features.egress_payload_density > 0.70
        is_large_payload = flow_features.mean_payload_bytes_proxy > 800.0
        is_asymmetric_ratio = (
            flow_features.outbound_inbound_byte_ratio > config.EXFIL_BYTE_RATIO_THRESHOLD
        )

        if is_high_density or is_asymmetric_ratio or is_large_payload:
            triggered.append("egress_payload_saturation")
            ratio = (
                flow_features.outbound_inbound_byte_ratio
                / config.EXFIL_BYTE_RATIO_THRESHOLD
            )
            score += min(max(ratio, 1.0) / 4.0, 0.35)
            stats["egress_payload_density"] = round(flow_features.egress_payload_density, 3)
            stats["mean_payload_bytes_proxy"] = round(flow_features.mean_payload_bytes_proxy, 1)
            stats["outbound_inbound_byte_ratio"] = round(flow_features.outbound_inbound_byte_ratio, 2)
            stats["diode_physics_note"] = (
                "Measured via egress payload saturation; return traffic is physically absent on unidirectional tap"
            )

        # --- Feature 2: Sustained asymmetric egress duration ---
        if flow_features.flow_duration > config.EXFIL_DURATION_THRESHOLD:
            triggered.append("sustained_egress_duration")
            score += 0.30
            stats["flow_duration_sec"] = round(flow_features.flow_duration, 2)
            stats["duration_threshold"] = config.EXFIL_DURATION_THRESHOLD

        # --- Feature 3: Isolation Forest ML Inference ---
        if self.iforest_model is not None:
            # Build feature vector dynamically matching model's feature_fields
            feat_vector = []
            for f_name in self.feature_fields:
                val = getattr(flow_features, f_name, 0.0)
                if f_name == "mean_payload_bytes_per_packet" and val == 0.0:
                    val = getattr(flow_features, "mean_payload_bytes_proxy", 0.0)
                feat_vector.append(float(val))

            try:
                raw_score = float(self.iforest_model.decision_function([feat_vector])[0])
                pred = int(self.iforest_model.predict([feat_vector])[0])

                stats["isolation_forest_decision_score"] = round(raw_score, 4)
                stats["isolation_forest_anomaly"] = bool(pred == -1)
                stats["isolation_forest_model"] = "IsolationForest(n_estimators=100)"

                if pred == -1:  # Outlier / Anomaly
                    triggered.append("isolation_forest_anomaly")
                    if_confidence = min(max(-raw_score * 2.0, 0.20), 0.35)
                    score += if_confidence
            except Exception as e:
                logger.error("Isolation Forest inference error: %s", e)

        # Require minimum byte volume (at least 5KB) and confidence threshold for exfiltration
        # Ensures exfiltration requires corroborating indicators (e.g. sustained duration or heavy volume)
        # and avoids false positive floods on short benign web requests.
        if flow_features.total_bytes < 5000 or score < 0.58 or not triggered:
            return []

        confidence = min(score, 1.0)
        severity = self._map_severity(confidence)

        stats["total_bytes"] = flow_features.total_bytes

        logger.info(
            "Exfiltration detected: flow=%s confidence=%.2f density=%.2f duration=%.1f iforest_anomaly=%s",
            flow_features.flow_id, confidence,
            flow_features.egress_payload_density,
            flow_features.flow_duration,
            stats.get("isolation_forest_anomaly", False),
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
        if confidence >= 0.75:
            return Severity.CRITICAL
        if confidence >= 0.50:
            return Severity.HIGH
        return Severity.MEDIUM

