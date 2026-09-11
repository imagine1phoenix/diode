"""
Alert Normalizer — Converts RawDetection objects to standardized Alerts.

rules.md R6.4: All detectors output through a single Alert Schema Normalizer.
Detectors do NOT write directly to the store.

rules.md R4: Every alert is validated against the Pydantic schema before emission.
"""

from __future__ import annotations

import logging
from typing import Any

from src.alert.schema import Alert, Evidence, Severity, ThreatClass
from src.detectors.base import RawDetection

logger = logging.getLogger(__name__)


def normalize(raw_detections: list[RawDetection]) -> list[Alert]:
    """
    Convert a list of RawDetection objects into standardized Alert objects.

    Each RawDetection is validated and transformed into the PRD §6 schema.
    Invalid detections are logged and skipped (never silently dropped).

    Args:
        raw_detections: List of raw detection outputs from detectors.

    Returns:
        List of validated Alert objects.
    """
    alerts: list[Alert] = []

    for raw in raw_detections:
        try:
            alert = _raw_to_alert(raw)
            alerts.append(alert)
        except Exception as e:
            logger.error(
                "Failed to normalize detection for flow=%s threat=%s: %s",
                raw.flow_id, raw.threat_class, e,
            )

    return alerts


def _raw_to_alert(raw: RawDetection) -> Alert:
    """
    Transform a single RawDetection into a validated Alert.

    The Pydantic model handles:
        - UUID generation (R4.1)
        - ISO8601 timestamp (R4.2)
        - flow_id format validation (R4.3)
        - threat_class enum validation (R4.4)
        - confidence range clamping (R4.5)
        - severity enum validation (R4.6)
        - evidence non-empty validation (R4.7)
        - extra field rejection (R4.9)
    """
    evidence = Evidence(
        features_triggered=raw.features_triggered,
        supporting_stats=raw.supporting_stats,
    )

    alert = Alert(
        flow_id=raw.flow_id,
        threat_class=raw.threat_class,
        confidence=raw.confidence,
        severity=raw.severity,
        evidence=evidence,
        detector_version=raw.detector_version,
    )

    return alert
