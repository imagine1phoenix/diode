"""
Base Detector — Abstract interface for all threat detectors.

rules.md R6.4: All detectors output RawDetection objects that the
Alert Normalizer converts to standardized Alerts. Detectors do NOT
write directly to the store.

rules.md R5: Each detector must use exactly the features and approach
specified in PRD §7.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from src.alert.schema import Severity, ThreatClass
from src.features.extractor import FlowFeatures, WindowFeatures


@dataclass
class RawDetection:
    """
    Raw detection output from a detector, before normalization.

    This is NOT the final Alert — the normalizer converts it into the
    standardized Alert schema (PRD §6).
    """

    flow_id: str
    threat_class: ThreatClass
    confidence: float  # [0.0, 1.0]
    severity: Severity
    features_triggered: list[str] = field(default_factory=list)
    supporting_stats: dict[str, Any] = field(default_factory=dict)
    detector_version: str = "0.1.0"


class BaseDetector(abc.ABC):
    """
    Abstract base class for all threat detectors.

    Every detector must implement:
      - detect(): analyse flow and window features, return detections
      - name: human-readable detector name
      - version: semver string

    Docstring requirement (rules.md R8.3): every subclass must document
    which features it uses, what thresholds/model it applies, and what
    evidence it populates.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable detector name."""
        ...

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Semver string for detector_version field (R4.8)."""
        ...

    @property
    @abc.abstractmethod
    def threat_class(self) -> ThreatClass:
        """The threat class this detector handles (R2.3)."""
        ...

    @abc.abstractmethod
    def detect(
        self,
        flow_features: FlowFeatures,
        window_features: WindowFeatures,
    ) -> list[RawDetection]:
        """
        Run detection on a single flow's features with window context.

        Args:
            flow_features: Per-flow features for the flow being analyzed.
            window_features: Aggregate window features for context.

        Returns:
            List of RawDetection objects. Empty list = no threat detected.
        """
        ...

    def _make_detection(
        self,
        flow_id: str,
        confidence: float,
        severity: Severity,
        features_triggered: list[str],
        supporting_stats: dict[str, Any],
    ) -> RawDetection:
        """Helper to build a RawDetection with this detector's metadata."""
        return RawDetection(
            flow_id=flow_id,
            threat_class=self.threat_class,
            confidence=min(max(confidence, 0.0), 1.0),
            severity=severity,
            features_triggered=features_triggered,
            supporting_stats=supporting_stats,
            detector_version=self.version,
        )
