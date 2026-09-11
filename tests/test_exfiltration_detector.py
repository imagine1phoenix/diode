"""
Unit tests for ExfiltrationDetector & Isolation Forest Model.

Verifies:
1. Isolation Forest model loads and executes inference on flow vectors.
2. Honest field naming: mean_payload_bytes_proxy and outbound_inbound_byte_ratio.
3. High payload density and bulk exfiltration trigger exfiltration alerts with supporting stats.
4. Benign flows are rejected.
"""

from __future__ import annotations

import unittest
from src.detectors.exfiltration import ExfiltrationDetector
from src.features.extractor import FlowFeatures, WindowFeatures
from src.alert.schema import ThreatClass, Severity


class TestExfiltrationDetector(unittest.TestCase):
    def setUp(self):
        self.detector = ExfiltrationDetector()

    def test_model_loaded(self):
        """Confirm that the trained Isolation Forest artifact is loaded."""
        self.assertIsNotNone(
            self.detector.iforest_model,
            "Isolation Forest model artifact models/isolation_forest_exfil.joblib should be loaded",
        )

    def test_exfiltration_bulk_flow_triggers(self):
        """A bulk exfiltration flow must trigger detection with isolation forest anomaly."""
        # Simulated 500KB exfil: 400 packets, ~1250 bytes payload per packet, 320s duration
        ff = FlowFeatures(
            flow_id="192.168.1.50:48920-198.51.100.50:8443-tcp",
            src_ip="192.168.1.50",
            dst_ip="198.51.100.50",
            src_port=48920,
            dst_port=8443,
            proto="tcp",
            total_bytes=520000,
            packet_count=400,
            flow_duration=320.0,
            egress_payload_density=0.92,
            mean_payload_bytes_proxy=1250.0,
            outbound_inbound_byte_ratio=55.0,
        )
        wf = WindowFeatures()

        detections = self.detector.detect(ff, wf)
        self.assertEqual(len(detections), 1, "Exfiltration flow should produce 1 detection")
        d = detections[0]

        self.assertEqual(d.threat_class, ThreatClass.EXFILTRATION)
        self.assertIn(d.severity, [Severity.HIGH, Severity.CRITICAL])
        self.assertIn("egress_payload_saturation", d.features_triggered)
        self.assertIn("sustained_egress_duration", d.features_triggered)
        self.assertIn("isolation_forest_anomaly", d.features_triggered)

        # Honest evidence stats verification
        stats = d.supporting_stats
        self.assertIn("mean_payload_bytes_proxy", stats)
        self.assertIn("outbound_inbound_byte_ratio", stats)
        self.assertIn("egress_payload_density", stats)
        self.assertIn("isolation_forest_decision_score", stats)
        self.assertTrue(stats["isolation_forest_anomaly"])
        self.assertEqual(stats["mean_payload_bytes_proxy"], 1250.0)
        self.assertEqual(stats["outbound_inbound_byte_ratio"], 55.0)

    def test_benign_web_flow_rejected(self):
        """A normal short web browsing flow must NOT trigger exfiltration."""
        ff = FlowFeatures(
            flow_id="192.168.1.20:51234-93.184.216.34:443-tcp",
            src_ip="192.168.1.20",
            dst_ip="93.184.216.34",
            src_port=51234,
            dst_port=443,
            proto="tcp",
            total_bytes=3200,
            packet_count=12,
            flow_duration=1.8,
            egress_payload_density=0.22,
            mean_payload_bytes_proxy=110.0,
            outbound_inbound_byte_ratio=0.15,
        )
        wf = WindowFeatures()

        detections = self.detector.detect(ff, wf)
        self.assertEqual(len(detections), 0, "Benign web flow should not trigger exfiltration")


if __name__ == "__main__":
    unittest.main()
