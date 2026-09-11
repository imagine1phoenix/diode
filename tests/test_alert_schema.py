"""
Test: Alert Schema — Validate that the Alert model enforces all PRD §6 constraints.

rules.md R4: Every field, type, and constraint must be enforced.
"""

from __future__ import annotations

import unittest

from pydantic import ValidationError

from src.alert.schema import Alert, Evidence, Severity, ThreatClass


class TestAlertSchema(unittest.TestCase):
    """Verify the Alert schema enforces PRD §6 and rules.md R4."""

    def _valid_alert_data(self) -> dict:
        """Return a minimal valid alert dict."""
        return {
            "flow_id": "192.168.1.1:12345-10.0.0.1:80-tcp",
            "threat_class": ThreatClass.DDOS,
            "confidence": 0.85,
            "severity": Severity.HIGH,
            "evidence": Evidence(
                features_triggered=["flow_rate_per_sec"],
                supporting_stats={"flow_rate": 5000.0},
            ),
            "detector_version": "0.1.0",
        }

    def test_valid_alert_creates_successfully(self):
        """A fully valid alert should pass all validators."""
        alert = Alert(**self._valid_alert_data())
        self.assertIsNotNone(alert.alert_id)  # Auto-generated UUID
        self.assertIsNotNone(alert.timestamp)  # Auto-generated timestamp

    def test_flow_id_format_validated(self):
        """flow_id must be src_ip:src_port-dst_ip:dst_port-proto (R4.3)."""
        data = self._valid_alert_data()
        data["flow_id"] = "invalid_format"
        with self.assertRaises(ValidationError):
            Alert(**data)

    def test_confidence_range(self):
        """confidence must be in [0.0, 1.0] (R4.5)."""
        data = self._valid_alert_data()

        data["confidence"] = -0.1
        with self.assertRaises(ValidationError):
            Alert(**data)

        data["confidence"] = 1.1
        with self.assertRaises(ValidationError):
            Alert(**data)

    def test_confidence_boundary_values(self):
        """confidence boundary values 0.0 and 1.0 should be accepted."""
        data = self._valid_alert_data()

        data["confidence"] = 0.0
        alert = Alert(**data)
        self.assertEqual(alert.confidence, 0.0)

        data["confidence"] = 1.0
        alert = Alert(**data)
        self.assertEqual(alert.confidence, 1.0)

    def test_invalid_threat_class_rejected(self):
        """Only the 6 defined threat classes are valid (R4.4)."""
        data = self._valid_alert_data()
        data["threat_class"] = "ransomware"
        with self.assertRaises(ValidationError):
            Alert(**data)

    def test_invalid_severity_rejected(self):
        """Only low/medium/high/critical are valid (R4.6)."""
        data = self._valid_alert_data()
        data["severity"] = "urgent"
        with self.assertRaises(ValidationError):
            Alert(**data)

    def test_empty_evidence_rejected(self):
        """Evidence must not be empty (R4.7)."""
        with self.assertRaises(ValidationError):
            Evidence(
                features_triggered=[],
                supporting_stats={"x": 1},
            )

    def test_empty_supporting_stats_rejected(self):
        """supporting_stats must not be empty (R4.7)."""
        data = self._valid_alert_data()
        with self.assertRaises(ValidationError):
            Evidence(
                features_triggered=["test"],
                supporting_stats={},
            )

    def test_extra_fields_rejected(self):
        """No extra fields allowed (R4.9)."""
        data = self._valid_alert_data()
        data["custom_field"] = "should be rejected"
        with self.assertRaises(ValidationError):
            Alert(**data)

    def test_all_six_threat_classes_exist(self):
        """Exactly 6 threat classes must exist (R2.3)."""
        self.assertEqual(len(ThreatClass), 6)
        expected = {"ddos", "c2_beaconing", "dga_dns", "encrypted_malware", "recon_scan", "exfiltration"}
        actual = {tc.value for tc in ThreatClass}
        self.assertEqual(actual, expected)

    def test_all_four_severities_exist(self):
        """Exactly 4 severity levels must exist (R4.6)."""
        self.assertEqual(len(Severity), 4)
        expected = {"low", "medium", "high", "critical"}
        actual = {s.value for s in Severity}
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
