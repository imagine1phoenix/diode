"""
Unit Tests for Enclave Reset functionality.
Tests:
- AlertStore.clear()
- ThroughputCounter.reset() & Pipeline.reset()
- AlertDispatcher.clear_logs()
- POST /api/reset endpoint with 'empty' and 'baseline' modes
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from src.alert.dispatcher import AlertDispatcher
from src.alert.schema import Alert, Evidence, Severity, ThreatClass
from src.alert.store import AlertStore
from src.pipeline.runner import Pipeline, ThroughputCounter
from src.api.main import app


class TestEnclaveReset(unittest.TestCase):
    """Test suite for enclave reset operations."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_alerts.db"
        self.store = AlertStore(self.db_path)

        # Seed sample alert
        sample_alert = Alert(
            alert_id="reset-test-01",
            timestamp="2026-09-12T03:00:00Z",
            flow_id="192.168.1.50:1234-10.0.0.1:80-tcp",
            threat_class=ThreatClass.DDOS,
            confidence=0.95,
            severity=Severity.CRITICAL,
            evidence=Evidence(
                features_triggered=["high_flow_rate"],
                supporting_stats={"flow_rate": 1200},
            ),
            detector_version="1.0.0",
        )
        self.store.save(sample_alert)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_alert_store_clear(self):
        """AlertStore.clear() should delete all alerts and return count."""
        initial_stats = self.store.get_stats()
        self.assertGreaterEqual(initial_stats["total_alerts"], 1)

        deleted = self.store.clear()
        self.assertGreaterEqual(deleted, 1)

        after_stats = self.store.get_stats()
        self.assertEqual(after_stats["total_alerts"], 0)
        self.assertEqual(len(self.store.get_recent(50)), 0)

    def test_throughput_counter_reset(self):
        """ThroughputCounter.reset() should reset processed counts."""
        counter = ThroughputCounter()
        counter.start()
        counter.record_flows(150)
        counter.record_alerts(5)

        report = counter.report()
        self.assertEqual(report["flows_processed"], 150)
        self.assertEqual(report["alerts_generated"], 5)

        counter.reset()
        clean_report = counter.report()
        self.assertEqual(clean_report["flows_processed"], 0)
        self.assertEqual(clean_report["alerts_generated"], 0)
        self.assertEqual(clean_report["flows_per_sec"], 0.0)

    def test_pipeline_reset(self):
        """Pipeline.reset() resets throughput counter."""
        pipeline = Pipeline(store=self.store)
        pipeline.throughput.start()
        pipeline.throughput.record_flows(50)
        self.assertEqual(pipeline.throughput.flows_processed, 50)

        pipeline.reset()
        self.assertEqual(pipeline.throughput.flows_processed, 0)

    def test_dispatcher_clear_logs(self):
        """AlertDispatcher.clear_logs() should clear logs and cooldown cache."""
        dispatcher = AlertDispatcher()
        dispatcher._dispatch_logs.append({"test": "log_entry"})
        dispatcher._cooldown_cache["test_key"] = 12345.0

        self.assertEqual(len(dispatcher.get_logs()), 1)
        self.assertIn("test_key", dispatcher._cooldown_cache)

        dispatcher.clear_logs()
        self.assertEqual(len(dispatcher.get_logs()), 0)
        self.assertNotIn("test_key", dispatcher._cooldown_cache)

    def test_api_reset_endpoint_empty_mode(self):
        """POST /api/reset with mode='empty' should return 0 alerts."""
        with TestClient(app) as client:
            resp = client.post("/api/reset", json={"mode": "empty", "clear_notifications": True})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["mode"], "empty")
            self.assertEqual(data["total_alerts"], 0)

            # Check /api/alerts does not auto-seed when empty mode is active
            alerts_resp = client.get("/api/alerts")
            self.assertEqual(alerts_resp.status_code, 200)
            self.assertEqual(len(alerts_resp.json()), 0)

    def test_api_reset_endpoint_baseline_mode(self):
        """POST /api/reset with mode='baseline' should restore baseline alerts."""
        with TestClient(app) as client:
            # First reset to empty
            client.post("/api/reset", json={"mode": "empty"})

            # Now reset to baseline
            resp = client.post("/api/reset", json={"mode": "baseline", "clear_notifications": True})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["mode"], "baseline")
            self.assertGreaterEqual(data["total_alerts"], 1)

            # Check /api/alerts now returns alerts
            alerts_resp = client.get("/api/alerts")
            self.assertEqual(alerts_resp.status_code, 200)
            self.assertGreaterEqual(len(alerts_resp.json()), 1)


if __name__ == "__main__":
    unittest.main()
