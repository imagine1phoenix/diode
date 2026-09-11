"""
Test: Normalizer Correlator & Flow Assembler Bounded Memory.

Verifies:
1. Confidence floor (< 0.40 suppressed).
2. DDoS window-level consolidation (many flows -> 1 victim incident alert).
3. Recon scan consolidation (many flows -> 1 scanner incident alert).
4. Point threat mutual exclusion per flow.
5. Cooldown suppression for repeated incidents.
6. FlowAssembler sample list bounding (O(1) memory per flow).
7. FlowAssembler idle flow expiration.
"""

from __future__ import annotations

import unittest
import time

from src.alert.normalizer import MIN_CONFIDENCE_THRESHOLD, normalize, reset_cooldown
from src.alert.schema import Severity, ThreatClass
from src.detectors.base import RawDetection
from src.ingest.flow_assembler import FlowAssembler, MAX_FLOW_SAMPLES
from src.ingest.reader import RawPacket


class TestNormalizerCorrelator(unittest.TestCase):
    def setUp(self):
        reset_cooldown()

    def test_confidence_floor_filtering(self):
        """Detections with confidence < 0.40 must be dropped."""
        low_raw = RawDetection(
            flow_id="192.168.1.1:1000-10.0.0.1:80-tcp",
            threat_class=ThreatClass.DDOS,
            confidence=0.35,
            severity=Severity.LOW,
            features_triggered=["high_flow_rate"],
            supporting_stats={"rate": 100},
        )
        alerts = normalize([low_raw])
        self.assertEqual(len(alerts), 0)

        high_raw = RawDetection(
            flow_id="192.168.1.1:1000-10.0.0.1:80-tcp",
            threat_class=ThreatClass.DDOS,
            confidence=0.75,
            severity=Severity.HIGH,
            features_triggered=["high_flow_rate"],
            supporting_stats={"rate": 2000},
        )
        alerts = normalize([high_raw])
        self.assertEqual(len(alerts), 1)

    def test_ddos_window_level_consolidation(self):
        """50 distinct flows targeting the same victim must emit 1 consolidated incident alert."""
        raws = []
        victim_ip = "10.0.0.5"
        for i in range(50):
            raws.append(
                RawDetection(
                    flow_id=f"192.168.1.{i}:5000-10.0.0.5:80-tcp",
                    threat_class=ThreatClass.DDOS,
                    confidence=0.80,
                    severity=Severity.HIGH,
                    features_triggered=["high_flow_rate", "syn_ack_ratio"],
                    supporting_stats={"victim_ip": victim_ip, "flow_rate": 1500.0},
                )
            )

        alerts = normalize(raws)
        # Should be exactly 1 consolidated alert for this victim, not 50 spam alerts
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.threat_class, ThreatClass.DDOS)
        self.assertEqual(alert.evidence.supporting_stats["aggregate_attacking_flows"], 50)
        self.assertEqual(alert.evidence.supporting_stats["victim_ip"], victim_ip)

    def test_recon_scan_consolidation(self):
        """100 distinct port probe flows from the same scanner must emit 1 scanner incident alert."""
        raws = []
        scanner_ip = "192.168.1.200"
        for port in range(1, 101):
            raws.append(
                RawDetection(
                    flow_id=f"{scanner_ip}:4000-10.0.0.1:{port}-tcp",
                    threat_class=ThreatClass.RECON_SCAN,
                    confidence=0.70,
                    severity=Severity.HIGH,
                    features_triggered=["distinct_dst_ports_per_src"],
                    supporting_stats={"distinct_dst_ports": 100},
                )
            )

        alerts = normalize(raws)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.threat_class, ThreatClass.RECON_SCAN)
        self.assertEqual(alert.evidence.supporting_stats["scanner_ip"], scanner_ip)
        self.assertEqual(alert.evidence.supporting_stats["probed_flows_count"], 100)

    def test_point_threat_mutual_exclusion(self):
        """Same flow triggering two point threats emits the higher-confidence dominant alert."""
        raw1 = RawDetection(
            flow_id="192.168.1.50:53-8.8.8.8:53-udp",
            threat_class=ThreatClass.DGA_DNS,
            confidence=0.85,
            severity=Severity.HIGH,
            features_triggered=["domain_name_entropy", "ngram_likelihood"],
            supporting_stats={"entropy": 4.1},
        )
        raw2 = RawDetection(
            flow_id="192.168.1.50:53-8.8.8.8:53-udp",
            threat_class=ThreatClass.C2_BEACONING,
            confidence=0.60,
            severity=Severity.MEDIUM,
            features_triggered=["inter_arrival_time_variance"],
            supporting_stats={"jitter": 0.05},
        )

        alerts = normalize([raw1, raw2])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].threat_class, ThreatClass.DGA_DNS)
        self.assertIn("correlated_signals", alerts[0].evidence.supporting_stats)

    def test_cooldown_suppression(self):
        """Repeated alert for the same entity within cooldown seconds must be suppressed."""
        import config
        config.ALERT_COOLDOWN_SECONDS = 10.0

        raw = RawDetection(
            flow_id="192.168.1.1:1000-10.0.0.1:80-tcp",
            threat_class=ThreatClass.DDOS,
            confidence=0.80,
            severity=Severity.HIGH,
            features_triggered=["high_flow_rate"],
            supporting_stats={"victim_ip": "10.0.0.1"},
        )

        # First alert emits
        alerts1 = normalize([raw], apply_cooldown=True)
        self.assertEqual(len(alerts1), 1)

        # Immediate second alert for same victim is suppressed under cooldown
        alerts2 = normalize([raw], apply_cooldown=True)
        self.assertEqual(len(alerts2), 0)


class TestFlowAssemblerMemory(unittest.TestCase):
    def test_bounded_sample_lists(self):
        """Flow sample lists must not grow beyond MAX_FLOW_SAMPLES even under 2000 packets."""
        assembler = FlowAssembler()
        base_time = 1000.0

        for i in range(2000):
            pkt = RawPacket(
                timestamp=base_time + i * 0.01,
                src_ip="192.168.1.10",
                dst_ip="10.0.0.1",
                src_port=45000,
                dst_port=80,
                proto="tcp",
                length=100,
                flags="S",
                payload_size=50,
            )
            assembler.process_packet(pkt)

        flows = assembler.flush()
        self.assertEqual(len(flows), 1)
        flow = flows[0]

        # Total counts reflect all 2,000 packets
        self.assertEqual(flow.packet_count, 2000)
        self.assertEqual(flow.total_bytes, 200000)
        self.assertEqual(flow.syn_count, 2000)

        # But memory-bound sample lists are capped at MAX_FLOW_SAMPLES (500)
        self.assertLessEqual(len(flow.timestamps), MAX_FLOW_SAMPLES)
        self.assertLessEqual(len(flow.packet_sizes), MAX_FLOW_SAMPLES)
        self.assertLessEqual(len(flow.payload_sizes), MAX_FLOW_SAMPLES)

    def test_expire_idle_flows(self):
        """Idle flows exceeding timeout are expired without dropping active ones."""
        assembler = FlowAssembler(flow_timeout=5.0)

        # Stale packet at t=10.0
        pkt1 = RawPacket(
            timestamp=10.0,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=1000,
            dst_port=80,
            proto="tcp",
            length=60,
        )
        assembler.process_packet(pkt1)

        # Active packet at t=19.0
        pkt2 = RawPacket(
            timestamp=19.0,
            src_ip="192.168.1.20",
            dst_ip="10.0.0.2",
            src_port=2000,
            dst_port=443,
            proto="tcp",
            length=60,
        )
        assembler.process_packet(pkt2)

        # Expire at current_time=20.0 (idle timeout = 5.0s, so pkt1 idle for 10s should expire, pkt2 idle for 1s stays active)
        expired = assembler.expire_idle_flows(current_time=20.0)
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].src_ip, "192.168.1.10")

        # Remaining active flow
        remaining = assembler.flush()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].src_ip, "192.168.1.20")


if __name__ == "__main__":
    unittest.main()
