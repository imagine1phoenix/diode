"""
Unit Tests for AlertDispatcher — Webhook, Discord, Slack, and Telegram notifications.
"""

from __future__ import annotations

import time
import unittest

from src.alert.dispatcher import AlertDispatcher
from src.alert.schema import Alert, Evidence, Severity, ThreatClass


class TestAlertDispatcher(unittest.TestCase):
    """Test suite for external alert notification dispatcher."""

    def setUp(self):
        self.dispatcher = AlertDispatcher()
        self.dispatcher.min_severity = "high"
        self.dispatcher.cooldown_seconds = 10.0
        self.dispatcher.webhook_url = "https://discord.com/api/webhooks/123/abc"
        self.dispatcher.telegram_bot_token = "123456:ABC-DEF1234ghIkl"
        self.dispatcher.telegram_chat_id = "-100987654321"

    def _sample_alert(self, severity: Severity, flow_id: str = "192.168.1.100:1234-10.0.0.1:80-tcp") -> Alert:
        return Alert(
            alert_id="test-uuid-001",
            timestamp="2026-09-12T03:00:00Z",
            flow_id=flow_id,
            threat_class=ThreatClass.DDOS,
            confidence=0.95,
            severity=severity,
            evidence=Evidence(
                features_triggered=["high_flow_rate", "syn_flood_ratio"],
                supporting_stats={"flow_rate_per_sec": 1400.0, "syn_ratio": 0.98},
            ),
            detector_version="1.0.0",
            mitre_tactic="TA0040",
            mitre_technique="T1498",
        )

    def test_severity_gating(self):
        """Low and Medium alerts should be suppressed when min_severity is 'high'."""
        self.dispatcher.min_severity = "high"

        low_alert = self._sample_alert(Severity.LOW, "1.1.1.1:1-2.2.2.2:2-tcp")
        self.assertFalse(self.dispatcher._should_dispatch(low_alert))

        med_alert = self._sample_alert(Severity.MEDIUM, "1.1.1.1:2-2.2.2.2:2-tcp")
        self.assertFalse(self.dispatcher._should_dispatch(med_alert))

        high_alert = self._sample_alert(Severity.HIGH, "1.1.1.1:3-2.2.2.2:2-tcp")
        self.assertTrue(self.dispatcher._should_dispatch(high_alert))

        crit_alert = self._sample_alert(Severity.CRITICAL, "1.1.1.1:4-2.2.2.2:2-tcp")
        self.assertTrue(self.dispatcher._should_dispatch(crit_alert))

    def test_cooldown_rate_limiting(self):
        """Repeated alerts for the same flow/threat should be throttled within cooldown window."""
        alert = self._sample_alert(Severity.CRITICAL, "10.10.10.10:80-20.20.20.20:80-tcp")

        # First alert passes
        self.assertTrue(self.dispatcher._should_dispatch(alert))

        # Immediate second alert for same flow and threat is throttled
        self.assertFalse(self.dispatcher._should_dispatch(alert))

        # Alert for different flow passes
        diff_alert = self._sample_alert(Severity.CRITICAL, "99.99.99.99:80-20.20.20.20:80-tcp")
        self.assertTrue(self.dispatcher._should_dispatch(diff_alert))

    def test_discord_formatter(self):
        """Verify Discord payload contains valid embed structure and color."""
        alert = self._sample_alert(Severity.CRITICAL)
        payload = self.dispatcher._format_discord_payload(alert)

        self.assertIn("embeds", payload)
        embed = payload["embeds"][0]
        self.assertEqual(embed["color"], 0xDC2626)  # Red for Critical
        self.assertIn("DDoS", embed["title"])
        self.assertTrue(any(f["name"] == "Flow 5-Tuple" for f in embed["fields"]))

    def test_slack_formatter(self):
        """Verify Slack payload contains valid Block Kit structure."""
        alert = self._sample_alert(Severity.HIGH)
        payload = self.dispatcher._format_slack_payload(alert)

        self.assertIn("blocks", payload)
        self.assertGreaterEqual(len(payload["blocks"]), 3)
        self.assertEqual(payload["blocks"][0]["type"], "header")

    def test_telegram_formatter(self):
        """Verify Telegram message contains Markdown tags and essential metadata."""
        alert = self._sample_alert(Severity.CRITICAL)
        text = self.dispatcher._format_telegram_message(alert)

        self.assertIn("*Threat:*", text)
        self.assertIn("*Severity:* `CRITICAL`", text)
        self.assertIn("192.168.1.100", text)

    def test_masked_config(self):
        """Verify secret tokens are masked in get_config() output."""
        cfg = self.dispatcher.get_config()
        self.assertEqual(cfg["webhook_type"], "discord")
        self.assertTrue(cfg["telegram_configured"])
        self.assertIn("...", cfg["telegram_bot_token_masked"])
        self.assertNotIn("ABC-DEF1234ghIkl", cfg["telegram_bot_token_masked"])


if __name__ == "__main__":
    unittest.main()
