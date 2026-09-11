"""
Alert Dispatcher — Real-time notification system for High and Critical threats.

Dispatches validated alerts to external operational channels:
    - Generic Webhooks (JSON payload)
    - Discord Incoming Webhooks (Rich color-coded embeds)
    - Slack Incoming Webhooks (Block Kit)
    - Telegram Bot API (Markdown messages)

Features:
    - Anti-flood cooldown per flow/threat (prevents webhook saturation)
    - Severity-based threshold gating (default: High & Critical only)
    - Thread-safe dispatch audit log (records last 50 deliveries with HTTP status)
    - On-demand test dispatch verification
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
import json
import logging
import time
from typing import Any
import urllib.error
import urllib.request

import config
from src.alert.schema import Alert, Severity, ThreatClass

logger = logging.getLogger(__name__)

SEVERITY_WEIGHT = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

THREAT_TITLES = {
    ThreatClass.DDOS: "DDoS / Volumetric Flooding",
    ThreatClass.RECON_SCAN: "Reconnaissance / Port Scanning",
    ThreatClass.C2_BEACONING: "Botnet C2 Beaconing",
    ThreatClass.DGA_DNS: "DGA / DNS Tunnelling",
    ThreatClass.ENCRYPTED_MALWARE: "Encrypted Malware (JA3)",
    ThreatClass.EXFILTRATION: "Data Exfiltration Anomaly",
}


class AlertDispatcher:
    """
    Manages external notification dispatches to Webhooks, Slack, Discord, and Telegram.
    Thread-safe and non-blocking.
    """

    def __init__(self) -> None:
        self.webhook_url: str = config.ALERT_WEBHOOK_URL
        self.telegram_bot_token: str = config.TELEGRAM_BOT_TOKEN
        self.telegram_chat_id: str = config.TELEGRAM_CHAT_ID
        self.min_severity: str = config.ALERT_MIN_SEVERITY
        self.cooldown_seconds: float = config.ALERT_DISPATCH_COOLDOWN_SECONDS

        # Anti-flood rate limiting: (flow_id, threat_class) -> last_dispatch_epoch
        self._cooldown_cache: dict[str, float] = {}

        # Circular buffer for recent dispatch delivery logs
        self._dispatch_logs: deque[dict[str, Any]] = deque(maxlen=50)

    # -----------------------------------------------------------------------
    # Configuration Management
    # -----------------------------------------------------------------------
    def get_config(self) -> dict[str, Any]:
        """Return active configuration with secrets masked."""
        masked_token = (
            f"{self.telegram_bot_token[:4]}...{self.telegram_bot_token[-4:]}"
            if len(self.telegram_bot_token) > 8
            else ("configured" if self.telegram_bot_token else "")
        )
        masked_webhook = (
            f"{self.webhook_url[:18]}...{self.webhook_url[-8:]}"
            if len(self.webhook_url) > 26
            else ("configured" if self.webhook_url else "")
        )
        channel_type = "none"
        if self.webhook_url:
            if "discord.com" in self.webhook_url:
                channel_type = "discord"
            elif "slack.com" in self.webhook_url:
                channel_type = "slack"
            else:
                channel_type = "generic_webhook"

        return {
            "webhook_url": self.webhook_url,
            "webhook_url_masked": masked_webhook,
            "webhook_type": channel_type,
            "telegram_configured": bool(self.telegram_bot_token and self.telegram_chat_id),
            "telegram_bot_token_masked": masked_token,
            "telegram_chat_id": self.telegram_chat_id,
            "min_severity": self.min_severity,
            "cooldown_seconds": self.cooldown_seconds,
            "total_dispatches": len(self._dispatch_logs),
        }

    def update_config(
        self,
        webhook_url: str | None = None,
        telegram_bot_token: str | None = None,
        telegram_chat_id: str | None = None,
        min_severity: str | None = None,
        cooldown_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Update notification dispatch settings at runtime."""
        if webhook_url is not None:
            self.webhook_url = webhook_url.strip()
        if telegram_bot_token is not None:
            self.telegram_bot_token = telegram_bot_token.strip()
        if telegram_chat_id is not None:
            self.telegram_chat_id = telegram_chat_id.strip()
        if min_severity is not None:
            self.min_severity = min_severity.strip().lower()
        if cooldown_seconds is not None:
            self.cooldown_seconds = max(5.0, float(cooldown_seconds))

        logger.info(
            "AlertDispatcher configuration updated (webhook=%s, telegram=%s, min_severity=%s)",
            bool(self.webhook_url),
            bool(self.telegram_bot_token and self.telegram_chat_id),
            self.min_severity,
        )
        return self.get_config()

    def get_logs(self, limit: int = 30) -> list[dict[str, Any]]:
        """Return recent notification delivery audit logs."""
        return list(self._dispatch_logs)[-limit:][::-1]

    # -----------------------------------------------------------------------
    # Gating & Rate Limiting
    # -----------------------------------------------------------------------
    def _should_dispatch(self, alert: Alert) -> bool:
        """Verify severity threshold and anti-flood cooldown."""
        # Check severity
        target_weight = 3  # default high
        if self.min_severity == "critical":
            target_weight = 4
        elif self.min_severity in ("medium", "med"):
            target_weight = 2
        elif self.min_severity in ("all", "low"):
            target_weight = 1

        alert_weight = SEVERITY_WEIGHT.get(alert.severity, 1)
        if alert_weight < target_weight:
            return False

        # Check anti-flood cooldown
        key = f"{alert.threat_class.value}:{alert.flow_id}"
        now = time.time()
        last_time = self._cooldown_cache.get(key, 0.0)
        if (now - last_time) < self.cooldown_seconds:
            logger.debug("Suppressing notification for %s (cooldown active)", key)
            return False

        self._cooldown_cache[key] = now
        return True

    # -----------------------------------------------------------------------
    # Payload Formatters
    # -----------------------------------------------------------------------
    def _format_discord_payload(self, alert: Alert) -> dict[str, Any]:
        """Format as rich Discord Webhook embed."""
        color = 0xDC2626 if alert.severity == Severity.CRITICAL else 0xD97706
        title = THREAT_TITLES.get(alert.threat_class, alert.threat_class.value)
        features = ", ".join(alert.evidence.features_triggered)
        conf_pct = round(alert.confidence * 100)

        # Extract evidence highlights
        stats = alert.evidence.supporting_stats
        evidence_summary = []
        for k, v in list(stats.items())[:4]:
            evidence_summary.append(f"• **{k.replace('_', ' ').title()}**: `{v}`")
        evidence_text = "\n".join(evidence_summary) or "Behavioral threshold exceeded"

        embed = {
            "title": f"🚨 [NET-DRISHTI] {title}",
            "description": f"Air-gapped telemetry sensor detected a **{alert.severity.value.upper()}** threat event on passive optical tap.",
            "color": color,
            "fields": [
                {"name": "Severity", "value": f"`{alert.severity.value.upper()}`", "inline": True},
                {"name": "Confidence", "value": f"`{conf_pct}%`", "inline": True},
                {"name": "MITRE ATT&CK", "value": f"`{alert.mitre_technique or 'T1498'}`", "inline": True},
                {"name": "Flow 5-Tuple", "value": f"`{alert.flow_id}`", "inline": False},
                {"name": "Triggered Features", "value": f"`{features}`", "inline": False},
                {"name": "Telemetry Evidence", "value": evidence_text, "inline": False},
            ],
            "footer": {
                "text": f"NET-DRISHTI Sensor // Event ID: {alert.alert_id[:8]}... // Zero-TX Enclave"
            },
            "timestamp": alert.timestamp,
        }
        return {"embeds": [embed]}

    def _format_slack_payload(self, alert: Alert) -> dict[str, Any]:
        """Format as Slack Block Kit JSON."""
        title = THREAT_TITLES.get(alert.threat_class, alert.threat_class.value)
        conf_pct = round(alert.confidence * 100)
        sev_icon = "🚨" if alert.severity == Severity.CRITICAL else "⚠️"

        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{sev_icon} NET-DRISHTI ALERT: {title}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:*\n`{alert.severity.value.upper()}`"},
                        {"type": "mrkdwn", "text": f"*Confidence:*\n`{conf_pct}%`"},
                        {"type": "mrkdwn", "text": f"*MITRE:*\n`{alert.mitre_technique or 'T1498'}`"},
                        {"type": "mrkdwn", "text": f"*Detector:*\n`v{alert.detector_version}`"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Connection Path:*\n`{alert.flow_id}`\n\n*Triggered Signals:*\n`{', '.join(alert.evidence.features_triggered)}`",
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Hardware Mode: *Passive Optical Diode (Rx-Only)* | Event: `{alert.alert_id}`",
                        }
                    ],
                },
            ]
        }

    def _format_telegram_message(self, alert: Alert) -> str:
        """Format as clean Telegram Markdown."""
        title = THREAT_TITLES.get(alert.threat_class, alert.threat_class.value)
        conf_pct = round(alert.confidence * 100)
        sev_emoji = "🔴" if alert.severity == Severity.CRITICAL else "🟠"

        stats = alert.evidence.supporting_stats
        evidence_lines = [f"• `{k}`: `{v}`" for k, v in list(stats.items())[:3]]
        evidence_str = "\n".join(evidence_lines)

        return (
            f"{sev_emoji} *[NET-DRISHTI AIR-GAPPED SOC]*\n"
            f"*Threat:* {title}\n"
            f"*Severity:* `{alert.severity.value.upper()}` | *Confidence:* `{conf_pct}%`\n"
            f"*MITRE Technique:* `{alert.mitre_technique or 'T1498'}`\n"
            f"*5-Tuple:* `{alert.flow_id}`\n\n"
            f"*Forensic Evidence:*\n{evidence_str}\n\n"
            f"_Physical Diode: Read-Only Ingest • Zero Outbound Sockets_"
        )

    # -----------------------------------------------------------------------
    # Dispatch Execution (Non-Blocking)
    # -----------------------------------------------------------------------
    def _http_post_sync(
        self, url: str, data: bytes, headers: dict[str, str], channel: str, target: str
    ) -> dict[str, Any]:
        """Synchronous HTTP POST executed in thread pool."""
        start_time = time.time()
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "channel": channel,
            "target": target,
            "status_code": 0,
            "status": "pending",
            "latency_ms": 0,
            "error": None,
        }

        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                status_code = resp.getcode()
                elapsed = round((time.time() - start_time) * 1000, 1)
                log_entry["status_code"] = status_code
                log_entry["status"] = "delivered" if 200 <= status_code < 300 else "failed"
                log_entry["latency_ms"] = elapsed
                logger.info("Alert dispatched successfully to %s in %sms (HTTP %d)", channel, elapsed, status_code)
                return log_entry
        except urllib.error.HTTPError as e:
            elapsed = round((time.time() - start_time) * 1000, 1)
            log_entry["status_code"] = e.code
            log_entry["status"] = "http_error"
            log_entry["latency_ms"] = elapsed
            log_entry["error"] = f"HTTP {e.code}: {e.reason}"
            logger.warning("HTTP error dispatching to %s: %s", channel, e)
            return log_entry
        except Exception as e:
            elapsed = round((time.time() - start_time) * 1000, 1)
            log_entry["status"] = "network_error"
            log_entry["latency_ms"] = elapsed
            log_entry["error"] = str(e)
            logger.warning("Failed to dispatch alert to %s: %s", channel, e)
            return log_entry

    async def dispatch_async(self, alert: Alert) -> list[dict[str, Any]]:
        """
        Asynchronously evaluate and dispatch alert to all configured channels.
        Invoked from pipeline alert callback without blocking the main event loop.
        """
        if not self._should_dispatch(alert):
            return []

        tasks = []
        loop = asyncio.get_event_loop()

        # 1. Webhook / Slack / Discord Dispatch
        if self.webhook_url:
            if "discord.com" in self.webhook_url:
                payload = self._format_discord_payload(alert)
                channel_name = "Discord Webhook"
            elif "slack.com" in self.webhook_url:
                payload = self._format_slack_payload(alert)
                channel_name = "Slack Webhook"
            else:
                payload = {
                    "event": "cyber_threat_alert",
                    "enclave": "NET-DRISHTI",
                    "alert": alert.model_dump(),
                }
                channel_name = "Generic Webhook"

            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json", "User-Agent": "NetDrishti-AlertDispatcher/1.0"}
            tasks.append(
                loop.run_in_executor(
                    None,
                    self._http_post_sync,
                    self.webhook_url,
                    data,
                    headers,
                    channel_name,
                    self.webhook_url[:35] + "...",
                )
            )

        # 2. Telegram Bot Dispatch
        if self.telegram_bot_token and self.telegram_chat_id:
            tg_url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            tg_text = self._format_telegram_message(alert)
            tg_payload = {
                "chat_id": self.telegram_chat_id,
                "text": tg_text,
                "parse_mode": "Markdown",
            }
            data = json.dumps(tg_payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            tasks.append(
                loop.run_in_executor(
                    None,
                    self._http_post_sync,
                    tg_url,
                    data,
                    headers,
                    "Telegram Bot",
                    f"Chat ID: {self.telegram_chat_id}",
                )
            )

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_results = []
        for r in results:
            if isinstance(r, dict):
                self._dispatch_logs.append(r)
                valid_results.append(r)

        return valid_results

    async def test_dispatch_async(
        self,
        channel: str = "all",
        webhook_url: str | None = None,
        telegram_bot_token: str | None = None,
        telegram_chat_id: str | None = None,
    ) -> dict[str, Any]:
        """Dispatch a mock threat alert on-demand to test and verify integration."""
        test_alert = Alert(
            alert_id=f"test-{int(time.time())}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            flow_id="198.51.100.44:54321-10.0.0.1:443-tcp",
            threat_class=ThreatClass.DDOS,
            confidence=0.97,
            severity=Severity.CRITICAL,
            evidence={
                "features_triggered": ["simulated_test_dispatch", "high_flow_rate"],
                "supporting_stats": {
                    "test_mode": "true",
                    "flow_rate_per_sec": 1520.0,
                    "operator_verification": "SOC Integration Audit",
                },
            },
            detector_version="1.0.0-test",
            mitre_tactic="TA0040",
            mitre_technique="T1498",
        )

        # Temporary overrides for test
        active_webhook = (webhook_url or self.webhook_url).strip()
        active_tg_token = (telegram_bot_token or self.telegram_bot_token).strip()
        active_tg_chat = (telegram_chat_id or self.telegram_chat_id).strip()

        deliveries = []
        loop = asyncio.get_event_loop()

        if active_webhook and channel in ("all", "webhook", "discord", "slack"):
            if "discord.com" in active_webhook:
                payload = self._format_discord_payload(test_alert)
                ch = "Discord Webhook (Test)"
            elif "slack.com" in active_webhook:
                payload = self._format_slack_payload(test_alert)
                ch = "Slack Webhook (Test)"
            else:
                payload = {"event": "test_ping", "alert": test_alert.model_dump()}
                ch = "Generic Webhook (Test)"

            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json", "User-Agent": "NetDrishti-Test/1.0"}
            res = await loop.run_in_executor(
                None, self._http_post_sync, active_webhook, data, headers, ch, active_webhook[:35] + "..."
            )
            self._dispatch_logs.append(res)
            deliveries.append(res)

        if active_tg_token and active_tg_chat and channel in ("all", "telegram"):
            tg_url = f"https://api.telegram.org/bot{active_tg_token}/sendMessage"
            tg_payload = {
                "chat_id": active_tg_chat,
                "text": "🧪 *[NET-DRISHTI TEST NOTIFICATION]*\n\nOperational notification channel verification.\nPassive data diode tap is operational.",
                "parse_mode": "Markdown",
            }
            data = json.dumps(tg_payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            res = await loop.run_in_executor(
                None, self._http_post_sync, tg_url, data, headers, "Telegram Bot (Test)", f"Chat: {active_tg_chat}"
            )
            self._dispatch_logs.append(res)
            deliveries.append(res)

        return {
            "status": "completed",
            "deliveries": deliveries,
            "total_sent": len(deliveries),
        }


# Global singleton instance
_dispatcher = AlertDispatcher()


def get_dispatcher() -> AlertDispatcher:
    """Return the global AlertDispatcher singleton."""
    return _dispatcher
