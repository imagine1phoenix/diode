"""
Alert Normalizer — Converts RawDetection objects to standardized Alerts.

rules.md R6.4: All detectors output through a single Alert Schema Normalizer.
Detectors do NOT write directly to the store.

rules.md R4: Every alert is validated against the Pydantic schema before emission.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import config
from src.alert.mitre import get_mitre_mapping
from src.alert.schema import Alert, Evidence, Severity, ThreatClass
from src.detectors.base import RawDetection

logger = logging.getLogger(__name__)

MIN_CONFIDENCE_THRESHOLD: float = 0.40

# Global in-memory incident cooldown cache: entity_key -> last_alert_time
_incident_cooldown: dict[str, float] = {}


def reset_cooldown() -> None:
    """Clear in-memory cooldown state (useful for tests and simulator resets)."""
    _incident_cooldown.clear()


def _extract_ips(flow_id: str) -> tuple[str, str]:
    """Parse src_ip and dst_ip from canonical flow_id (src:sport-dst:dport-proto)."""
    try:
        parts = flow_id.split("-")
        src_ip = parts[0].split(":")[0]
        dst_ip = parts[1].split(":")[0]
        return src_ip, dst_ip
    except Exception:
        return "", ""


def normalize(raw_detections: list[RawDetection], apply_cooldown: bool = False) -> list[Alert]:
    """
    Convert a list of RawDetection objects into standardized, deduplicated Alert objects.

    Pipeline:
    1. Confidence Floor: Discard detections with confidence < 0.40.
    2. Incident Aggregation (Window-Level emit):
       - DDoS: Grouped by victim destination IP -> 1 consolidated incident alert per victim.
       - Recon: Grouped by scanner source IP -> 1 consolidated incident alert per scanner.
       - C2 Beaconing: Grouped by host pair (src, dst) -> 1 consolidated alert per host pair.
       - Point Threats: Grouped by flow_id with mutual exclusion (dominant threat wins).
    3. Incident Cooldown:
       - Suppresses duplicate alert emission within config.ALERT_COOLDOWN_SECONDS per entity.
    4. Strict Severity Alignment:
       - Critical: confidence >= 0.88 with at least 2 confirming features.
       - High: confidence >= 0.72.
       - Medium: confidence >= 0.55.
       - Low: confidence >= 0.40.
    """
    current_time = time.time()

    # 1. Filter out low-confidence noise
    valid_raws = [
        raw for raw in raw_detections
        if raw.confidence >= MIN_CONFIDENCE_THRESHOLD and len(raw.features_triggered) > 0
    ]
    if not valid_raws:
        return []

    # Step A: Per-flow mutual exclusion (1 flow -> at most 1 dominant raw detection)
    by_flow: dict[str, list[RawDetection]] = {}
    for raw in valid_raws:
        by_flow.setdefault(raw.flow_id, []).append(raw)

    dominant_raws: list[RawDetection] = []
    for flow_id, raws in by_flow.items():
        raws.sort(key=lambda d: (d.confidence, len(d.features_triggered)), reverse=True)
        primary = raws[0]
        if len(raws) > 1:
            stats = dict(primary.supporting_stats)
            stats["correlated_signals"] = [
                f"{d.threat_class.value} (conf={d.confidence:.2f})" for d in raws[1:]
            ]
            primary.supporting_stats = stats
        dominant_raws.append(primary)

    # Step B: Separate dominant detections by incident category
    ddos_by_victim: dict[str, list[RawDetection]] = {}
    recon_by_scanner: dict[str, list[RawDetection]] = {}
    c2_by_host_pair: dict[tuple[str, str], list[RawDetection]] = {}
    dga_by_host: dict[str, list[RawDetection]] = {}
    point_threats_by_flow: dict[str, list[RawDetection]] = {}

    for raw in dominant_raws:
        src_ip, dst_ip = _extract_ips(raw.flow_id)

        if raw.threat_class == ThreatClass.DDOS:
            victim = dst_ip or raw.flow_id
            ddos_by_victim.setdefault(victim, []).append(raw)
        elif raw.threat_class == ThreatClass.RECON_SCAN:
            scanner = src_ip or raw.flow_id
            recon_by_scanner.setdefault(scanner, []).append(raw)
        elif raw.threat_class == ThreatClass.C2_BEACONING:
            pair = (src_ip, dst_ip) if (src_ip and dst_ip) else (raw.flow_id, "")
            c2_by_host_pair.setdefault(pair, []).append(raw)
        elif raw.threat_class == ThreatClass.DGA_DNS:
            host = src_ip or raw.flow_id
            dga_by_host.setdefault(host, []).append(raw)
        else:
            point_threats_by_flow.setdefault(raw.flow_id, []).append(raw)

    alerts: list[Alert] = []


    # --- Process DDoS Incidents (1 alert per victim per window) ---
    for victim_ip, detections in ddos_by_victim.items():
        cooldown_key = f"ddos:{victim_ip}"
        if apply_cooldown and config.ALERT_COOLDOWN_SECONDS > 0:
            last = _incident_cooldown.get(cooldown_key, 0.0)
            if (current_time - last) < config.ALERT_COOLDOWN_SECONDS:
                logger.debug("DDoS alert for victim %s suppressed under cooldown", victim_ip)
                continue
            _incident_cooldown[cooldown_key] = current_time

        detections.sort(key=lambda d: (d.confidence, len(d.features_triggered)), reverse=True)
        primary = detections[0]
        all_features = list(dict.fromkeys([f for d in detections for f in d.features_triggered]))
        max_conf = min(1.0, max(d.confidence for d in detections) + min(len(detections) * 0.005, 0.15))

        stats = dict(primary.supporting_stats)
        stats["victim_ip"] = victim_ip
        stats["incident_type"] = "distributed_denial_of_service"
        stats["aggregate_attacking_flows"] = len(detections)
        if len(detections) > 1:
            stats["attack_burst_summary"] = f"{len(detections)} concurrent flows targeting {victim_ip}"

        alert = _build_alert(
            flow_id=primary.flow_id,
            threat_class=ThreatClass.DDOS,
            confidence=max_conf,
            features_triggered=all_features,
            supporting_stats=stats,
            detector_version=primary.detector_version,
        )
        if alert:
            alerts.append(alert)

    # --- Process Recon Scan Incidents (1 alert per scanner per window) ---
    for scanner_ip, detections in recon_by_scanner.items():
        cooldown_key = f"recon:{scanner_ip}"
        if apply_cooldown and config.ALERT_COOLDOWN_SECONDS > 0:
            last = _incident_cooldown.get(cooldown_key, 0.0)
            if (current_time - last) < config.ALERT_COOLDOWN_SECONDS:
                logger.debug("Recon alert for scanner %s suppressed under cooldown", scanner_ip)
                continue
            _incident_cooldown[cooldown_key] = current_time

        detections.sort(key=lambda d: (d.confidence, len(d.features_triggered)), reverse=True)
        primary = detections[0]
        all_features = list(dict.fromkeys([f for d in detections for f in d.features_triggered]))
        max_conf = min(1.0, max(d.confidence for d in detections) + min(len(detections) * 0.005, 0.12))

        stats = dict(primary.supporting_stats)
        stats["scanner_ip"] = scanner_ip
        stats["incident_type"] = "reconnaissance_sweep"
        stats["probed_flows_count"] = len(detections)

        alert = _build_alert(
            flow_id=primary.flow_id,
            threat_class=ThreatClass.RECON_SCAN,
            confidence=max_conf,
            features_triggered=all_features,
            supporting_stats=stats,
            detector_version=primary.detector_version,
        )
        if alert:
            alerts.append(alert)

    # --- Process C2 Beaconing Host Pairs (1 alert per host-pair per window) ---
    for pair, detections in c2_by_host_pair.items():
        src_ip, dst_ip = pair
        cooldown_key = f"c2:{src_ip}->{dst_ip}"
        if apply_cooldown and config.ALERT_COOLDOWN_SECONDS > 0:
            last = _incident_cooldown.get(cooldown_key, 0.0)
            if (current_time - last) < config.ALERT_COOLDOWN_SECONDS:
                logger.debug("C2 alert for pair %s->%s suppressed under cooldown", src_ip, dst_ip)
                continue
            _incident_cooldown[cooldown_key] = current_time

        detections.sort(key=lambda d: (d.confidence, len(d.features_triggered)), reverse=True)
        primary = detections[0]
        all_features = list(dict.fromkeys([f for d in detections for f in d.features_triggered]))
        max_conf = max(d.confidence for d in detections)

        stats = dict(primary.supporting_stats)
        stats["c2_host_pair"] = f"{src_ip} -> {dst_ip}"
        stats["beacon_flows_observed"] = len(detections)

        alert = _build_alert(
            flow_id=primary.flow_id,
            threat_class=ThreatClass.C2_BEACONING,
            confidence=max_conf,
            features_triggered=all_features,
            supporting_stats=stats,
            detector_version=primary.detector_version,
        )
        if alert:
            alerts.append(alert)

    # --- Process DGA DNS Incidents (1 alert per client host per window) ---
    for host_ip, detections in dga_by_host.items():
        cooldown_key = f"dga:{host_ip}"
        if apply_cooldown and config.ALERT_COOLDOWN_SECONDS > 0:
            last = _incident_cooldown.get(cooldown_key, 0.0)
            if (current_time - last) < config.ALERT_COOLDOWN_SECONDS:
                logger.debug("DGA alert for host %s suppressed under cooldown", host_ip)
                continue
            _incident_cooldown[cooldown_key] = current_time

        detections.sort(key=lambda d: (d.confidence, len(d.features_triggered)), reverse=True)
        primary = detections[0]
        all_features = list(dict.fromkeys([f for d in detections for f in d.features_triggered]))
        max_conf = max(d.confidence for d in detections)

        stats = dict(primary.supporting_stats)
        stats["host_ip"] = host_ip
        stats["query_count"] = len(detections)
        if len(detections) > 1:
            stats["dga_queries_observed"] = len(detections)
            domains = list(dict.fromkeys([
                d.supporting_stats.get("domain", "")
                for d in detections if d.supporting_stats.get("domain")
            ]))
            if domains:
                stats["sample_domains"] = domains[:3]

        alert = _build_alert(
            flow_id=primary.flow_id,
            threat_class=ThreatClass.DGA_DNS,
            confidence=max_conf,
            features_triggered=all_features,
            supporting_stats=stats,
            detector_version=primary.detector_version,
        )
        if alert:
            alerts.append(alert)

    # --- Process Point Threats with Flow-Level Mutual Exclusion ---
    for flow_id, detections in point_threats_by_flow.items():
        detections.sort(key=lambda d: (d.confidence, len(d.features_triggered)), reverse=True)
        primary = detections[0]

        cooldown_key = f"{primary.threat_class.value}:{flow_id}"
        if apply_cooldown and config.ALERT_COOLDOWN_SECONDS > 0:
            last = _incident_cooldown.get(cooldown_key, 0.0)
            if (current_time - last) < config.ALERT_COOLDOWN_SECONDS:
                continue
            _incident_cooldown[cooldown_key] = current_time

        combined_stats = dict(primary.supporting_stats)
        if len(detections) > 1:
            secondaries = [f"{d.threat_class.value} (conf={d.confidence:.2f})" for d in detections[1:]]
            combined_stats["correlated_signals"] = secondaries

        alert = _build_alert(
            flow_id=primary.flow_id,
            threat_class=primary.threat_class,
            confidence=primary.confidence,
            features_triggered=primary.features_triggered,
            supporting_stats=combined_stats,
            detector_version=primary.detector_version,
        )
        if alert:
            alerts.append(alert)

    # Stagger alert timestamps so demo and live stream progress naturally in time
    if alerts:
        now_dt = datetime.now(timezone.utc)
        num_alerts = len(alerts)
        for idx, alert in enumerate(alerts):
            # Calculate staggered timestamp (most recent at now, preceding alerts stepped back)
            stagger = (num_alerts - 1 - idx) * 14.0 + (idx % 4) * 3.0
            alert.timestamp = (now_dt - timedelta(seconds=stagger)).isoformat()

    return alerts


def _build_alert(
    flow_id: str,
    threat_class: ThreatClass,
    confidence: float,
    features_triggered: list[str],
    supporting_stats: dict[str, Any],
    detector_version: str,
) -> Alert | None:
    """Build and validate a single standardized Alert with aligned severity."""
    conf = max(0.0, min(confidence, 1.0))

    if conf >= 0.88 and len(features_triggered) >= 2:
        severity = Severity.CRITICAL
    elif conf >= 0.72:
        severity = Severity.HIGH
    elif conf >= 0.55:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    try:
        mapping = get_mitre_mapping(threat_class.value)
        mitre_tactic = mapping.tactic_id if mapping else None
        mitre_technique = mapping.technique_id if mapping else None
        if mapping:
            supporting_stats["mitre_tactic"] = f"{mapping.tactic_id}: {mapping.tactic_name}"
            supporting_stats["mitre_technique"] = f"{mapping.technique_id}: {mapping.technique_name}"
            if mapping.subtechnique_id:
                supporting_stats["mitre_subtechnique"] = mapping.subtechnique_id

        evidence = Evidence(
            features_triggered=features_triggered,
            supporting_stats=supporting_stats,
        )
        return Alert(
            flow_id=flow_id,
            threat_class=threat_class,
            confidence=conf,
            severity=severity,
            evidence=evidence,
            detector_version=detector_version,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
        )
    except Exception as e:
        logger.error("Failed to build alert for flow=%s threat=%s: %s", flow_id, threat_class, e)
        return None

