"""
MITRE ATT&CK Matrix Mapping for SIH Threat Classification.

Maps all 6 threat classes to standardized Enterprise ATT&CK Tactics and Techniques.
"""

from __future__ import annotations

from typing import Any, NamedTuple


class MitreMapping(NamedTuple):
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: str | None
    reference_url: str
    description: str


MITRE_MATRIX: dict[str, MitreMapping] = {
    "ddos": MitreMapping(
        tactic_id="TA0040",
        tactic_name="Impact",
        technique_id="T1498",
        technique_name="Network Denial of Service",
        subtechnique_id="T1498.001",
        reference_url="https://attack.mitre.org/techniques/T1498/001/",
        description="Direct network volumetric flood saturating link bandwidth or receiver socket buffers.",
    ),
    "recon_scan": MitreMapping(
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        technique_id="T1595",
        technique_name="Active Scanning",
        subtechnique_id="T1595.001",
        reference_url="https://attack.mitre.org/techniques/T1595/001/",
        description="Systematic probing of IP addresses or destination ports to map vulnerable services.",
    ),
    "c2_beaconing": MitreMapping(
        tactic_id="TA0011",
        tactic_name="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        subtechnique_id="T1071.001",
        reference_url="https://attack.mitre.org/techniques/T1071/001/",
        description="Periodic low-jitter heartbeat beacons communicating with an external command-and-control server.",
    ),
    "dga_dns": MitreMapping(
        tactic_id="TA0011",
        tactic_name="Command and Control",
        technique_id="T1568",
        technique_name="Dynamic Resolution",
        subtechnique_id="T1568.002",
        reference_url="https://attack.mitre.org/techniques/T1568/002/",
        description="Domain Generation Algorithms (DGAs) generating pseudo-random domain queries to evade domain blocklists.",
    ),
    "encrypted_malware": MitreMapping(
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        technique_id="T1573",
        technique_name="Encrypted Channel",
        subtechnique_id="T1573.002",
        reference_url="https://attack.mitre.org/techniques/T1573/002/",
        description="Encrypted TLS session concealing command payload with suspicious cipher/JA3 fingerprint profile.",
    ),
    "exfiltration": MitreMapping(
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        subtechnique_id="T1048.003",
        reference_url="https://attack.mitre.org/techniques/T1048/003/",
        description="Sustained anomalous egress payload transfer transmitting sensitive data across network perimeter.",
    ),
}


def get_mitre_mapping(threat_class: str) -> MitreMapping | None:
    """Look up MITRE ATT&CK mapping for a given threat class."""
    return MITRE_MATRIX.get(threat_class.lower())


def enrich_alert_with_mitre(alert_dict: dict[str, Any]) -> dict[str, Any]:
    """Enrich an alert dictionary with MITRE ATT&CK fields."""
    tc = alert_dict.get("threat_class", "")
    mapping = get_mitre_mapping(tc)
    if mapping:
        alert_dict["mitre_tactic"] = mapping.tactic_id
        alert_dict["mitre_technique"] = mapping.technique_id
        # Also enrich evidence.supporting_stats
        evidence = alert_dict.setdefault("evidence", {})
        stats = evidence.setdefault("supporting_stats", {})
        stats["mitre_tactic"] = f"{mapping.tactic_id}: {mapping.tactic_name}"
        stats["mitre_technique"] = f"{mapping.technique_id}: {mapping.technique_name}"
        if mapping.subtechnique_id:
            stats["mitre_subtechnique"] = mapping.subtechnique_id
    return alert_dict
