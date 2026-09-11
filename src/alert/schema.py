"""
Alert Schema — Core data models for the SIH Cyber Threat Detection system.

Implements the exact alert schema from PRD §6 and enforces all constraints
from rules.md R4. Every alert emitted by every detector MUST conform to
this schema — no extra fields, no missing fields.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ThreatClass(str, Enum):
    """
    Fixed threat classification enum (rules.md R2.3).
    Exactly 6 values — do NOT add a 7th.
    """
    DDOS = "ddos"
    C2_BEACONING = "c2_beaconing"
    DGA_DNS = "dga_dns"
    ENCRYPTED_MALWARE = "encrypted_malware"
    RECON_SCAN = "recon_scan"
    EXFILTRATION = "exfiltration"


class Severity(str, Enum):
    """
    Alert severity levels (rules.md R4.6).
    Exactly 4 values.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    """
    Supporting evidence for an alert (rules.md R4.7).
    Must never be empty — an alert without evidence is noise.
    """
    features_triggered: list[str] = Field(
        ...,
        min_length=1,
        description="List of feature names that triggered this detection",
    )
    supporting_stats: dict[str, Any] = Field(
        ...,
        description="Statistical values that support the detection",
    )

    @field_validator("supporting_stats")
    @classmethod
    def stats_not_empty(cls, v: dict[str, Any]) -> dict[str, Any]:
        if not v:
            raise ValueError("supporting_stats must not be empty (rules.md R4.7)")
        return v


class Alert(BaseModel):
    """
    Standardized alert schema — PRD §6, rules.md R4.

    Every field is required. No extra fields allowed (R4.9).
    """
    alert_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="UUID v4 per alert (R4.1)",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp (R4.2)",
    )
    flow_id: str = Field(
        ...,
        description="Format: src_ip:src_port-dst_ip:dst_port-proto (R4.3)",
    )
    threat_class: ThreatClass = Field(
        ...,
        description="One of 6 enum values (R4.4)",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Float in [0.0, 1.0] (R4.5)",
    )
    severity: Severity = Field(
        ...,
        description="One of: low, medium, high, critical (R4.6)",
    )
    evidence: Evidence = Field(
        ...,
        description="Must always be populated (R4.7)",
    )
    detector_version: str = Field(
        ...,
        description="Semver string identifying the detector (R4.8)",
    )

    @field_validator("flow_id")
    @classmethod
    def validate_flow_id_format(cls, v: str) -> str:
        """Enforce exact format: src_ip:src_port-dst_ip:dst_port-proto (R4.3)."""
        parts = v.split("-")
        if len(parts) != 3:
            raise ValueError(
                f"flow_id must have format src_ip:src_port-dst_ip:dst_port-proto, got: {v}"
            )
        src, dst, proto = parts
        if ":" not in src or ":" not in dst:
            raise ValueError(
                f"flow_id src and dst must contain ':' separator, got: {v}"
            )
        return v

    model_config = {"extra": "forbid"}  # R4.9: No extra fields
