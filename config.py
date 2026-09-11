"""
SIH Cyber Threat Detection — Configuration Module

Single source of truth for all configurable values (rules.md R7.4).
Uses environment variables with sensible defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).parent
DATA_DIR: Path = PROJECT_ROOT / "traffic" / "samples"
MODELS_DIR: Path = PROJECT_ROOT / "models"
DB_PATH: Path = Path(os.getenv("SIH_DB_PATH", str(PROJECT_ROOT / "alerts.db")))

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
API_HOST: str = os.getenv("SIH_API_HOST", os.getenv("HOST", "0.0.0.0"))
API_PORT: int = int(os.getenv("SIH_API_PORT", os.getenv("PORT", "8000")))

# ---------------------------------------------------------------------------
# Streaming backbone
# ---------------------------------------------------------------------------
USE_REDIS: bool = os.getenv("SIH_USE_REDIS", "false").lower() == "true"
REDIS_URL: str = os.getenv("SIH_REDIS_URL", "redis://localhost:6379/0")

# ---------------------------------------------------------------------------
# Pipeline settings
# ---------------------------------------------------------------------------
WINDOW_SIZE_SECONDS: float = float(os.getenv("SIH_WINDOW_SIZE", "10.0"))
WINDOW_OVERLAP_SECONDS: float = float(os.getenv("SIH_WINDOW_OVERLAP", "5.0"))
FLOW_TIMEOUT_SECONDS: float = float(os.getenv("SIH_FLOW_TIMEOUT", "30.0"))

# ---------------------------------------------------------------------------
# Detection thresholds — DDoS (PRD §7)
# ---------------------------------------------------------------------------
DDOS_FLOW_RATE_THRESHOLD: float = float(os.getenv("SIH_DDOS_FLOW_RATE", "20.0"))
DDOS_SRC_ENTROPY_LOW: float = float(os.getenv("SIH_DDOS_ENTROPY_LOW", "0.5"))
DDOS_SYN_ACK_RATIO_THRESHOLD: float = float(os.getenv("SIH_DDOS_SYN_ACK", "5.0"))
DDOS_PKT_SIZE_UNIFORMITY_THRESHOLD: float = float(
    os.getenv("SIH_DDOS_PKT_UNIFORMITY", "0.9")
)

# ---------------------------------------------------------------------------
# Detection thresholds — Recon / Port Scan (PRD §7)
# ---------------------------------------------------------------------------
RECON_DST_PORTS_THRESHOLD: int = int(os.getenv("SIH_RECON_DST_PORTS", "20"))
RECON_DST_HOSTS_THRESHOLD: int = int(os.getenv("SIH_RECON_DST_HOSTS", "15"))
RECON_LOW_BYTES_THRESHOLD: int = int(os.getenv("SIH_RECON_LOW_BYTES", "200"))

# ---------------------------------------------------------------------------
# Detection thresholds — C2 Beaconing (PRD §7)
# ---------------------------------------------------------------------------
C2_PERIODICITY_THRESHOLD: float = float(os.getenv("SIH_C2_PERIODICITY", "0.7"))
C2_LOW_JITTER_THRESHOLD: float = float(os.getenv("SIH_C2_LOW_JITTER", "0.1"))
C2_MIN_CONNECTIONS: int = int(os.getenv("SIH_C2_MIN_CONNS", "10"))

# ---------------------------------------------------------------------------
# Detection thresholds — DGA / DNS Tunnelling (PRD §7)
# ---------------------------------------------------------------------------
DGA_ENTROPY_THRESHOLD: float = float(os.getenv("SIH_DGA_ENTROPY", "3.5"))
DGA_NGRAM_THRESHOLD: float = float(os.getenv("SIH_DGA_NGRAM", "-9.2"))
DGA_QUERY_LENGTH_THRESHOLD: int = int(os.getenv("SIH_DGA_QUERY_LEN", "20"))

# ---------------------------------------------------------------------------
# Detection thresholds — Encrypted Malware (Tier 2) (PRD §7)
# ---------------------------------------------------------------------------
MALWARE_JA3_BLOCKLIST_PATH: Path = Path(
    os.getenv("SIH_JA3_BLOCKLIST", str(PROJECT_ROOT / "models" / "ja3_blocklist.csv"))
)

# ---------------------------------------------------------------------------
# Detection thresholds — Exfiltration (Tier 2) (PRD §7)
# ---------------------------------------------------------------------------
EXFIL_BYTE_RATIO_THRESHOLD: float = float(os.getenv("SIH_EXFIL_RATIO", "10.0"))
EXFIL_DURATION_THRESHOLD: float = float(os.getenv("SIH_EXFIL_DURATION", "60.0"))

# ---------------------------------------------------------------------------
# Alert Deduplication & Cooldown (PRD §6, rules.md R4)
# ---------------------------------------------------------------------------
ALERT_COOLDOWN_SECONDS: float = float(os.getenv("SIH_ALERT_COOLDOWN", "10.0"))

# ---------------------------------------------------------------------------
# External Alert Notifications (Webhooks, Discord, Slack, Telegram)
# ---------------------------------------------------------------------------
ALERT_WEBHOOK_URL: str = os.getenv("ALERT_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")
ALERT_MIN_SEVERITY: str = os.getenv("ALERT_MIN_SEVERITY", "high").lower()
ALERT_DISPATCH_COOLDOWN_SECONDS: float = float(os.getenv("ALERT_DISPATCH_COOLDOWN", "60.0"))

