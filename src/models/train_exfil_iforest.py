"""
Data Exfiltration Anomaly Classifier — Isolation Forest Training Script.

Trains an unsupervised Isolation Forest model (sklearn.ensemble.IsolationForest)
on baseline benign network flow features to detect unauthorized data exfiltration
and outbound tunneling on unidirectional optical diode taps.

PRD §4 & PRD §7 row 6: Unsupervised anomaly detection for data exfiltration.
Output: models/isolation_forest_exfil.joblib
"""

from __future__ import annotations

import logging
import math
import random
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_exfil_iforest")

OUTPUT_MODEL_PATH = Path(__file__).parent.parent.parent / "models" / "isolation_forest_exfil.joblib"

FEATURE_NAMES = [
    "egress_payload_density",       # Ratio of payload bytes to total wire bytes [0.0, 1.0]
    "mean_payload_bytes_proxy",     # Average payload bytes per packet
    "flow_duration",                # Flow duration in seconds
    "total_bytes",                  # Total volume in bytes
    "bytes_per_sec",                # Throughput rate in bytes/second
    "outbound_inbound_byte_ratio",  # Ratio of outbound to inbound bytes (capped at 100.0)
]


def extract_exfil_features_vector(
    total_bytes: float,
    packet_count: int,
    flow_duration: float,
    payload_bytes: float,
    reverse_bytes: float = 0.0,
) -> list[float]:
    """
    Extract standard 6-dimensional feature vector for exfiltration anomaly evaluation:
    1. egress_payload_density [0.0, 1.0]
    2. mean_payload_bytes_proxy
    3. flow_duration (seconds)
    4. total_bytes
    5. bytes_per_sec
    6. outbound_inbound_byte_ratio (capped at 100.0)
    """
    safe_pkts = max(packet_count, 1)
    safe_dur = max(flow_duration, 0.05)
    safe_tot = max(total_bytes, 1.0)

    density = min(max(payload_bytes / safe_tot, 0.0), 1.0)
    mean_payload = payload_bytes / safe_pkts
    bps = total_bytes / safe_dur

    if reverse_bytes > 0:
        byte_ratio = min(total_bytes / reverse_bytes, 100.0)
    else:
        byte_ratio = 100.0  # Max ceiling for simplex/unidirectional upload

    return [
        round(density, 4),
        round(mean_payload, 2),
        round(flow_duration, 3),
        round(float(total_bytes), 2),
        round(bps, 2),
        round(byte_ratio, 2),
    ]


def generate_benign_flow_dataset(n_samples: int = 1500) -> list[list[float]]:
    """
    Generate synthetic benign network flows representing normal enterprise traffic:
    - Standard Web browsing (HTTP/HTTPS client requests with server replies)
    - DNS queries (small payloads, short duration)
    - Interactive SSH / API telemetry / NTP
    - Benign file downloads (inbound-heavy: low outbound:inbound ratio)
    """
    random.seed(42)
    flows = []

    for _ in range(n_samples):
        traffic_type = random.choices(
            ["web_browse", "dns_query", "api_telemetry", "large_download", "internal_rpc"],
            weights=[0.45, 0.25, 0.15, 0.10, 0.05],
        )[0]

        if traffic_type == "web_browse":
            # Normal GET/POST request: small client payload, moderate duration, inbound-heavy
            duration = random.uniform(0.2, 14.0)
            packets = random.randint(6, 40)
            # Web client requests: payload density typically 0.15 - 0.45
            payload_per_pkt = random.uniform(50, 350)
            payload_bytes = payload_per_pkt * (packets * random.uniform(0.2, 0.6))
            total_bytes = payload_bytes + packets * random.uniform(40, 64)
            # Inbound server response is usually 2x - 30x larger
            reverse_bytes = total_bytes * random.uniform(2.0, 25.0)

        elif traffic_type == "dns_query":
            # DNS lookup: 1-4 packets, very small payloads (<120 bytes), sub-second
            duration = random.uniform(0.01, 0.3)
            packets = random.randint(1, 3)
            payload_bytes = random.uniform(32, 96) * packets
            total_bytes = payload_bytes + packets * 42
            reverse_bytes = total_bytes * random.uniform(1.0, 3.0)

        elif traffic_type == "api_telemetry":
            # Background JSON telemetry: periodic, small bursts
            duration = random.uniform(0.1, 2.5)
            packets = random.randint(4, 15)
            payload_bytes = random.uniform(80, 450)
            total_bytes = payload_bytes + packets * 54
            reverse_bytes = total_bytes * random.uniform(0.8, 3.0)

        elif traffic_type == "large_download":
            # Host downloading files/updates: massive inbound volume, small outbound ACKs
            duration = random.uniform(5.0, 45.0)
            packets = random.randint(50, 400)
            # Outbound is almost entirely TCP ACKs with minimal payload
            payload_bytes = random.uniform(0, 1200)
            total_bytes = payload_bytes + packets * 54
            reverse_bytes = total_bytes * random.uniform(20.0, 100.0)

        else:  # internal_rpc
            duration = random.uniform(0.05, 1.5)
            packets = random.randint(4, 20)
            payload_bytes = random.uniform(100, 800)
            total_bytes = payload_bytes + packets * 54
            reverse_bytes = total_bytes * random.uniform(0.9, 1.8)

        feat = extract_exfil_features_vector(
            total_bytes=total_bytes,
            packet_count=packets,
            flow_duration=duration,
            payload_bytes=payload_bytes,
            reverse_bytes=reverse_bytes,
        )
        flows.append(feat)

    return flows


def generate_exfiltration_attack_dataset(n_samples: int = 300) -> list[list[float]]:
    """
    Generate synthetic data exfiltration attack flows:
    - Bulk database/archive dump over HTTPS/TCP
    - Sustained high-volume outbound streaming
    - High egress payload saturation (MTU ~1400 bytes, density > 0.85)
    - Long duration (60 - 600 seconds)
    - High outbound:inbound byte ratio (>25:1)
    """
    random.seed(1337)
    attacks = []

    for _ in range(n_samples):
        # Exfiltration is characterized by sustained large outbound payload
        duration = random.uniform(60.0, 600.0)
        packets = random.randint(100, 5000)
        # Saturated MTU packets with payload 1200 - 1460 bytes
        mean_payload = random.uniform(1100, 1440)
        payload_bytes = mean_payload * packets
        # Wire overhead is small relative to bulk data (density > 0.85)
        total_bytes = payload_bytes + packets * random.uniform(40, 54)
        # Return traffic is either 0 (simplex diode tap) or tiny ACKs (ratio > 25:1)
        reverse_bytes = packets * random.uniform(0, 40)

        feat = extract_exfil_features_vector(
            total_bytes=total_bytes,
            packet_count=packets,
            flow_duration=duration,
            payload_bytes=payload_bytes,
            reverse_bytes=reverse_bytes,
        )
        attacks.append(feat)

    return attacks


def train_isolation_forest() -> tuple[IsolationForest, dict[str, Any]]:
    """Train unsupervised Isolation Forest on benign flow baseline."""
    logger.info("Generating benign baseline dataset (n=1,500)...")
    benign_data = generate_benign_flow_dataset(1500)
    X_train = np.array(benign_data, dtype=float)

    logger.info("Initializing IsolationForest(n_estimators=100, contamination=0.03)...")
    model = IsolationForest(
        n_estimators=100,
        max_samples="auto",
        contamination=0.03,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)

    # Evaluate on held-out benign and synthetic exfiltration
    logger.info("Evaluating anomaly boundary...")
    test_benign = np.array(generate_benign_flow_dataset(300), dtype=float)
    test_attacks = np.array(generate_exfiltration_attack_dataset(300), dtype=float)

    # Decision function: > 0 is inlier (normal), < 0 is outlier (anomalous exfiltration)
    scores_benign = model.decision_function(test_benign)
    scores_attacks = model.decision_function(test_attacks)

    preds_benign = model.predict(test_benign)      # +1 normal, -1 anomaly
    preds_attacks = model.predict(test_attacks)    # +1 normal, -1 anomaly

    fp_rate = float(np.mean(preds_benign == -1))
    tp_rate = float(np.mean(preds_attacks == -1))

    # ROC AUC: higher anomaly score indicates exfiltration (-scores)
    y_true = np.array([0] * len(test_benign) + [1] * len(test_attacks))
    y_scores = -np.concatenate([scores_benign, scores_attacks])
    auc = roc_auc_score(y_true, y_scores)

    metrics = {
        "n_train_benign": len(benign_data),
        "true_positive_rate": round(tp_rate, 4),
        "false_positive_rate": round(fp_rate, 4),
        "roc_auc": round(float(auc), 4),
        "feature_names": FEATURE_NAMES,
    }

    logger.info(
        "Model trained successfully — AUC: %.4f | TPR (Exfiltration Detected): %.2f%% | FPR: %.2f%%",
        auc, tp_rate * 100, fp_rate * 100
    )

    OUTPUT_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUTPUT_MODEL_PATH)
    logger.info("Saved Isolation Forest model to %s", OUTPUT_MODEL_PATH)

    return model, metrics


if __name__ == "__main__":
    train_isolation_forest()
