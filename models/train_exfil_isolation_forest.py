"""
Data Exfiltration Anomaly Detection — Isolation Forest Training Pipeline.

Generates baseline benign network traffic (web browsing + DNS queries),
writes the packets to a PCAP file, processes them through the SIH ingest
pipeline (reader + FlowAssembler), extracts flow features, and trains an
unsupervised scikit-learn IsolationForest model on 5 key exfiltration features.

PRD §7 Row 6: Unsupervised Anomaly Detection for Data Exfiltration.
Output Artifact: models/exfil_isolation_forest.joblib
"""

from __future__ import annotations

import logging
from pathlib import Path
import sys
import time

import joblib
import numpy as np
from scapy.all import wrpcap
from sklearn.ensemble import IsolationForest

# Ensure repository root is on sys.path for absolute package imports
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.features.extractor import extract_flow_features
from src.ingest.flow_assembler import FlowAssembler
from src.ingest.reader import read_pcap_batch
from traffic.generators.generate_traffic import (
    generate_benign_dns,
    generate_benign_web,
)

# -----------------------------------------------------------------------------
# Configuration & Constants
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("train_exfil_isolation_forest")

FEATURE_FIELDS = [
    "egress_payload_density",
    "mean_payload_bytes_per_packet",
    "flow_duration",
    "total_bytes",
    "packet_count",
]

OUTPUT_PATH = Path(__file__).parent / "exfil_isolation_forest.joblib"
TRAINING_PCAP_PATH = (
    Path(__file__).parent.parent / "traffic" / "samples" / "exfil_training_benign.pcap"
)


def generate_training_pcap(
    n_web_flows: int = 4000, n_dns_flows: int = 1500
) -> Path:
    """
    Generate synthetic benign network traffic and write to PCAP.

    Uses generate_benign_web and generate_benign_dns from the traffic generator
    suite to craft legitimate enterprise web requests and DNS resolutions.

    Args:
        n_web_flows: Number of benign HTTP/HTTPS web conversation flows.
        n_dns_flows: Number of benign DNS query flows.

    Returns:
        Path to the written PCAP file.
    """
    logger.info(
        "Generating benign traffic: %d web flows + %d DNS queries...",
        n_web_flows,
        n_dns_flows,
    )
    t0 = time.time()
    web_packets = generate_benign_web(count=n_web_flows)
    dns_packets = generate_benign_dns(count=n_dns_flows)

    all_packets = web_packets + dns_packets
    # Sort packets chronologically by timestamp for coherent flow assembly
    all_packets.sort(key=lambda pkt: getattr(pkt, "time", 0.0))

    TRAINING_PCAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    logger.info(
        "Writing %d total packets to %s...", len(all_packets), TRAINING_PCAP_PATH
    )
    wrpcap(str(TRAINING_PCAP_PATH), all_packets)
    elapsed = time.time() - t0
    logger.info("PCAP generation completed in %.2f seconds.", elapsed)
    return TRAINING_PCAP_PATH


def extract_benign_feature_matrix(pcap_path: Path) -> np.ndarray:
    """
    Ingest PCAP through the pipeline and extract the 5-feature matrix.

    Reads raw packets with read_pcap_batch(), groups them into 5-tuple flows
    using FlowAssembler(flow_timeout=30.0), and extracts flow features using
    extract_flow_features().

    Args:
        pcap_path: Path to the benign training PCAP file.

    Returns:
        np.ndarray of shape (n_flows, 5) corresponding to FEATURE_FIELDS.
    """
    logger.info("Reading packets from %s...", pcap_path)
    t0 = time.time()
    raw_packets = read_pcap_batch(pcap_path)
    logger.info("Ingested %d packets via fast reader.", len(raw_packets))

    assembler = FlowAssembler(flow_timeout=30.0)
    flows = list(assembler.assemble_from_packets(raw_packets))
    logger.info("Assembled %d completed flows from PCAP.", len(flows))

    matrix_rows: list[list[float]] = []
    for flow in flows:
        features = extract_flow_features(flow)
        row = [
            float(getattr(features, field, 0.0)) for field in FEATURE_FIELDS
        ]
        matrix_rows.append(row)

    feature_matrix = np.array(matrix_rows, dtype=np.float64)
    elapsed = time.time() - t0
    logger.info(
        "Feature matrix constructed: shape=%s in %.2f seconds.",
        feature_matrix.shape,
        elapsed,
    )
    return feature_matrix


def train_and_save(matrix: np.ndarray) -> None:
    """
    Train Isolation Forest model on benign flow matrix and save artifact.

    Args:
        matrix: 2D numpy array of benign flow feature vectors.
    """
    target_contamination = 0.03
    logger.info(
        "Fitting IsolationForest(n_estimators=100, contamination=%.2f, random_state=42)...",
        target_contamination,
    )
    model = IsolationForest(
        n_estimators=100,
        contamination=target_contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(matrix)

    # Sanity-check evaluation on training flows
    preds = model.predict(matrix)
    n_anomalies = int(np.sum(preds == -1))
    pct_anomalous = (n_anomalies / len(preds)) * 100.0
    logger.info(
        "Sanity check: %.2f%% of training flows scored as anomalous (target contamination: %.2f%%)",
        pct_anomalous,
        target_contamination * 100.0,
    )

    # Attach feature fields to model for dynamic extraction
    model.feature_fields = FEATURE_FIELDS

    payload = {
        "model": model,
        "feature_fields": FEATURE_FIELDS,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, OUTPUT_PATH)
    file_size_kb = OUTPUT_PATH.stat().st_size / 1024.0
    logger.info(
        "Model artifact saved to %s (%.1f KB)",
        OUTPUT_PATH,
        file_size_kb,
    )


def main() -> None:
    """Main execution entrypoint for exfiltration Isolation Forest training."""
    logger.info("Starting exfiltration Isolation Forest model training pipeline...")
    pcap_path = generate_training_pcap(n_web_flows=4000, n_dns_flows=1500)
    matrix = extract_benign_feature_matrix(pcap_path)

    if matrix.shape[0] < 200:
        logger.warning(
            "Fewer than 200 flows assembled (%d) — model may underfit.",
            matrix.shape[0],
        )

    train_and_save(matrix)
    logger.info("Done. Next: wire this model into ExfiltrationDetector.__init__().")


if __name__ == "__main__":
    main()
