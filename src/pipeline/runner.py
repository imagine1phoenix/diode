"""
Streaming Pipeline Runner — Orchestrates the full detection pipeline.

PRD §5: Traffic Generators → PCAP/Flow → Ingest → Features → Detectors
        → Alert Normalizer → Alert Store + API → Dashboard

rules.md R6.1: Pipeline is strictly linear.
rules.md R3: asyncio queue by default, Redis Streams optional.

This module ties all stages together and provides:
    - Batch mode: process a PCAP file end-to-end
    - Streaming mode: process flows as they arrive (asyncio)
    - Throughput measurement (PRD §8)
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

import config
from src.alert.normalizer import normalize
from src.alert.schema import Alert
from src.alert.store import AlertStore
from src.detectors.base import BaseDetector, RawDetection
from src.detectors.c2_beaconing import C2BeaconingDetector
from src.detectors.ddos import DDoSDetector
from src.detectors.dga_dns import DGADNSDetector
from src.detectors.encrypted_malware import EncryptedMalwareDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.detectors.recon_scan import ReconScanDetector
from src.features.extractor import (
    FlowFeatures,
    WindowFeatures,
    extract_flow_features,
    extract_window_features,
)
from src.ingest.flow_assembler import FlowAssembler, FlowRecord
from src.ingest.reader import read_pcap_batch, read_pcap_stream

logger = logging.getLogger(__name__)


class ThroughputCounter:
    """
    Tracks pipeline throughput for PRD §8 reporting.
    Records flows/sec and alerts/sec.
    """

    def __init__(self) -> None:
        self.start_time: float = 0.0
        self.flows_processed: int = 0
        self.alerts_generated: int = 0

    def start(self) -> None:
        self.start_time = time.monotonic()

    def record_flows(self, count: int) -> None:
        self.flows_processed += count

    def record_alerts(self, count: int) -> None:
        self.alerts_generated += count

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time if self.start_time else 0.0

    @property
    def flows_per_sec(self) -> float:
        if self.elapsed == 0:
            return 0.0
        return self.flows_processed / self.elapsed

    @property
    def alerts_per_sec(self) -> float:
        if self.elapsed == 0:
            return 0.0
        return self.alerts_generated / self.elapsed

    def report(self) -> dict[str, Any]:
        return {
            "elapsed_seconds": round(self.elapsed, 3),
            "flows_processed": self.flows_processed,
            "alerts_generated": self.alerts_generated,
            "flows_per_sec": round(self.flows_per_sec, 2),
            "alerts_per_sec": round(self.alerts_per_sec, 2),
        }


class Pipeline:
    """
    Main pipeline orchestrator.

    Stages (rules.md R6.1):
        1. Ingest (read-only) → RawPackets
        2. Flow assembly → FlowRecords
        3. Feature extraction → FlowFeatures + WindowFeatures
        4. Detection (all detectors) → RawDetections
        5. Normalization → Alerts
        6. Store → SQLite
    """

    def __init__(
        self,
        store: AlertStore | None = None,
        alert_callback: Any | None = None,
    ) -> None:
        """
        Args:
            store: AlertStore for persistence. Uses default DB path if None.
            alert_callback: Optional async callback invoked with each new Alert
                           (used for WebSocket broadcasting).
        """
        self._store = store or AlertStore(config.DB_PATH)
        self._alert_callback = alert_callback
        self._throughput = ThroughputCounter()

        # Initialize all detectors (rules.md R2.1, R2.2)
        self._detectors: list[BaseDetector] = [
            # Tier 1 — must ship
            DDoSDetector(),
            ReconScanDetector(),
            C2BeaconingDetector(),
            DGADNSDetector(),
            # Tier 2 — partial
            EncryptedMalwareDetector(),
            ExfiltrationDetector(),
        ]
        logger.info(
            "Pipeline initialized with %d detectors: %s",
            len(self._detectors),
            [d.name for d in self._detectors],
        )

    @property
    def throughput(self) -> ThroughputCounter:
        return self._throughput

    def _run_detectors(
        self,
        flow_features: FlowFeatures,
        window_features: WindowFeatures,
    ) -> list[RawDetection]:
        """Run all detectors on a single flow's features."""
        all_detections: list[RawDetection] = []
        for detector in self._detectors:
            try:
                detections = detector.detect(flow_features, window_features)
                all_detections.extend(detections)
            except Exception as e:
                logger.error(
                    "Detector %s failed on flow %s: %s",
                    detector.name, flow_features.flow_id, e,
                )
        return all_detections

    def process_window(self, flows: list[FlowRecord]) -> list[Alert]:
        """
        Process a window of flows through the full pipeline.

        Args:
            flows: List of FlowRecords in the current analysis window.

        Returns:
            List of Alert objects generated for this window.
        """
        if not flows:
            return []

        # Stage 3: Feature extraction
        window_features = extract_window_features(flows)
        flow_features_list = [extract_flow_features(f) for f in flows]

        # Stage 4: Detection
        all_raw: list[RawDetection] = []
        for ff in flow_features_list:
            raw = self._run_detectors(ff, window_features)
            all_raw.extend(raw)

        # Stage 5: Normalization
        alerts = normalize(all_raw)

        # Stage 6: Store
        if alerts:
            saved = self._store.save_batch(alerts)
            logger.info("Stored %d alerts from window of %d flows", saved, len(flows))

        # Update throughput
        self._throughput.record_flows(len(flows))
        self._throughput.record_alerts(len(alerts))

        return alerts

    def process_pcap(self, pcap_path: Path) -> list[Alert]:
        """
        Process an entire PCAP file through the pipeline.

        This is the primary batch-mode entry point for demos and testing.

        Args:
            pcap_path: Path to a .pcap or .pcapng file.

        Returns:
            All alerts generated from the file.
        """
        logger.info("Processing PCAP: %s", pcap_path)
        self._throughput.start()

        # Stage 1: Ingest
        packets = read_pcap_batch(pcap_path)

        # Stage 2: Flow assembly
        assembler = FlowAssembler(flow_timeout=config.FLOW_TIMEOUT_SECONDS)
        flows = list(assembler.assemble_from_packets(iter(packets)))
        logger.info("Assembled %d flows from %d packets", len(flows), len(packets))

        # Window the flows and process
        all_alerts: list[Alert] = []
        window_size = config.WINDOW_SIZE_SECONDS

        if not flows:
            return all_alerts

        # Sort flows by start time
        flows.sort(key=lambda f: f.start_time)
        window_start = flows[0].start_time

        while True:
            window_end = window_start + window_size
            window_flows = [
                f for f in flows
                if window_start <= f.start_time < window_end
            ]

            if window_flows:
                alerts = self.process_window(window_flows)
                all_alerts.extend(alerts)

            window_start = window_end
            if window_start > flows[-1].start_time:
                break

        # Process any remaining flows not in a window
        report = self._throughput.report()
        logger.info(
            "PCAP processing complete. %s",
            report,
        )

        return all_alerts

    async def process_pcap_async(
        self, pcap_path: Path
    ) -> list[Alert]:
        """
        Async wrapper for PCAP processing with alert callbacks.

        Streams packets through the pipeline and invokes the alert
        callback for each new alert (for WebSocket broadcasting).
        """
        logger.info("Async processing PCAP: %s", pcap_path)
        self._throughput.start()

        # Run the CPU-bound work in a thread pool
        all_alerts = await asyncio.get_event_loop().run_in_executor(
            None, self.process_pcap, pcap_path
        )

        # Broadcast alerts via callback
        if self._alert_callback and all_alerts:
            for alert in all_alerts:
                try:
                    await self._alert_callback(alert)
                except Exception as e:
                    logger.error("Alert callback failed: %s", e)

        return all_alerts

    def get_stats(self) -> dict[str, Any]:
        """Get combined pipeline + alert store statistics."""
        store_stats = self._store.get_stats()
        throughput_stats = self._throughput.report()
        return {
            "pipeline": throughput_stats,
            "alerts": store_stats,
        }
