"""
SIH Cyber Threat Detection — Main Entry Point

Usage:
    # Generate demo traffic + run pipeline + start dashboard
    python main.py

    # Run API server only (dashboard at http://localhost:8000)
    python main.py --serve

    # Process a specific PCAP file
    python main.py --pcap traffic/samples/demo_traffic.pcap

    # Generate demo traffic only
    python main.py --generate
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import uvicorn

import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sih")


def cmd_generate() -> Path:
    """Generate demo traffic PCAP."""
    from traffic.generators.generate_traffic import generate_demo_pcap

    logger.info("Generating demo traffic PCAP...")
    path = generate_demo_pcap()
    logger.info("✅ Demo PCAP: %s", path)
    return path


def cmd_analyze(pcap_path: Path) -> None:
    """Run the pipeline on a PCAP file."""
    from src.alert.store import AlertStore
    from src.pipeline.runner import Pipeline

    logger.info("Analyzing PCAP: %s", pcap_path)
    store = AlertStore(config.DB_PATH)
    pipeline = Pipeline(store=store)
    alerts = pipeline.process_pcap(pcap_path)

    logger.info("=" * 60)
    logger.info("Pipeline Results:")
    logger.info("  Alerts generated: %d", len(alerts))
    report = pipeline.throughput.report()
    logger.info("  Throughput: %.2f flows/sec", report["flows_per_sec"])
    logger.info("  Elapsed: %.3f sec", report["elapsed_seconds"])
    logger.info("=" * 60)

    # Print summary by threat class
    from collections import Counter
    threat_counts = Counter(a.threat_class.value for a in alerts)
    severity_counts = Counter(a.severity.value for a in alerts)

    logger.info("By Threat Class:")
    for tc, count in threat_counts.most_common():
        logger.info("  %-20s %d", tc, count)

    logger.info("By Severity:")
    for sev, count in severity_counts.most_common():
        logger.info("  %-20s %d", sev, count)


def cmd_serve() -> None:
    """Start the FastAPI server with dashboard."""
    logger.info("Starting API server at http://%s:%d", config.API_HOST, config.API_PORT)
    logger.info("Dashboard: http://%s:%d", config.API_HOST, config.API_PORT)
    logger.info("API docs:  http://%s:%d/docs", config.API_HOST, config.API_PORT)
    uvicorn.run(
        "src.api.main:app",
        host=config.API_HOST,
        port=config.API_PORT,
        reload=False,
        log_level="info",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SIH Cyber Threat Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--generate", action="store_true",
        help="Generate demo traffic PCAP only",
    )
    parser.add_argument(
        "--pcap", type=str, default=None,
        help="Path to PCAP file to analyze",
    )
    parser.add_argument(
        "--serve", action="store_true",
        help="Start API server + dashboard only",
    )

    args = parser.parse_args()

    if args.generate:
        cmd_generate()
        return

    if args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            logger.error("PCAP file not found: %s", pcap_path)
            sys.exit(1)
        cmd_analyze(pcap_path)
        return

    if args.serve:
        cmd_serve()
        return

    # Default: generate traffic, analyze, then serve
    logger.info("🚀 SIH Cyber Threat Detection — Full Demo")
    logger.info("=" * 60)

    # Step 1: Generate traffic
    pcap_path = cmd_generate()

    # Step 2: Analyze
    cmd_analyze(pcap_path)

    # Step 3: Serve dashboard
    logger.info("")
    logger.info("Starting dashboard server...")
    cmd_serve()


if __name__ == "__main__":
    main()
