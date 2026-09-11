# System Architecture

## Overview

The SIH Cyber Threat Detection System is a high-throughput, streaming pipeline designed to ingest simulated unidirectional IP traffic (such as from a hardware data diode or passive network tap), extract per-flow statistical and behavioral features, classify threats across 6 distinct categories, and emit standardized, evidenced alerts to a live web dashboard.

```mermaid
flowchart TD
    subgraph Traffic["Traffic Ingestion (Read-Only)"]
        GEN[Traffic Generators / PCAP Source] -->|Simulated Diode Tap| RDR[PCAP / Stream Reader]
        RDR --> FA[Flow Assembler (5-Tuple + State)]
    end

    subgraph FeaturePipeline["Feature Extraction (Sliding Windows)"]
        FA --> EXT[Feature Extractor]
        EXT --> ENT[Entropy Engine (IPs, Domains)]
        EXT --> PER[Periodicity Engine (FFT, Autocorr)]
        EXT --> STAT[Statistical Metrics (Fan-out, Asymmetry)]
    end

    subgraph Detectors["Per-Threat Detection Engines"]
        EXT --> D1[DDoS Detector]
        EXT --> D2[Recon & Scan Detector]
        EXT --> D3[Botnet C2 Beaconing Detector]
        EXT --> D4[DGA & DNS Tunnel Detector]
        EXT --> D5[Encrypted Malware Classifier]
        EXT --> D6[Data Exfiltration Detector]
    end

    subgraph Alerting["Alert Normalization & Storage"]
        D1 & D2 & D3 & D4 & D5 & D6 --> NORM[Alert Schema Normalizer]
        NORM --> STORE[(SQLite / Postgres Alert Store)]
    end

    subgraph Presentation["API & Live Dashboard"]
        STORE --> API[FastAPI Server]
        API -->|WebSocket Stream| DASH[Web Dashboard (Chart.js & Live Feed)]
        API -->|REST Query / Filtering| DASH
    end
```

## Architectural Isolation (rules.md R1)

Per problem constraints, the ingestion engine operates behind a simulated data diode:
1. **No Outbound Network Sockets**: The `src/ingest` module contains no socket client or HTTP client libraries.
2. **Read-Only Data Flow**: Traffic is read strictly in a unidirectional manner; no responses, ACKs, or handshakes are ever generated towards the source.
3. **AST-Enforced Isolation**: An automated AST unit test (`tests/test_ingest_isolation.py`) continuously scans the ingest codebase to guarantee no outbound networking capabilities are introduced.
