# Changelog

All notable changes to the **diode** (AI-Based Detection of Cyber Threats in Unidirectional IP Traffic) project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-09-11

### Added
- **Unsupervised Isolation Forest Exfiltration Detector**: Implemented flow matrix extraction and unsupervised outlier detection for high-volume, anomalous egress transfers (`src/detectors/exfiltration.py`, `models/exfil_isolation_forest.joblib`).
- **Tactical SOC Interface (NET-DRISHTI)**: High-contrast operator UI with Tactical White Card design, dedicated MITRE ATT&CK badges, live alert counters, and explainability pills.
- **Air-Gapped Copilot SLM Engine**: Added local heuristic triage and on-premise Small Language Model (SLM) fallback for multi-turn tactical Q&A and incident mitigation runbooks (`src/api/triage.py`, `/api/copilot/chat`).
- **Voice Audit Assist**: Integrated Web Speech API synthesized audio readouts for immediate, hands-free SOC operator incident notifications.
- **Pipeline Inspector Modal**: Interactive step-by-step telemetry visualizer demonstrating optical diode Rx isolation, sliding-window flow assembly, FFT spectral calculation, and Pydantic alert validation.
- **Comprehensive Model Cards**: Published technical cards for the DGA Random Forest classifier and Exfiltration Isolation Forest model (`models/MODEL_CARD_EXFIL_ISOLATION_FOREST.md`, `docs/model_cards.md`).

### Changed
- **Exfiltration Feature Honesty**: Refactored `outbound_inbound_byte_ratio` to compute bidirectional ratios on full-duplex/SPAN taps while providing fallback proxies (`mean_payload_bytes_proxy`, `egress_payload_density`) when return traffic is physically absent on simplex optical taps.
- **DGA Alert Deduplication**: Consolidated bursts of algorithmically generated domain queries per host into single windowed incident alerts.
- **API Performance**: Configured strict cache-control (`no-store, no-cache`) headers on root dashboard endpoints to prevent browser stale-bundle caching.

### Fixed
- Fixed missing `BaseModel` import in `src/api/main.py` causing ASGI server reload failures.
- Fixed Scapy packet timestamp staggering in synthetic attack generators to ensure monotonic flow progression.

---

## [1.1.0] - 2026-09-10

### Added
- **Supervised DGA Random Forest Model**: Trained on 10,000+ legitimate domains and algorithmic malware domains (Conficker, Cryptolocker, GameOver Zeus).
- **Fast Fourier Transform (FFT) C2 Beaconing Engine**: Spectral density peak analysis and autocorrelation to identify persistent command-and-control callbacks with low jitter.
- **Live Attack Simulator**: Interactive UI trigger (`/api/simulate`) injecting multi-vector synthetic attacks into the live pipeline.
- **JA3/JA4 TLS Fingerprint Blocklist**: Handshake metadata parser identifying malicious Cobalt Strike, TrickBot, and Emotet client hellos.

### Changed
- Streamlined Pydantic V2 schema validation and normalizer pipeline.
- Replaced Scapy reader hot path with high-throughput `dpkt` binary frame parser (>100,000 pkts/sec).

---

## [1.0.0] - 2026-09-08

### Added
- Initial release of the Unidirectional IP Threat Detection Enclave.
- Core pipeline: Read-only PCAP ingestion, 5-tuple flow assembler with temporal sliding window eviction.
- Physical diode architectural proof: Automated AST code scanner (`tests/test_ingest_isolation.py`) ensuring zero outbound network sockets.
- 6 Threat Detectors: Volumetric DDoS, Reconnaissance & Port Scans, C2 Beaconing, DGA DNS Tunneling, Encrypted Malware, and Data Exfiltration.
- Alert Store with SQLite WAL mode persistence.
- FastAPI backend serving REST endpoints and `/ws` live WebSocket stream.
- React + Vite dashboard with Chart.js visualization widgets.
