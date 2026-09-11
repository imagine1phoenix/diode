# Development Rules — AI-Based Cyber Threat Detection (SIH)

> **Purpose:** These rules are the source of truth for all implementation decisions.
> Every line of code, every design choice, and every library import must be
> traceable back to the [PRD](file:///Users/pritthacker/SIH/PRD.md).
> If the PRD does not mention it, do **not** invent it.

---

## R0 — Golden Rule

> **Build only what the PRD specifies. When in doubt, leave it out.**
>
> - Do NOT add features, libraries, abstractions, or threat classes beyond what the PRD lists.
> - Do NOT assume capabilities the unidirectional constraint forbids.
> - Do NOT use placeholder / mock implementations and call them "done." If a feature is stubbed, it must be explicitly labelled as Tier 2 / partial.

---

## R1 — Unidirectional Constraint (PRD §1, §5)

These rules are **non-negotiable**. They define the physical reality of the system.

| # | Rule |
|---|------|
| R1.1 | The ingest layer **MUST NOT** contain any outbound network calls — no sockets opened back toward a traffic source, no DNS resolution, no HTTP requests to external services during live analysis. |
| R1.2 | No return path: no TCP RSTs, no ICMP unreachable, no active probing, no handshakes initiated by our system. |
| R1.3 | No payload decryption. TLS/QUIC traffic is analysed **only** via metadata: JA3/JA4 fingerprints, certificate fields visible in the ClientHello, packet sizes, timing. |
| R1.4 | No inline blocking, dropping, or mitigation. The system's **only output** is structured alerts to the dashboard. |
| R1.5 | The one-way property must be **architecturally demonstrable** in code — the ingest module reads from a file/pipe/socket in one direction only. This must be verifiable by code review and called out in documentation. |

---

## R2 — Scope & Tiering (PRD §3)

| # | Rule |
|---|------|
| R2.1 | **Tier 1 (must ship, demo-ready):** DDoS, Reconnaissance/Port Scan, C2 Beaconing, DGA/DNS Tunnelling — exactly these 4. |
| R2.2 | **Tier 2 (build if time, else "designed, partially implemented"):** Encrypted Malware (JA3/JA4), Data Exfiltration. |
| R2.3 | Do NOT add a 7th threat class. Do NOT rename or redefine the 6 classes. The `threat_class` enum is fixed: `ddos`, `c2_beaconing`, `dga_dns`, `encrypted_malware`, `recon_scan`, `exfiltration`. |
| R2.4 | Tier 2 stubs must clearly state they are stubs — no pretending a stub is a complete detector. |

---

## R3 — Tech Stack (PRD §4)

Only the following technologies are approved. Do NOT substitute without explicit team approval.

| Layer | Approved Choice | Forbidden Alternatives |
|---|---|---|
| Traffic generation | `hping3`, `Slowloris`, `dnscat2`/`iodine`, `iperf3`, DGArchive samples | Do not use custom traffic generators unless wrapping these tools |
| Packet/flow capture | `tshark`, `scapy`, synthetic NetFlow/IPFIX | Do not introduce `tcpdump` wrappers or custom C capture agents |
| Streaming backbone | Python + Redis Streams **or** `asyncio` queue | **No Kafka, No Spark** unless a team member has proven prior experience (must be flagged and approved) |
| Feature extraction | Python: `scapy`, `dpkt`, `pandas` | No PySpark, no Dask, no Polars (unnecessary complexity) |
| ML models | Statistical/rule-based (entropy, z-score, fan-out) + lightweight ML (Isolation Forest, Random Forest, XGBoost) | **No deep learning** (no PyTorch, no TensorFlow, no neural networks) — timeline does not allow it |
| Alert store | SQLite **or** PostgreSQL | No MongoDB, no Redis as primary store, no Elasticsearch |
| Dashboard backend | FastAPI | No Django, no Flask, no Express |
| Dashboard frontend | React **or** server-rendered HTML + Chart.js | No Next.js, no Vue, no Svelte, no Angular |
| Live updates | Polling **or** WebSocket | No Server-Sent Events unless trivially simpler |

---

## R4 — Alert Schema (PRD §6)

The alert schema is **fixed and standardized**. Every alert emitted by every detector must conform exactly.

```json
{
  "alert_id": "uuid",
  "timestamp": "ISO8601",
  "flow_id": "src_ip:src_port-dst_ip:dst_port-proto",
  "threat_class": "ddos | c2_beaconing | dga_dns | encrypted_malware | recon_scan | exfiltration",
  "confidence": 0.0,
  "severity": "low | medium | high | critical",
  "evidence": {
    "features_triggered": [],
    "supporting_stats": {}
  },
  "detector_version": "string"
}
```

| # | Rule |
|---|------|
| R4.1 | `alert_id` — UUID v4, generated per alert. |
| R4.2 | `timestamp` — ISO 8601 format, always UTC. |
| R4.3 | `flow_id` — must use exact format: `src_ip:src_port-dst_ip:dst_port-proto`. |
| R4.4 | `threat_class` — must be one of the 6 enum values, lowercase, snake_case as shown. |
| R4.5 | `confidence` — float in range [0.0, 1.0]. |
| R4.6 | `severity` — exactly one of: `low`, `medium`, `high`, `critical`. |
| R4.7 | `evidence` — must always be populated. Never emit an alert with empty evidence. An alert without evidence is not an alert — it's noise. |
| R4.8 | `detector_version` — semver string identifying the detector that produced the alert. |
| R4.9 | **No extra fields.** Do not add fields to the schema without PRD amendment. |

---

## R5 — Detection Approaches (PRD §7)

Each detector must use **exactly** the features and approach specified. Do not invent features.

| Threat Class | Required Features | Required Approach | Forbidden |
|---|---|---|---|
| **DDoS** | flow rate/sec, source-IP entropy, SYN/ACK ratio, packet-size uniformity | Statistical thresholds + entropy scoring | No ML for DDoS unless statistical is proven insufficient |
| **Recon/Port Scan** | distinct-dst-ports-per-src in window, distinct-dst-hosts-per-src, low bytes/flow | Fan-out counting + threshold | No ML |
| **C2 Beaconing** | inter-arrival time variance, destination-set size, periodicity (FFT or autocorrelation) | Periodicity/regularity scoring | No DNS-based detection (that's DGA) |
| **DGA/DNS Tunnelling** | domain name entropy, n-gram likelihood vs dictionary, query length, TXT/NULL record ratio | Entropy + lightweight n-gram classifier | No external API calls to resolve domains |
| **Encrypted Malware** (Tier 2) | JA3/JA4 fingerprint match, packet-size/timing sequence anomaly | Fingerprint lookup + sequence anomaly model | No payload decryption |
| **Exfiltration** (Tier 2) | outbound:inbound byte ratio, sustained asymmetric flow duration, destination rarity | Ratio thresholds + Isolation Forest | No DPI |

---

## R6 — Architecture Rules (PRD §5)

| # | Rule |
|---|------|
| R6.1 | The pipeline is strictly linear: `Traffic Generators → PCAP/Flow → Ingest (read-only) → Feature Extraction → Detectors → Alert Normalizer → Alert Store + API → Dashboard`. |
| R6.2 | Each stage must be a **separate, importable Python module** — not a monolithic script. |
| R6.3 | The ingest layer is isolated: it has **no dependency on detection logic** and **no outbound network capability**. |
| R6.4 | All detectors output through a single **Alert Schema Normalizer** — detectors do not write directly to the store. |
| R6.5 | The dashboard reads from the Alert Store via the API — it does not import detection code or ingest code. |

---

## R7 — Project Structure

```
SIH/
├── PRD.md                          # Product requirements (read-only reference)
├── rules.md                        # This file (read-only reference)
├── README.md                       # Architecture diagram, setup, model docs, throughput results
├── requirements.txt                # Pinned Python dependencies
│
├── traffic/                        # Traffic generation scripts & sample PCAPs
│   ├── generators/                 # Wrapper scripts for hping3, slowloris, dnscat2, etc.
│   └── samples/                    # Labelled PCAP/flow files (benign + attack)
│
├── src/
│   ├── ingest/                     # Read-only packet/flow ingestion
│   │   └── __init__.py
│   ├── features/                   # Per-flow & windowed feature extraction
│   │   └── __init__.py
│   ├── detectors/                  # One module per threat class
│   │   ├── __init__.py
│   │   ├── ddos.py
│   │   ├── recon_scan.py
│   │   ├── c2_beaconing.py
│   │   ├── dga_dns.py
│   │   ├── encrypted_malware.py    # Tier 2
│   │   └── exfiltration.py         # Tier 2
│   ├── alert/                      # Alert schema, normalizer, store interface
│   │   └── __init__.py
│   ├── pipeline/                   # Streaming orchestration (asyncio / Redis Streams)
│   │   └── __init__.py
│   └── api/                        # FastAPI application
│       └── __init__.py
│
├── dashboard/                      # Frontend (React or HTML+Chart.js)
│
├── models/                         # Trained model artifacts (joblib/pickle)
│
├── tests/                          # Unit & integration tests
│
└── docs/                           # Architecture diagram, model cards, training notes
```

| # | Rule |
|---|------|
| R7.1 | Follow this structure exactly. Do not flatten, merge, or reorganize without PRD amendment. |
| R7.2 | Every Python package must have an `__init__.py`. |
| R7.3 | No code outside `src/`, `traffic/`, `dashboard/`, and `tests/`. |
| R7.4 | Configuration via environment variables or a single `config.py` / `.env` — no YAML/TOML config frameworks. |

---

## R8 — Quality & Documentation (PRD §8, §11)

| # | Rule |
|---|------|
| R8.1 | **Throughput** must be stated as a real, measured number — not estimated, not assumed. Benchmark on actual hardware, report in README. |
| R8.2 | The README must contain: architecture diagram, model descriptions, feature engineering rationale, training/validation approach, measured throughput, and setup instructions. |
| R8.3 | Every detector module must have a docstring explaining: which features it uses, what thresholds/model it applies, and what evidence it populates. |
| R8.4 | False-positive reasoning beats unexplainable accuracy — document known false-positive scenarios per detector. |
| R8.5 | All ML models must be **explainable** — no black-box models without feature importance. |

---

## R9 — What NOT to Build

> These are explicitly **out of scope** (PRD §2 Non-goals). Implementing any of these is a rule violation.

- ❌ Active response, blocking, or mitigation of any kind
- ❌ Payload inspection or decryption
- ❌ Production-grade scaling infrastructure (Kubernetes, load balancers, etc.)
- ❌ Deep learning models (CNNs, RNNs, transformers, LLMs)
- ❌ Real-time threat intelligence feed integration (external API calls during analysis)
- ❌ User authentication / RBAC on the dashboard (nice-to-have but not in PRD)
- ❌ Automated report generation beyond the alert schema
- ❌ Any 7th+ threat category

---

## R10 — Code Hygiene

| # | Rule |
|---|------|
| R10.1 | Python 3.10+ only. Use type hints on all function signatures. |
| R10.2 | No wildcard imports (`from x import *`). |
| R10.3 | Every module must be independently testable — no hidden global state. |
| R10.4 | Dependencies must be in `requirements.txt` with pinned versions. |
| R10.5 | No print-statement debugging in committed code — use Python `logging` module. |
| R10.6 | All timestamps in UTC. No local timezone handling. |

---

## R11 — AI Assistant Behaviour Rules

> These rules govern how any AI assistant (including this one) must behave when working on this project.

| # | Rule |
|---|------|
| R11.1 | **Always cite the PRD section** when making a design decision. If you can't cite a section, you're probably inventing something. |
| R11.2 | **Never hallucinate libraries.** Only use libraries that exist on PyPI/npm and are listed in the approved tech stack (R3). |
| R11.3 | **Never generate fake data and present it as real results.** If benchmark numbers are needed, write the benchmark script — don't invent numbers. |
| R11.4 | **Never silently change the alert schema.** If a schema change is needed, flag it explicitly as a proposed PRD amendment. |
| R11.5 | **Never implement active responses.** If code can send a packet, open an outbound connection, or modify traffic flow, it violates R1. |
| R11.6 | **Prefer simple over clever.** A readable 20-line detector beats an opaque 5-line one. |
| R11.7 | **Flag scope creep immediately.** If a request goes beyond the PRD, say so before writing any code. |
| R11.8 | **Tier 2 items must be labelled.** Never present Tier 2 detectors as complete without flagging their tier status. |
| R11.9 | **Read `rules.md` and `PRD.md` at the start of every session.** Do not rely on memory of prior sessions. |
| R11.10 | **When unsure, ask.** Do not guess requirements — surface the question to the team. |

---

## Quick Reference: Threat Class Enum

```python
from enum import Enum

class ThreatClass(str, Enum):
    DDOS = "ddos"
    C2_BEACONING = "c2_beaconing"
    DGA_DNS = "dga_dns"
    ENCRYPTED_MALWARE = "encrypted_malware"
    RECON_SCAN = "recon_scan"
    EXFILTRATION = "exfiltration"
```

## Quick Reference: Severity Enum

```python
from enum import Enum

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

---

*Last updated: 2026-09-11 | Derived from [PRD.md](file:///Users/pritthacker/SIH/PRD.md)*
