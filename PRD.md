# Product Requirements Document
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Team size:** 6 | **Timeline:** Aug 28 – Sep 3 (6 days) | **Track:** Smart India Hackathon (Internal Round)

---

## 1. Problem Framing

A monitoring enclave receives traffic through a **one-way tap** (data diode / passive mirror). It can see everything, touch nothing:

- No return path to source or destination
- No handshakes, no active probing
- No inline blocking or mitigation commands
- No payload decryption — TLS/QUIC must be read from metadata only

The system's only output is **intelligence**: labelled, scored, evidenced alerts on a dashboard. This is a passive detection system, not an IPS.

**Why this constraint matters for design:** every feature must be derivable from something a diode can *see* — packet headers, flow records (NetFlow/IPFIX/sFlow), TLS handshake metadata, DNS query strings, timing. Nothing that requires querying the source, resolving a domain yourself, or completing a TCP handshake as a participant.

---

## 2. Goal & Non-Goals

**Goal:** A streaming pipeline that ingests simulated one-directional IP traffic, extracts features per flow, classifies against 6 threat categories, and emits structured alerts to a live dashboard — within a stated, demonstrated throughput bound.

**Non-goals (explicitly out of scope for this prototype):**
- Any active response, blocking, or mitigation
- Payload inspection or decryption
- Production-grade scale (we state a modest, honestly-tested throughput number, not a marketing number)
- Perfect accuracy — a well-reasoned, evidenced false-positive rate beats an unexplainable 99%

---

## 3. Scope Decision — Read This First

Six days, six people, six threat classes, a streaming pipeline, and a dashboard is a lot. Trying to build all six detectors to equal depth in 6 days risks a demo where nothing works well. Recommended scoping strategy:

**Tier 1 — build to a solid, demo-ready standard (4 classes):**
1. Volumetric/protocol DDoS (SYN flood, UDP amplification) — statistical, no ML training data needed, fast to build, very demoable
2. Reconnaissance/port scanning — same: rule+statistical, fast, reliable
3. Botnet C2 beaconing — periodicity analysis, moderately fast to build, high "wow factor"
4. DGA domains / DNS tunnelling — entropy/n-gram on DNS names, classic and well-documented approach

**Tier 2 — build if time allows, else present as "designed, partially implemented" (2 classes):**
5. Malware in encrypted sessions (JA3/JA4 + timing) — valuable but fingerprint-DB dependent; can be stubbed with a small curated JA3 blocklist + timing anomaly as a fallback
6. Data exfiltration — asymmetric byte-ratio detection; actually simple to implement (just a threshold+ML classifier on flow stats), can likely fold into Tier 1 if time allows

This tiering is a **recommendation** — flag if your team wants to attempt all 6 at equal depth instead; I'll adjust the plan.

---

## 4. Recommended Tech Stack

| Layer | Choice | Why |
|---|---|---|
| Traffic generation | `hping3`, `Slowloris`, `dnscat2`/`iodine`, `iperf3`, DGArchive samples | Given in problem statement's dataset link |
| Packet/flow capture | `tshark`/`scapy` for PCAP → flow records; or synthetic NetFlow/IPFIX generation directly | Avoids needing real diode hardware — you simulate the "one-way" property in software by only ever reading, never writing back |
| Streaming backbone | **Python + a lightweight queue (Redis Streams or simple asyncio queue)** rather than Kafka/Spark | Kafka/Spark add real setup overhead for a 6-day build; Redis Streams or even an in-process async pipeline hits the "streaming, not batch" requirement without the ops burden. Reassess only if someone on the team already knows Kafka well. |
| Feature extraction | Python (`scapy`, `dpkt`, pandas for batching windows) | Team likely already fluent in Python (per your GenAI coursework) |
| ML models | Mix of **statistical/rule-based** (entropy, z-score, fan-out counts) + **lightweight ML** (Isolation Forest, Random Forest, or a small XGBoost) per threat class — avoid deep learning given the timeline | Classical ML trains fast, is explainable (important for "supporting evidence" requirement), and is defensible in Q&A |
| Alert store | SQLite or Postgres (simple schema) | No need for anything heavier at this scale |
| Dashboard | **FastAPI + a simple React or even server-rendered HTML/Chart.js frontend**, polling or WebSocket for live updates | Fast to stand up, matches "live or replayed detections" requirement |
| Repo/docs | GitHub repo + README with architecture diagram, model docs, training/validation notes | Explicitly required deliverable |

If your team already has strong Kafka/Spark experience, that's a legitimate alternative for the streaming layer — flag it and I'll adjust.

---

## 5. System Architecture

```
[Traffic Generators]  →  [PCAP / Flow Export]  →  [Ingest Layer (read-only)]
                                                          │
                                                          ▼
                                              [Feature Extraction (per-flow, windowed)]
                                                          │
                                                          ▼
                                        [Per-threat-class Detectors] ──┐
                                        (DDoS / Scan / C2 / DGA /      │
                                         TLS-metadata / Exfil)         │
                                                          │            │
                                                          ▼            │
                                              [Alert Schema Normalizer]│
                                                          │            │
                                                          ▼            │
                                            [Alert Store + API] ◄──────┘
                                                          │
                                                          ▼
                                              [Dashboard: live feed,
                                               severity, confidence,
                                               evidence drill-down]
```

**Key architectural rule to bake in from day one:** the ingest layer should be built so it *physically cannot* write back — e.g., it reads from a file/socket in one direction only, with no client socket ever opened back toward the traffic source. This isn't just a policy — demonstrate it in the code structure (e.g., ingest module has no outbound network calls at all, verifiable by code review).

---

## 6. Alert Schema (standardized, per requirement 5e)

```json
{
  "alert_id": "uuid",
  "timestamp": "ISO8601",
  "flow_id": "src_ip:src_port-dst_ip:dst_port-proto",
  "threat_class": "ddos | c2_beaconing | dga_dns | encrypted_malware | recon_scan | exfiltration",
  "confidence": 0.0-1.0,
  "severity": "low | medium | high | critical",
  "evidence": {
    "features_triggered": ["..."],
    "supporting_stats": { "...": "..." }
  },
  "detector_version": "string"
}
```

---

## 7. Per-Threat Detection Approach (feature summary)

| Threat | Key features | Approach |
|---|---|---|
| DDoS | flow rate/sec, source-IP entropy, SYN/ACK ratio, packet-size uniformity | Statistical thresholds + entropy scoring |
| Port scan / recon | distinct-dst-ports-per-src in window, distinct-dst-hosts-per-src, low bytes/flow | Fan-out counting + threshold |
| C2 beaconing | inter-arrival time variance, destination-set size, periodicity (FFT or autocorrelation on timestamps) | Periodicity/regularity scoring |
| DGA / DNS tunnelling | domain name entropy, n-gram likelihood vs. dictionary corpus, query length, TXT/NULL record ratio | Entropy + lightweight n-gram classifier |
| Encrypted malware | JA3/JA4 fingerprint match against curated bad list, packet-size/timing sequence anomaly | Fingerprint lookup + sequence anomaly model |
| Exfiltration | outbound:inbound byte ratio, sustained asymmetric flow duration, destination rarity | Ratio thresholds + Isolation Forest on flow stats |

---

## 8. Throughput Target (requirement 5d)

Must be **stated and demonstrated**, not assumed. Recommendation: pick a modest, honest number early (e.g., "sustained X flows/sec on a single-core Python process" or "Y Mbps replayed PCAP"), benchmark it on day 4-5, and report the actual measured number in the README — reviewers will respect a real tested number over an inflated claim.

---

## 9. Team Allocation (6 people)

| Role | Focus | Suggested owner count |
|---|---|---|
| Traffic generation & dataset prep | Set up hping3/Slowloris/dnscat2/DGArchive traffic, produce labeled benign+attack PCAPs | 1 |
| Ingest + feature extraction pipeline | Build the read-only streaming ingest and windowed feature extraction | 1-2 |
| Detection models (DDoS + recon) | Statistical detectors, fastest to deliver | 1 |
| Detection models (C2 + DGA/DNS) | Periodicity + entropy/n-gram detectors | 1 |
| Detection models (TLS-metadata + exfil), if time allows | Tier 2 detectors | 1 |
| Dashboard + alert API + docs | FastAPI backend, frontend, README, architecture diagram | 1-2 |

Adjust based on actual skill distribution across the six of you — happy to help re-split if you tell me who's strong at what (backend, ML, frontend, networking).

---

## 10. Day-by-Day Plan (Aug 28 → Sep 3)

| Day | Focus |
|---|---|
| **Day 1 (Aug 28)** | Finalize scope/tiering, assign roles, set up repo, generate first batch of benign + attack traffic (DDoS, scan) |
| **Day 2 (Aug 29)** | Build ingest + flow feature extraction skeleton; start DDoS/recon detectors (statistical) |
| **Day 3 (Aug 30)** | Finish DDoS/recon detectors; start C2 beaconing + DGA/DNS detectors; alert schema + store wired up |
| **Day 4 (Aug 31)** | Finish C2 + DGA detectors; start dashboard (live feed view); begin Tier 2 detectors if on schedule |
| **Day 5 (Sep 1)** | Dashboard polish (severity/confidence/evidence drill-down); throughput benchmarking; integration testing end-to-end |
| **Day 6 (Sep 2)** | Bug fixes, README + architecture diagram + model/training documentation, record demo/replay dataset, rehearse presentation |
| **Buffer (Sep 3)** | Final polish, submission |

---

## 11. Deliverables Checklist

- [ ] Source repository with ingest → feature extraction → inference → alert output pipeline
- [ ] Documentation: models used, features engineered, training/validation approach
- [ ] Working dashboard (live or replayed) with severity + confidence per alert
- [ ] Stated and demonstrated throughput number
- [ ] Standardized alert schema in use throughout
- [ ] Evidence in code/docs that ingest is architecturally one-way (no return path)

---

## 12. Open Questions for the Team

- Which 2 Tier-1 threat classes should each ML-focused pair own first?
- Real hardware diode simulation, or is a strictly-read-only software boundary (file/pipe, no outbound sockets) acceptable for the demo? (Recommendation: the latter — sufficient for prototype, and it's what the "expected solution" describes.)
- Any existing team experience with Kafka/Spark that would change the streaming-layer recommendation?
