# Project Data & Sources Specification
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

> **System Profile:** Unidirectional Optical Data Diode Network Sensor  
> **Operational Constraint:** Physical one-way optical fiber tap (Rx-only, zero outbound transmission, zero packet decryption)  
> **Standard:** Smart India Hackathon (SIH) Cybersecurity Technical Blueprint  

---

## 1. Executive Summary

This project analyzes unidirectional IP traffic passively tapped from an optical data diode to detect cyber threats in real time without active probing, handshake completion, or TLS payload decryption. 

The project's data architecture is structured across four layers:
1. **Raw Network Packet Captures (PCAPs):** Ground-truth network streams simulating benign background traffic and active cyberattacks across 6 threat vectors.
2. **Machine Learning Training & Language Corpora:** Curated legitimate domain registries, DGA malware algorithms, and baseline enterprise network flow distributions.
3. **Threat Intelligence Signatures:** Curated cryptographic TLS ClientHello fingerprints (JA3).
4. **Normalized Output Alert Data:** An SQLite alert repository storing structured, mathematically evidenced SOC alerts mapped to MITRE ATT&CK.

---

## 2. Primary Network Datasets (`traffic/samples/`)

All raw network traces are stored in the [`traffic/samples/`](file:///Users/pritthacker/SIH/traffic/samples/) directory. These files represent standard PCAP captures generated using the project's traffic engine ([`traffic/generators/generate_traffic.py`](file:///Users/pritthacker/SIH/traffic/generators/generate_traffic.py)) with realistic packet timing, protocol headers, and IP diversity:

| PCAP File | File Size | Traffic Composition & Simulated Threat Vector | Target Scenarios |
|---|---|---|---|
| [`demo_traffic.pcap`](file:///Users/pritthacker/SIH/traffic/samples/demo_traffic.pcap) | **~948 KB** | **Master Multi-Threat Benchmark:** Injects standard benign background traffic (HTTP/S web browsing and recursive DNS queries) mixed with all 6 threat vectors across multiple subnets. | Full pipeline evaluation & live dashboard demonstration |
| [`exfil_training_benign.pcap`](file:///Users/pritthacker/SIH/traffic/samples/exfil_training_benign.pcap) | **~16.9 MB** | **Enterprise Baseline Traffic:** Large-scale benign enterprise traffic capturing normal bidirectional-simulated flows, background cloud API telemetry, software updates, and large file downloads. | Unsupervised baseline density calibration |
| [`simulate_ddos.pcap`](file:///Users/pritthacker/SIH/traffic/samples/simulate_ddos.pcap) | **~619 KB** | **Volumetric & Protocol DDoS:** High-rate SYN flood bursts (>100 flows/sec) targeting `10.0.0.1` and DNS UDP amplification floods (1,400-byte packets) targeting `10.0.0.2`. | `ddos` detector |
| [`simulate_recon_scan.pcap`](file:///Users/pritthacker/SIH/traffic/samples/simulate_recon_scan.pcap) | **~261 KB** | **Reconnaissance & Subnet Sweeps:** Horizontal TCP port sweeps across 60 sequential ports (`192.168.1.100` → `10.0.0.1`) and vertical host sweeps across 35 subnet hosts on port 22 (`10.0.0.1`–`35`). | `recon_scan` detector |
| [`simulate_c2_beaconing.pcap`](file:///Users/pritthacker/SIH/traffic/samples/simulate_c2_beaconing.pcap) | **~270 KB** | **Botnet C2 Beaconing:** Strictly periodic callback intervals (16.0s and 22.0s intervals, low jitter CoV < 0.05) from internal workstations to external Command & Control IPs. | `c2_beaconing` detector |
| [`simulate_dga_dns.pcap`](file:///Users/pritthacker/SIH/traffic/samples/simulate_dga_dns.pcap) | **~251 KB** | **DGA Lookups & DNS Tunnels:** High-entropy algorithmically generated pseudo-random domain queries alongside covert DNS tunneling channels utilizing base16/hex data chunks inside TXT records (`*.t.evil-tunnel.com`). | `dga_dns` detector |
| [`simulate_exfiltration.pcap`](file:///Users/pritthacker/SIH/traffic/samples/simulate_exfiltration.pcap) | **~531 KB** | **Asymmetric Data Exfiltration:** Long-duration sustained outbound data dumps exceeding 100 packets with 1,400-byte payloads (MTU saturation) to external staging servers (`198.51.100.77` and `203.0.113.99`). | `exfiltration` detector |

---

## 3. Data Sources & Modeling Toolchains

The datasets and models in this project derive from the following official sources, tools, and repositories:

### A. Traffic Generation Toolchain (Per PRD §4)
Per the technical problem requirements, real-world attack signatures were modeled after industry-standard adversary and network testing tools:
* **`hping3`:** Volumetric TCP SYN packet flooding patterns.
* **`Slowloris`:** Low-and-slow application-layer connection exhaustion patterns.
* **`dnscat2` & `iodine`:** DNS query encapsulation protocols used to craft TXT and NULL record covert exfiltration channels.
* **`nmap`:** TCP SYN stealth scan timing and port/host iteration sequences.
* **`iperf3`:** Maximum transmission unit (MTU) saturating outbound data streaming profiles.
* **`Scapy` Packet Synthesizer:** Packets are programmatically assembled using Python's `scapy` engine ([`traffic/generators/generate_traffic.py`](file:///Users/pritthacker/SIH/traffic/generators/generate_traffic.py)) with monotonic timestamps.

---

### B. Machine Learning Training Corpora

#### 1. DGA Lexical & Language Corpora ([`src/models/train_dga.py`](file:///Users/pritthacker/SIH/src/models/train_dga.py))
Used to train the supervised `RandomForestClassifier` ([`models/dga_rf_model.joblib`](file:///Users/pritthacker/SIH/models/dga_rf_model.joblib)):
* **Legitimate Domain Corpus ($y = 0$):** High-reputation domains sampled from the **Tranco / Alexa Top 1M List** (e.g., `google.com`, `wikipedia.org`, `github.com`, `microsoft.com`, `cloudflare.com`, `amazon.com`, `stackoverflow.com`).
* **Malicious DGA Corpus ($y = 1$):** Domain patterns sourced from academic repositories (**DGArchive**) representing active malware families (Conficker, Necurs, Torpig, Suppobox, Murofet).
* **English Bigram Transition Matrix:** Normalized empirical probability distribution of English 2-character sequences ($\mathcal{B}$) used to calculate domain log-likelihood:
  $$\text{LL}(\text{domain}) = \frac{1}{|ngrams|} \sum_{i=1}^{k} \log_2 P(b_i \mid \mathcal{B})$$

#### 2. Enterprise Flow Baseline Corpus ([`src/models/train_exfil_iforest.py`](file:///Users/pritthacker/SIH/src/models/train_exfil_iforest.py))
Used to train the unsupervised `IsolationForest` anomaly model ([`models/isolation_forest_exfil.joblib`](file:///Users/pritthacker/SIH/models/isolation_forest_exfil.joblib)):
* **Baseline Normal Enterprise Flows ($n = 1,500$):**
  * $45\%$ Web browsing (HTTP/HTTPS client requests with high reverse payload density).
  * $25\%$ DNS resolution queries (sub-second duration, low byte count).
  * $15\%$ Cloud API calls and telemetry heartbeats.
  * $10\%$ Inbound file downloads (reverse-asymmetric, inbound-heavy).
  * $5\%$ Internal microservice RPC exchanges.
* **Exfiltration Outliers ($n = 300$):** Anomalous outbound flows with payload density $> 0.80$, average packet payload $> 1,200$ bytes, and prolonged duration.

---

### C. Threat Intelligence & Signature Repositories

#### 1. JA3 TLS Fingerprint Blocklist ([`models/ja3_blocklist.csv`](file:///Users/pritthacker/SIH/models/ja3_blocklist.csv))
Curated cryptographic ClientHello MD5 hashes based on the **Salesforce JA3 open-source standard** and **abuse.ch SSL Blacklist (SSLBL)**:
* `e7d705a3286e19ea42f587b344ee6865` — **Trickbot** Banking Trojan
* `6734f37431670b3ab4292b8f60f29984` — **AsyncRAT** Remote Access Trojan
* `72a589da586844d7f0818ce684948eea` — **Metasploit** Meterpreter Stager
* `a0e9f5d64349fb13191bc781f81f42e1` — **CobaltStrike** Malleable C2 Beacon
* `b32309a26951912be7dba376398abc3b` — **Emotet** Malware Distribution Engine

---

### D. Cyber Threat Taxonomy & SOC Knowledge Sources

#### 1. MITRE ATT&CK Matrix Mapping ([`src/alert/mitre.py`](file:///Users/pritthacker/SIH/src/alert/mitre.py))
Every threat classification is linked to MITRE ATT&CK Enterprise techniques:
* **DDoS:** `T1498.001` (Network Denial of Service: Direct Network Flood)
* **Reconnaissance:** `T1595.001` (Active Scanning: Scanning IP Blocks)
* **C2 Beaconing:** `T1071.001` (Application Layer Protocol: Web Protocols)
* **DGA / DNS Tunnel:** `T1568.002` (Dynamic Resolution: Domain Generation Algorithms) & `T1071.004` (DNS)
* **Encrypted Malware:** `T1573.002` (Encrypted Channel: Asymmetric Cryptography)
* **Data Exfiltration:** `T1048.003` (Exfiltration Over Alternative Protocol)

#### 2. SOC AI Copilot / Incident Response Engine ([`src/api/triage.py`](file:///Users/pritthacker/SIH/src/api/triage.py))
* **Primary Engine:** LLaMA-3.3-70B-Versatile via Groq Cloud API for contextual security runbooks.
* **Air-Gapped Fallback:** Offline deterministic rule-based SOC SOP generator designed for air-gapped data diode enclaves.

---

## 4. Pipeline Input/Output Data Schemas

### A. Raw Flow Feature Extraction Schema ([`src/features/extractor.py`](file:///Users/pritthacker/SIH/src/features/extractor.py))
The ingest engine parses incoming packets via `dpkt` and groups them into 5-tuple flow records:
$$\text{flow\_id} = \text{src\_ip}:\text{src\_port}-\text{dst\_ip}:\text{dst\_port}-\text{proto}$$

Key feature dimensions extracted without payload decryption:
1. `syn_ack_ratio` & `packet_size_uniformity` (DDoS)
2. `distinct_dst_ports` & `distinct_dst_hosts` (Reconnaissance)
3. `inter_arrival_time_variance`, `autocorrelation`, & `fft_peak_freq` (C2 Beaconing)
4. `shannon_entropy`, `ngram_likelihood`, & `txt_null_ratio` (DGA / DNS Tunnels)
5. `ja3_fingerprint` (Encrypted TLS Malware)
6. `egress_payload_density` & `outbound_inbound_byte_ratio` (Exfiltration)

### B. Output Alert Storage Schema ([`alerts.db`](file:///Users/pritthacker/SIH/alerts.db))
Alerts are stored in SQLite conforming to PRD §6:
```sql
CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    flow_id TEXT NOT NULL,
    threat_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    severity TEXT NOT NULL,
    evidence TEXT NOT NULL,       -- JSON object of mathematical supporting stats
    detector_version TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 5. Summary of Key File Links

* **Data Directory:** [`traffic/samples/`](file:///Users/pritthacker/SIH/traffic/samples/)
* **Traffic Generator:** [`traffic/generators/generate_traffic.py`](file:///Users/pritthacker/SIH/traffic/generators/generate_traffic.py)
* **DGA Training Script:** [`src/models/train_dga.py`](file:///Users/pritthacker/SIH/src/models/train_dga.py)
* **Exfiltration Training Script:** [`src/models/train_exfil_iforest.py`](file:///Users/pritthacker/SIH/src/models/train_exfil_iforest.py)
* **JA3 Blocklist:** [`models/ja3_blocklist.csv`](file:///Users/pritthacker/SIH/models/ja3_blocklist.csv)
* **Model Cards Documentation:** [`docs/model_cards.md`](file:///Users/pritthacker/SIH/docs/model_cards.md)
* **Architecture Documentation:** [`docs/architecture.md`](file:///Users/pritthacker/SIH/docs/architecture.md)
* **Alert Storage Database:** [`alerts.db`](file:///Users/pritthacker/SIH/alerts.db)
