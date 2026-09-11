# Model Documentation & Detection Cards

## Overview of Detectors

The detection framework combines statistical rule-based engines, frequency-domain signal analysis, and lightweight machine learning models (Isolation Forests, XGBoost / Random Forests) to provide transparent, explainable alerts.

---

### 1. Volumetric / Protocol DDoS (`ddos`)
- **Category:** Tier 1 (Production Ready)
- **Techniques:** Flow arrival rates, Source IP Shannon Entropy, SYN/ACK packet ratio, packet size uniformity.
- **Evidence Emitted:** Flow rate (flows/sec), IP entropy score, dominant packet length distribution.
- **Thresholds:** Flagged when flow arrival rate exceeds 1,000 flows/sec with low source IP entropy (< 0.5) or anomalous SYN packet dominance.

---

### 2. Reconnaissance & Port Scanning (`recon_scan`)
- **Category:** Tier 1 (Production Ready)
- **Techniques:** Unique destination IP/port fan-out ratios, low byte-per-flow ratios, SYN without payload patterns.
- **Evidence Emitted:** Distinct port count, target IP fan-out cardinality, average bytes per flow.
- **Thresholds:** Horizontal sweeps flagged when > 20 distinct targets hit within a window; vertical scans flagged when > 30 ports probed on a single target.

---

### 3. Botnet C2 Beaconing (`c2_beaconing`)
- **Category:** Tier 1 (Production Ready)
- **Techniques:** Fast Fourier Transform (FFT) spectral peak detection, autocorrelation coefficient calculation, inter-arrival time (IAT) coefficient of variation.
- **Evidence Emitted:** Peak frequency (Hz), beaconing interval estimate (seconds), jitter metric (%).
- **Thresholds:** Regular periodic traffic with coefficient of variation (CoV) < 0.15 and strong autocorrelation (> 0.7) trigger high-confidence C2 beaconing alerts.

---

### 4. DGA Domains & DNS Tunnelling (`dga_dns`)
- **Category:** Tier 1 (Production Ready)
- **Techniques:** English bigram log-likelihood scoring, character-level Shannon entropy, subdomain label depth, query length distribution.
- **Evidence Emitted:** Domain entropy (bits), n-gram log-likelihood score, query payload length.
- **Thresholds:** Domain names with Shannon entropy > 3.8 bits and bigram likelihood < -9.0 or base64-encoded subdomains (> 50 chars) flagged as DGA / Exfil tunnel.

---

### 5. Encrypted Malware Sessions (`encrypted_malware`)
- **Category:** Tier 2 (Designed & Stubbed)
- **Techniques:** JA3/JA4 TLS handshake metadata hashing, packet timing sequences, initial burst bytes.
- **Evidence Emitted:** Observed JA3 hash, known malicious fingerprint match, timing anomaly score.

---

### 6. Data Exfiltration (`exfiltration`)
- **Category:** Tier 2 (Functional Heuristic Classifier)
- **Techniques:** Outbound/Inbound volume asymmetry ratios, long-duration flow byte accumulation, anomalous egress transfer rates.
- **Evidence Emitted:** Total bytes egressed, transfer duration, byte ratio (out/in).
- **Thresholds:** Flow transfers exceeding 50x asymmetric outbound byte ratio without corresponding service patterns.
