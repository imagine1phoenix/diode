# Threat Detection Engine — Model Cards & Specifications

## Overview of Detection Philosophy

Per **PRD §4 & rules.md R3**, detection combines **statistical flow heuristics**, **frequency-domain signal analysis**, and **explainable machine learning** (Isolation Forests, XGBoost) rather than unexplainable deep learning:
- **Zero Black Boxes:** In high-consequence cyber defense (data diodes, critical national infrastructure), every alert must provide mathematical supporting evidence for SOC triaging.
- **Microsecond Latency:** Detection algorithms operate in streaming sliding windows without heavy GPU inference overhead.

---

## Model Card 1: Volumetric & Protocol DDoS (`ddos`)

- **Classification Tier:** Tier 1 (Production Ready)
- **Problem Statement:** Detect SYN floods, UDP amplification, and volume-based denial of service across a passive unidirectional tap.
- **Mathematical Methodology:**
  1. **Flow Arrival Rate ($R_f$):** Evaluated over a 10-second sliding window. Flagged when $R_f > 1,000 \text{ flows/s}$.
  2. **Source IP Shannon Entropy ($H_{src}$):**
     $$H_{src} = -\sum_{i=1}^{k} p(ip_i) \log_2 p(ip_i)$$
     Low entropy ($H_{src} < 0.5$) indicates single-source or small-subnet flooding; high rate with moderate entropy indicates distributed floods.
  3. **SYN/ACK Flag Ratio:** In unidirectional traffic, we observe outbound SYN packets. An overwhelming ratio of SYN-only packets with zero payload indicates SYN flood exhaustion attacks.
  4. **Packet Size Uniformity:** Standard deviation of packet byte lengths approaches zero in synthetic amplification attacks.
- **Supporting Evidence Emitted:**
  `flow_rate`, `src_ip_entropy`, `syn_ack_ratio`, `pkt_size_uniformity`.

---

## Model Card 2: Reconnaissance & Port Scanning (`recon_scan`)

- **Classification Tier:** Tier 1 (Production Ready)
- **Problem Statement:** Detect horizontal subnet sweeps and vertical port scans before attacks escalate.
- **Mathematical Methodology:**
  1. **Vertical Port Scan Fan-Out ($F_{port}$):** Number of unique destination ports targeted per individual source IP.
     $$\text{Trigger when } |\{dst\_port \mid src\_ip = X\}| \ge 30 \text{ in window}$$
  2. **Horizontal Host Sweep Fan-Out ($F_{host}$):** Number of unique destination IPs targeted on the same service port (e.g. port 22, 445, 3389).
     $$\text{Trigger when } |\{dst\_ip \mid src\_ip = X, dst\_port = P\}| \ge 20 \text{ in window}$$
  3. **Low-Byte Ratio:** Scans consist of TCP SYN probes with negligible payload (< 100 bytes per flow).
- **Supporting Evidence Emitted:**
  `distinct_ports`, `distinct_targets`, `avg_bytes_per_flow`, `scan_type` (vertical/horizontal).

---

## Model Card 3: Botnet C2 Beaconing (`c2_beaconing`)

- **Classification Tier:** Tier 1 (Production Ready)
- **Problem Statement:** Identify compromised hosts checking in with Command & Control (C2) servers over periodic intervals.
- **Mathematical Methodology:**
  1. **Inter-Arrival Time (IAT) Signal:** Sequence of inter-packet timestamps $\Delta t = [t_2 - t_1, t_3 - t_2, \dots]$.
  2. **Fast Fourier Transform (FFT) Spectral Analysis:**
     $$X(f) = \sum_{n=0}^{N-1} \Delta t[n] e^{-j 2\pi f n / N}$$
     Identifies dominant frequency peaks corresponding to automated beacon intervals (e.g. 60s, 300s).
  3. **Autocorrelation Coefficient ($R_{xx}(\tau)$):**
     $$R_{xx}(\tau) = \frac{\sum (x_t - \bar{x})(x_{t+\tau} - \bar{x})}{\sum (x_t - \bar{x})^2}$$
     High autocorrelation ($R_{xx} > 0.7$) indicates strict periodicity.
  4. **Coefficient of Variation (CoV):**
     $$CoV = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}} < 0.15$$
     Low jitter confirms non-human, machine-driven callback schedules.
- **Supporting Evidence Emitted:**
  `peak_frequency_hz`, `estimated_period_sec`, `autocorr_score`, `jitter_cov`.

---

## Model Card 4: DGA Domains & DNS Tunnelling (`dga_dns`)

- **Classification Tier:** Tier 1 (Production Ready)
- **Problem Statement:** Detect Domain Generation Algorithms (DGA) used by malware for resilient C2 and DNS data exfiltration tunnels.
- **Mathematical Methodology:**
  1. **English Bigram Log-Likelihood ($LL_{ngram}$):**
     Scored against a normalized reference frequency table of English bigrams $\mathcal{B}$:
     $$LL(domain) = \frac{1}{|ngrams|} \sum_{i=1}^{k} \log_2 P(b_i \mid \mathcal{B})$$
     Natural domains score near $0$ to $-6$; algorithmically generated domains score $\le -9.0$.
  2. **Character-Level Shannon Entropy ($H_{dom}$):**
     Random DGA subdomains exhibit high character diversity ($H_{dom} > 3.8 \text{ bits}$).
  3. **Subdomain Length & Label Depth:**
     DNS tunnels encoding data in DNS queries exhibit anomalously long subdomain labels (> 50 characters, high hex/base64 ratio).
- **Supporting Evidence Emitted:**
  `domain_entropy`, `ngram_likelihood`, `subdomain_length`, `query_type`.

---

## Model Card 5: Encrypted Malware Sessions (`encrypted_malware`)

- **Classification Tier:** Tier 2 (Heuristic & Fingerprint Matching)
- **Problem Statement:** Flag malware operating inside TLS encrypted channels without breaking decryption.
- **Mathematical Methodology:**
  1. **JA3/JA4 Fingerprinting:** Computes MD5 hash of TLS Client Hello metadata fields:
     $$\text{JA3} = \text{MD5}(\text{SSLVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats})$$
  2. **Curated Threat Matching:** Compares observed JA3 hashes against a curated threat intelligence blocklist (`models/ja3_blocklist.csv`).
- **Supporting Evidence Emitted:**
  `ja3_hash`, `blocklist_match`, `malware_family`.

---

## Model Card 6: Data Exfiltration (`exfiltration`)

- **Classification Tier:** Tier 2 (Asymmetric Flow Classifier)
- **Problem Statement:** Detect unauthorized bulk data transfer out of the protected enclave.
- **Mathematical Methodology:**
  1. **Volume Asymmetry Ratio ($R_{bytes}$):**
     $$R_{bytes} = \frac{\text{Bytes Outbound}}{\text{Bytes Inbound}} > 50.0$$
  2. **Sustained Egress Volume:** Identifies long-duration flows with cumulative data transfer exceeding normal baseline thresholds.
- **Supporting Evidence Emitted:**
  `outbound_bytes`, `byte_ratio_out_in`, `duration_seconds`.
