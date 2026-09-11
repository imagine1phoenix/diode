# Project Wiki & Research Notes — diode

This directory functions as the local repository mirror and submodule for the **diode** project wiki and technical research notes.

## Table of Contents

- [01. Optical Data Diode Architecture & Hardware Realization](wiki_data_diode_hardware.md)
  * Physical Rx-only fiber transceiver specifications
  * Total absence of transmit lasers on the tap receiver
  * AST mathematical proof of zero socket creation in the ingest layer
- [02. Mathematical Foundations of Signal Processing & Entropy](../docs/model_cards.md)
  * Discrete Fast Fourier Transform (FFT) for C2 beacon detection
  * Shannon Entropy over dynamic sliding IP windows and DNS character distributions
  * English n-gram transition matrices and log-likelihood calculation
- [03. Machine Learning Architectures & Model Cards](../docs/model_cards.md)
  * Supervised DGA lexical classifier: Random Forest hyperparameter tuning and cross-validation
  * Unsupervised Exfiltration anomaly engine: Isolation Forest contamination tuning on benign baseline flows
- [04. SOC Operational Runbooks & MITRE ATT&CK Mapping](../docs/architecture.md)
  * Standard Operating Procedures (SOP) for air-gapped threat triage
  * ATT&CK tactic and technique matrix (T1498, T1046, T1071, T1568, T1048)
- [05. High-Throughput Ingest Benchmarking & Zero-Copy Hot Paths](../docs/benchmarks.md)
  * Micro-benchmarking `dpkt` vs `scapy` in Python 3.11/3.14
  * Memory footprint management during multi-gigabit DDoS line-rate saturation
