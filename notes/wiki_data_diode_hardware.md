# Optical Data Diode Architecture & Hardware Realization

## 1. Physical Layer Barrier
A true physical data diode operates at Layer 1 of the OSI model:
- **Transmitter (Tx) Enclave:** Contains an LED or laser emitter connected to a single-core optical fiber strand.
- **Receiver (Rx) Enclave:** Contains a photodetector diode with zero transmit capability (no laser, no LED, no reverse fiber).
- **Physical Guarantee:** Light can physically travel only from the Tx side to the Rx side. Photons cannot propagate backwards.

## 2. Ingest Software Invariant (rules.md R1)
Because the hardware cannot receive feedback:
- No TCP ACK packets can ever be sent back.
- No TCP three-way handshakes can be initiated or completed by the sensor.
- The sensor must operate as a strictly passive listener.
- Verified by static code analysis (`tests/test_ingest_isolation.py`).
