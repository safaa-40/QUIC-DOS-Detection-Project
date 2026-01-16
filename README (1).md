# QUIC DoS Detection Using Machine Learning

Detection of Denial-of-Service attacks in QUIC network traffic using anomaly detection.

## 📋 Project Overview

This project develops a machine learning system to detect DoS attacks against QUIC (Quick UDP Internet Connections) servers. QUIC is the modern transport protocol replacing TCP, used by major services like Google, Facebook, and Cloudflare.

**Key Features:**
- ✅ Custom QUIC traffic generation (benign + malicious)
- ✅ Network testbed with realistic latency
- ✅ 44 discriminative features for ML
- ✅ Dataset of 210K+ labeled flows (ideally)
- ✅ Anomaly detection using autoencoders (still being considered)

---

## 🎯 Problem Statement

**Challenge:** Detect resource exhaustion DoS attacks against QUIC servers

**Attack Type:** High-rate connection flooding
- Attacker sends thousands of connection requests per second
- Server becomes overwhelmed
- Legitimate users cannot connect
- Connections fail to complete handshake (S0 state)

**Solution:** Machine learning model trained on network flow features to distinguish normal traffic from DoS attacks

---

## 🏗️ Architecture

```
┌─────────────┐         ┌─────────────┐
│  VirtualBox │         │ WSL/Windows │
│             │ Network │             │
│ QUIC Server │◄───────►│  Generator  │
│  (Target)   │  1-5ms  │  + Capture  │
└─────────────┘         └─────────────┘
                              │
                              ▼
                        traffic.pcap
                              │
                              ▼
                        ┌──────────┐
                        │   Zeek   │
                        └──────────┘
                              │
                              ▼
                         conn.log
                              │
                              ▼
                    ┌──────────────────┐
                    │extract_features  │
                    └──────────────────┘
                              │
                              ▼
                         flows.csv (44 features)
                              │
                              ▼
                        ┌──────────┐
                        │Autoencoder?│
                        └──────────┘
                              │
                              ▼
                        DoS Detector
```

---

## 📁 Repository Structure

```
quic-dos-detection/
├── README.md                          # This file
├── PROJECT_SUMMARY.md                 # Executive summary for supervisors
├── TECHNICAL_METHODOLOGY.md           # Detailed technical explanation
├── SETUP_GUIDE.md                     # Installation and setup instructions
│
├── scripts/
│   ├── quic_server.py                 # QUIC/HTTP3 server
│   ├── quic_traffic_generator.py      # Benign traffic generation
│   ├── quic_dos_realistic.py          # Malicious traffic generation
│   ├── extract_features_advanced.py   # Feature extraction (44 features)
│   ├── validate_features_advanced.py  # Dataset validation
│   └── analyze_conn_states.py         # Connection state analysis
│
├── notebooks/
│   ├── data_exploration.ipynb         # Dataset visualization
│   ├── model_training.ipynb           # Autoencoder training
│   └── evaluation.ipynb               # Model evaluation
│
├── models/
│   ├── autoencoder.py                 # Autoencoder architecture
│   └── train.py                       # Training script
│
├── data/
│   ├── benign_flows.csv               # Benign traffic features (200K flows)
│   ├── malicious_flows.csv            # Malicious traffic features (10.5K flows)
│   └── dataset_stats.txt              # Dataset statistics
│
└── docs/
    ├── features.md                    # Feature descriptions
    ├── results.md                     # Evaluation results
    └── thesis_draft.pdf               # Thesis document
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.8+
python3 --version

# Required packages
pip install aioquic pandas numpy scikit-learn

# Zeek network analyzer
sudo apt install zeek

# tcpdump
sudo apt install tcpdump
```

### 1. Generate Traffic

**Start QUIC server:**
```bash
python3 scripts/quic_server.py \
  --certificate cert.pem \
  --private-key key.pem
```

**Generate benign traffic:**
```bash
python3 scripts/quic_traffic_generator.py \
  --server 127.0.0.1 \
  --port 4433 \
  --mode benign \
  --sessions 1000
```

**Generate malicious traffic:**
```bash
python3 scripts/quic_dos_realistic.py \
  --server 127.0.0.1 \
  --port 4433 \
  --attacks 1000 \
  --rate 5000
```

### 2. Extract Features

```bash
# Analyze with Zeek
zeek -C -r traffic.pcap

# Extract ML features
python3 scripts/extract_features.py \
  --input conn.log \
  --output flows.csv \
  --label "Benign"
```

### 3. Validate Dataset

```bash
python3 scripts/validate_features.py
```

### 4. Train Model

tbd

---

## 📊 Dataset

### Statistics (Goal)

| Metric | Benign | Malicious |
|--------|--------|-----------|
| **Flows** | 200,000 (95%) | 10,500 (5%) |
| **Packets/flow** | tbd| 2.2 |
| **Bytes/flow** | tbd | 1,368 |
| **Duration** | tbd | 0.01s |
| **Incomplete handshakes** | 0% | 53% |
| **Roundtrips** | tbd | 1.6 |

### Features (44 total)

**Basic Features (7):**
- PACKETS, PACKETS_REV, BYTES, BYTES_REV, DURATION, PACKETS_TOTAL, BYTES_TOTAL

**Rate Features (4):**
- PPI (packets/sec), PPI_REV, BPS (bytes/sec), BPS_REV

**Ratio Features (3):**
- FWD_BWD_PKT_RATIO, FWD_BWD_BYTE_RATIO, ASYMMETRY_SCORE

**DoS Signatures (8):**
- SHORT_LIVED, NO_RESPONSE, FEW_RESPONSES, HIGH_RATE, VERY_HIGH_RATE, HIGHLY_ASYMMETRIC, INCOMPLETE_NO_DATA, DOS_SCORE

**State Features (7):**
- FLOW_ENDREASON_IDLE, FLOW_ENDREASON_ACTIVE, FLOW_ENDREASON_OTHER, IS_COMPLETE, IS_INCOMPLETE, IS_RESET, IS_REJECTED

**Others (15):**
- Packet size, timing, handshake, efficiency metrics

---

## 🧠 Model Architecture

**Autoencoder for Anomaly Detection:**

tbd

**Training:**
- Trained on benign traffic only (95% of dataset)
- Learns to reconstruct normal traffic patterns
- High reconstruction error = anomaly = potential DoS attack

**Threshold:**
- Calculate reconstruction error on validation set
- Set threshold at 95th percentile of benign errors
- Flows above threshold flagged as malicious

---

## 📈 Results

### Performance Metrics

| Metric | Value |
|--------|-------|
| **Precision** | tbd |
| **Recall** | tbd |
| **F1-Score** | tbd |
| **AUC-ROC** | tbd |
| **False Positive Rate** | tbd |

### Confusion Matrix

```
tbd
```

## 🔬 Methodology

### Traffic Generation

**Benign Traffic:**
- Uses aioquic library with complete handshakes
- Makes 1-5 HTTP/3 requests per session
- Session duration: 1-10 seconds
- Rate: 2 sessions/second

**Malicious Traffic:**
- Uses aioquic library with `wait_connected=False`
- Sends Initial packet and immediately disconnects
- Attack rate: 5,000 connections/second
- Server overwhelmed → connections timeout

**Network Setup:**
- Server on VirtualBox VM (Ubuntu 24.04)
- Client on Windows/WSL
- Bridged network adapter
- Realistic latency: 1-5ms

### Why This Works

**Localhost (baseline):**
- Latency: <0.1ms
- Attack signature: 27% incomplete handshakes ❌

**VM network (final):**
- Latency: 1-5ms
- Attack signature: 53% incomplete handshakes ✅

Network latency gives server less time to respond before clients timeout!

---

## 📖 Documentation

- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - Executive summary, progress, timeline
- **[TECHNICAL_METHODOLOGY.md](TECHNICAL_METHODOLOGY.md)** - Detailed technical explanationd

---

## 🛠️ Tools & Technologies

- **Python 3.8+** - Programming language
- **aioquic** - QUIC protocol implementation
- **Zeek** - Network security monitoring
- **tcpdump** - Packet capture
- **pandas/numpy** - Data processing
- **scikit-learn** - ML utilities
- **PyTorch** - Deep learning framework
- **VirtualBox** - Virtual machine
- **Ubuntu 24.04** - Operating system

---