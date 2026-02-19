# QUIC Handshake Degradation Detection

Detection of DoS-induced service degradation in QUIC network traffic using unsupervised anomaly detection.

---

## 📋 Project Overview

This project develops an anomaly detection system to identify DoS attacks against QUIC servers by modeling **realistic service degradation** — not synthetic failure. QUIC is the modern transport protocol (RFC 9000) replacing TCP, used by Google, Cloudflare, and virtually every major web service via HTTP/3.

**What makes this different from a naive approach:**
- ✅ Attack modeled through **resource exhaustion**, not protocol manipulation
- ✅ Detects **both incomplete (S0) and degraded completed (SF) flows** as malicious
- ✅ Detection is **purely statistical** — no hardcoded DoS signatures
- ✅ Autoencoder trained on **benign only** — no labeled attack data required
- ✅ Empirically validated with Welch's t-tests and Cohen's d across three comparison groups
- ✅ **AUC = 0.9998** — 100% malicious SF detection rate at 5% FPR threshold

---

## 🎯 Problem Statement

**Challenge:** Detect resource-exhaustion DoS attacks against QUIC servers using only flow-level statistics.

**Attack type:** High-rate connection flooding via `quic_dos_realistic.py`
- Attacker dispatches thousands of valid QUIC Initial packets per second
- Server cryptographic processing (TLS 1.3 key derivation) is the bottleneck
- At 10,000/sec: 59.7% of flows fail to complete (S0), 40.3% complete but with degraded statistics (SF)
- Legitimate users experience severe latency or failure

**Key insight:** Flooding does **not** cause binary collapse. It causes **gradual degradation**. Completed handshakes under attack look statistically different from normal completed handshakes — fewer roundtrips, fewer packets, longer wall-clock duration. Detection must capture this.

**Solution:** Autoencoder trained on benign flows learns normal statistical behavior. Both degraded SF and S0 flows score high reconstruction error → flagged as anomalous.

---

## 🏗️ System Architecture

```
┌─────────────────────┐              ┌─────────────────────┐
│   VirtualBox VM     │              │    WSL / Windows    │
│   Ubuntu 24.04      │              │    Client + Attack  │
│                     │              │                     │
│   QUIC Server       │◄────────────►│  Traffic Generator  │
│   (Target)          │  Bridged     │  tcpdump            │
│   quic_server.py    │  1–5ms RTT   │  Zeek               │
└─────────────────────┘              └─────────────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │  traffic.pcap   │
                                    └─────────────────┘
                                              │
                                    zeek -C -r traffic.pcap
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │    conn.log     │
                                    └─────────────────┘
                                              │
                                    python3 extract_features.py
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │   flows.csv     │
                                    │  (18 features)  │
                                    └─────────────────┘
                                              │
                                    ┌─────────────────┐
                                    │  Autoencoder    │
                                    │ (benign only)   │
                                    └─────────────────┘
                                              │
                                              ▼
                                    Reconstruction Error
                                    → Anomaly Detection
```

---

## 📁 Repository Structure

```
quic-dos-detection/
├── README.md                        # This file — overview, architecture, quick start
├── PROJECT_SUMMARY.md               # Executive summary — dataset, results, progress
├── TECHNICAL_METHODOLOGY.md         # Deep dive — QUIC protocol, code logic, features
│
├── scripts/
│   ├── quic_server.py               # QUIC/HTTP3 server (target)
│   ├── quic_traffic_generator.py    # Benign HTTP/3 session generator
│   ├── quic_dos_realistic.py        # DoS flooding generator (high-rate)
│   ├── extract_features.py          # Extracts 18 statistical features from conn.log
│   └── statistical_analysis.py     # Welch t-test + Cohen's d validation
│
├── notebooks/
│   ├── DOS_Detection.ipynb       # Dataset visualization + Autoencoder training + Results and threshold analysis
│  
│   
│

│
└── data/
    ├── normal_conn.log              # Benign Zeek flow log (159,420 flows)
    ├── malicious_vm3_rate_10000_conn.log  # Malicious flow log (14,375 flows)
    ├── benign_flows.csv             # Extracted features, benign
    └── malicious_flows.csv          # Extracted features, malicious
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.8+
pip install aioquic pandas numpy scipy scikit-learn torch

# Zeek network analyzer (on server/capture machine)
sudo apt install zeek tcpdump

# TLS certificates for the server
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 1. Start the QUIC server (on VM)

```bash
python3 scripts/quic_server.py \
  --certificate cert.pem \
  --private-key key.pem \
  --host 0.0.0.0 \
  --port 4433
```

### 2. Capture traffic (on VM, separate terminal)

```bash
sudo tcpdump -i any udp port 4433 -w benign.pcap
```

### 3. Generate traffic (from WSL)

**Benign traffic:**
```bash
python3 scripts/quic_traffic_generator.py \
  --server 192.168.1.147 \
  --port 4433 \
  --mode benign \
  --sessions 200000 \
  --duration 108000
```

**Malicious traffic (separate capture session):**
```bash
python3 scripts/quic_dos_realistic.py \
  --server 192.168.1.147 \
  --port 4433 \
  --attacks 20000 \
  --rate 10000 \
  --duration 600
```

### 4. Extract features

```bash
# Process PCAP with Zeek
zeek -C -r benign.pcap

# Extract ML features
python3 scripts/extract_features.py \
  --input conn.log \
  --output benign_flows.csv \
  --label Benign

python3 scripts/extract_features.py \
  --input malicious_conn.log \
  --output malicious_flows.csv \
  --label Malicious
```

### 5. Validate statistical separation

```bash
python3 scripts/statistical_analysis.py \
  --benign normal_conn.log \
  --malicious malicious_vm3_rate_10000_conn.log
```

---

## 📊 Dataset

### Final Statistics

| Metric | Benign | Malicious |
|--------|--------|-----------|
| **Total flows** | 159,420 | 14,375 |
| **Conn state** | ~100% SF | 59.7% S0 / 40.3% SF |
| **Mean orig_pkts** | 13.45 | 2.78 |
| **Mean resp_pkts** | 11.07 | 1.11 |
| **Mean ROUNDTRIPS** | 11.07 | 1.03 |
| **Mean ASYMMETRY** | 0.104 | 0.646 |
| **Mean PPI (pkts/sec)** | 3.07 | 248.16 |

The 40.3% of malicious flows that are SF (completed handshakes) are still labeled **Malicious** — statistical testing confirms they differ significantly from benign SF flows. See `PROJECT_SUMMARY.md` for full justification and statistical tables.

### Feature Set (13 features after preprocessing, used in training)

The pipeline starts with 19 extracted features, then reduces to 13 after correlation filtering:

| Category | Features kept | Dropped (corr > 0.95) |
|----------|--------------|----------------------|
| Packet counts | `PACKETS_FWD` | `PACKETS_REV`, `PACKETS_TOTAL` |
| Byte counts | `BYTES_FWD`, `BYTES_REV` | `BYTES_TOTAL` |
| Duration | `DURATION` | — |
| Rate | `PPS_FWD`, `BPS_FWD` | `PPS_REV`, `BPS_REV` |
| Directional ratios | `FWD_BWD_PKT_RATIO`, `FWD_BWD_BYTE_RATIO`, `ASYMMETRY` | — |
| Bidirectionality | `ROUNDTRIPS_PER_SEC` | `BIDIRECTIONAL_PAIRS` |
| Packet size | `MEAN_PKT_SIZE_FWD`, `MEAN_PKT_SIZE_REV` | — |
| Timing | `TIME_PER_PKT_FWD` | — |

State features (`IS_COMPLETE`, `IS_INCOMPLETE`, `IS_RESET`, `IS_REJECTED`) are extracted for analysis but **excluded from training** to prevent label leakage.

---

## 🧠 Detection Model

### Preprocessing Pipeline

Before training, the 19 extracted features go through three steps:

1. **Log transform** (`log1p`) applied to 9 heavy-tailed features: `PPS_FWD`, `PPS_REV`, `BPS_FWD`, `BPS_REV`, `FWD_BWD_PKT_RATIO`, `FWD_BWD_BYTE_RATIO`, `BYTES_TOTAL`, `BYTES_FWD`, `BYTES_REV` — stabilizes extreme values from S0 flows
2. **Variance filtering** (`VarianceThreshold(1e-6)`) — removes near-constant features (none dropped in practice)
3. **Correlation filtering** — removes one from each pair with correlation > 0.95; drops `PACKETS_REV`, `PACKETS_TOTAL`, `BYTES_TOTAL`, `PPS_REV`, `BPS_REV`, `BIDIRECTIONAL_PAIRS` → **13 final features**

Scaling uses **RobustScaler** (fitted on benign training set only — median/IQR based, robust to outliers).

### Autoencoder Architecture

```
Input (13 features)
    │
Dense(128, relu)
    │
Dense(64, relu)
    │
Dense(4, relu)       ← bottleneck (input_dim // 4 = 3, floored to 4)
    │
Dense(64, relu)
    │
Dense(128, relu)
    │
Dense(13, linear)    ← reconstruction
    │
MSE loss vs input
```

- Optimizer: Adam (lr=1e-3)
- Batch size: 512
- Max epochs: 100 with EarlyStopping (patience=5, monitor val_loss)
- Data split: 60% train / 20% val / 20% test (all benign); malicious held out entirely

### Results

| Model | AUC-ROC | Malicious SF Detection Rate |
|-------|---------|----------------------------|
| **Autoencoder** | **0.9998** | **100%** |
| Isolation Forest (baseline) | 0.9971 | — |

**Threshold sensitivity** (95th percentile of benign test error = operating point):

| Threshold percentile | FPR | TPR |
|---------------------|-----|-----|
| 90th | 10.0% | 100% |
| **95th** | **5.0%** | **100%** |
| 97th | 3.0% | 100% |
| 99th | 1.0% | 96.3% |

The 95th percentile threshold delivers **100% detection of all malicious flows** including degraded-but-completed SF handshakes, at a 5% false positive rate. This validates both the labeling strategy and the feature design.

### Ablation Study

Removing any single feature group causes negligible AUC degradation:

| Removed group | AUC | Mal SF Detection |
|---------------|-----|-----------------|
| Full model | 0.9998 | 100% |
| Without counts | 0.9997 | 100% |
| Without rates | 0.9996 | 100% |
| Without ratios | 0.9997 | 100% |
| Without bidirectional | 0.9999 | 100% |
| Without timing | 0.9996 | 100% |

No single group is a failure point — the degradation signal is distributed across all feature categories.

**Why unsupervised?** Supervised classifiers require labeled attack samples and learn specific signatures, limiting generalization. An autoencoder trained only on benign data detects *any* deviation from normal — including attack variants not seen during training. This is a more realistic deployment assumption.

---

## 🔬 Why the Network Setup Matters

The VM + WSL setup with bridged networking is not arbitrary — it is essential:

| Setup | RTT Latency | S0 Rate | Usable for ML? |
|-------|-------------|---------|----------------|
| Localhost (baseline) | < 0.1ms | ~27% | ❌ Weak signal |
| VM bridged network | 1–5ms | 53–60% | ✅ Strong signal |

At sub-millisecond latency, the server responds to almost every Initial packet before the attacker's 1ms timeout fires — producing mostly SF flows that are barely distinguishable from benign. The 1–5ms network delay gives the attack the right conditions to saturate server capacity and produce realistic degradation.

---

## 📖 Documentation

| Document | Purpose |
|----------|---------|
| `README.md` | This file — overview, architecture, quick start |
| `PROJECT_SUMMARY.md` | Dataset breakdown, statistical results, labeling rationale, progress |
| `TECHNICAL_METHODOLOGY.md` | QUIC protocol deep dive, exact code logic, feature engineering |

---

## 🛠️ Tools & Technologies

| Tool | Role |
|------|------|
| **Python 3.8+** | Primary language |
| **aioquic** | RFC 9000 QUIC implementation (both client and server) |
| **Zeek** | Network security monitor — converts PCAP to flow records |
| **tcpdump** | Raw packet capture |
| **pandas / numpy** | Data processing and feature engineering |
| **scipy** | Statistical validation (Welch t-test, Cohen's d) |
| **PyTorch** | Autoencoder training |
| **VirtualBox + Ubuntu 24.04** | Server VM providing realistic network latency |
