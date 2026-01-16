# QUIC DoS Detection - Project Summary

**Student:** Safaa  
**Date:** January 2026  
**Status:** Data Collection Phase (In Progress)

---

## Executive Summary

This project's goal is to develop a machine learning model to detect Denial-of-Service (DoS) attacks in QUIC network traffic using anomaly detection techniques. The work involves generating a labeled dataset of benign and malicious QUIC traffic, extracting relevant features, and training an autoencoder for anomaly detection.

**Current Progress:** 70% Complete
- ✅ Research and methodology finalized
- ✅ Traffic generation scripts developed
- ✅ Network testbed configured
- 🔄 Dataset generation in progress (200K+ flows)
- ⏳ Model training (next phase)
- ⏳ Evaluation and report writing (final phase)

---

## What Has Been Done So Far

### 1. Research & Literature Review (Complete ✅)

**Objective:** Understand QUIC protocol and DoS attack characteristics

**Key Findings:**
- QUIC is the modern transport protocol replacing TCP (used by Google, Facebook, Cloudflare)
- DoS attacks against QUIC target the handshake phase by overwhelming servers with connection requests
- Existing datasets lack comprehensive QUIC attack traffic
- Need to generate custom dataset with "realistic" attack patterns

**Outcome:** Identified gap in existing research - no high-quality QUIC DoS datasets for ML training

---

### 2. Methodology Design (Complete ✅)

**Attack Strategy:** High-rate flooding
- Send 3,000-5,000 connection requests per second
- Server can only handle ~1,000/second
- Result: Server overwhelmed → connections timeout → incomplete handshakes (attack signature)

**Why This Approach:**
- Models real-world DoS attacks (resource exhaustion)
- Uses standards-compliant QUIC protocol (RFC 9000)
- Creates measurable differences between benign and malicious traffic

**Validation:**
- Achieved 47% incomplete handshake rate in malicious traffic
- Benign traffic shows 100% complete handshakes
- Clear statistical separation for ML classification

---

### 3. Software Development (Complete ✅)

**Tools & Libraries:**
- **Python 3** - Primary programming language
- **aioquic** - Official QUIC protocol library (implements RFC 9000)
- **Zeek** - Network security monitoring tool (flow extraction)
- **tcpdump** - Packet capture utility
- **pandas/numpy** - Data processing and feature extraction

**Scripts Developed:**

| Script | Purpose | 
|--------|---------|
| `quic_server.py` | QUIC/HTTP3 server for receiving connections | 
| `quic_traffic_generator.py` | Generates benign QUIC traffic |
| `quic_dos_realistic.py` | Generates malicious DoS traffic |
| `extract_features.py` | Extracts 44 ML features from network flows |
| `validate_features.py` | Validates dataset quality |
| `analyze_conn_states.py` | Analyzes connection states |

---

### 4. Network Testbed Configuration (Complete ✅)

**Setup:**
```
┌─────────────────┐              ┌─────────────────┐
│  VirtualBox VM  │              │   WSL/Windows   │
│  Ubuntu 24.04   │              │   Client/Attack │
│                 │              │                 │
│  QUIC Server    │◄────────────►│  Traffic Gen    │
│  (Target)       │   Network    │  tcpdump        │
│                 │   1-5ms RTT  │  Zeek           │
└─────────────────┘              └─────────────────┘
```

**Why This Setup:**
- **Separate machines** introduce realistic network latency (1-5ms)
- **Localhost testing** had insufficient latency (<0.1ms) → only 27% attack signature
- **VM network** achieves ~47% attack signature → much better for ML

**Network Configuration:**
- VM IP: 192.168.1.147
- Server Port: 4433 (QUIC/UDP)
- Network Mode: Bridged Adapter
- Bandwidth: Unlimited (local network)

---

### 5. Traffic Generation Parameters (Complete ✅)

#### Benign Traffic
- **Rate:** 2 sessions/second (realistic user behavior)
- **Sessions:** 200,000 total
- **Duration per session:** 1-10 seconds (randomized)
- **Requests per session:** 1-5 HTTP/3 requests (randomized)
- **Total generation time:** ~30 hours
- **Expected flows:** 200,000

#### Malicious Traffic
- **Rate:** 5,000 attacks/second (overwhelming)
- **Attacks:** 20,000 total
- **Duration:** 10 minutes
- **Expected flows:** ~12,000 (47% incomplete handshakes)
- **Total generation time:** 10 minutes

#### Dataset Composition (Goal)
- **Benign:** 200,000 flows (95%)
- **Malicious:** 10,500 flows (5%)
- **Total:** 210,500 flows
- **Class balance:** Optimal for anomaly detection

---

### 6. Feature Engineering (Complete ✅)

**44 features extracted per flow:**

**Categories:**
1. **Basic features** (7): Packet/byte counts, duration
2. **Rate features** (4): Packets per second, bytes per second
3. **Directional ratios** (3): Forward/backward asymmetry
4. **Timing features** (2): Inter-packet timing statistics
5. **Handshake features** (2): Roundtrips, completion status
6. **Connection state** (7): Complete/incomplete/reset flags
7. **DoS signatures** (8): Short-lived, no response, high rate flags
8. **Efficiency metrics** (2): Payload ratio, data exchange efficiency
9. **Derived score** (1): Weighted DoS probability score

**Key Discriminative Features:**
- `FLOW_ENDREASON_IDLE`: tbd
- `DOS_SCORE`: tbd
- `NO_RESPONSE`: tbd
- `ROUNDTRIPS`: tbd
- `PPI` (packets/sec): tbd

**All features are flow-level** (not packet-level), making them:
- ✅ Available in real-world NetFlow/IPFIX exports
- ✅ Lightweight and scalable
- ✅ Privacy-preserving (no payload inspection)

---

## Current Status: Data Collection Phase 🔄

**Started:** January 12, 2026  
**Current Activity:** Generating 200,000 benign flows  
**Progress:** Hour 12 of ~30 hours  
**Estimated Completion:** January 16, 2026

**What's Running:**
1. VM: QUIC server accepting connections
2. WSL Terminal 1: tcpdump capturing packets
3. WSL Terminal 2: Traffic generator sending benign sessions

**Files Being Generated:**
- `benign_full.pcap` - Raw packet capture (~50GB estimated)
- `conn.log` - Zeek flow records (after pcap processing)
- `benign_flows.csv` - Final feature dataset (~200MB)

---

## Next Steps

### Phase 1: Complete Dataset Generation (In Progress)
**Timeline:** January 17-18, 2026 (2 days)

**Tasks:**
- [🔄] Generate 200K benign flows (~30 hours)
- [✅] Generate ~40K malicious flows (completed)
- [ ] Validate dataset quality
- [ ] Balance classes (downsample malicious to 5%)
- [ ] Split train/test sets (80/20)

**Deliverables:**
- `benign_flows.csv` (200,000 rows)
- `malicious_flows.csv` (10,500 rows, balanced)

---

### Phase 2: Model Development
**Timeline:** January 19-28, 2026 

**Tasks:**
- [ ] Implement autoencoder architecture (PyTorch/TensorFlow)
- [ ] Train on benign data (unsupervised learning)
- [ ] Hyperparameter tuning
- [ ] Cross-validation

**Model Architecture:**
```
tbd
```

**Performance:**
tbd

---

### Phase 3: Evaluation & Analysis
**Timeline:** January 29-11, 2026 

**Tasks:**
- [ ] Test set evaluation
- [ ] Confusion matrix analysis
- [ ] Feature importance analysis
- [ ] Comparison with baseline models (Random Forest, Isolation Forest)
- [ ] Error analysis (false positives/negatives)
- [ ] Threshold optimization

**Deliverables:**
- Model evaluation report
- Performance comparison tables
- Visualization plots (ROC curves, confusion matrices)

---

### Phase 4: Report Writing
**Timeline:** February 11-, 2026 

**Chapters:**
1. Introduction & Motivation
2. Background (QUIC protocol, DoS attacks, ML techniques)
3. Related Work & Literature Review
4. Methodology (traffic generation, feature extraction)
5. Implementation (system design, tools)
6. Evaluation & Results
7. Discussion & Limitations
8. Conclusion & Future Work

---