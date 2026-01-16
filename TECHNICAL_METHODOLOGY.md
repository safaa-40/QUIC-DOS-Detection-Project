# Technical Methodology - QUIC DoS Traffic Generation

**Purpose:** Explain exactly how the traffic was generated, what each script does, and how the system works.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [How QUIC Protocol Works](#how-quic-protocol-works)
3. [How aioquic Library Works](#how-aioquic-library-works)
4. [Traffic Generation Scripts](#traffic-generation-scripts)
5. [Network Setup](#network-setup)
6. [Feature Extraction Process](#feature-extraction-process)
7. [Data Validation](#data-validation)

---

## System Architecture

### Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     RESEARCH WORKFLOW                         │
└──────────────────────────────────────────────────────────────┘

Step 1: Traffic Generation
┌─────────────┐         ┌─────────────┐
│   VM (VM)   │         │  WSL/Win    │
│             │ Network │             │
│ QUIC Server │◄───────►│ Generator   │
│  (Target)   │  1-5ms  │ + Capture   │
└─────────────┘         └─────────────┘
                              │
                              ▼
                        benign.pcap
                        malicious.pcap

Step 2: Flow Extraction
        benign.pcap
             │
             ▼
        ┌────────┐
        │  Zeek  │ (Network analyzer)
        └────────┘
             │
             ▼
        conn.log (Flow records)

Step 3: Feature Extraction
        conn.log
             │
             ▼
    ┌──────────────────┐
    │ extract_features │ (Python script)
    └──────────────────┘
             │
             ▼
        flows.csv (44 features)

Step 4: ML Training
        flows.csv
             │
             ▼
        ┌──────────┐
        │Autoencoder│
        └──────────┘
             │
             ▼
        DoS Detector
```

---

## How QUIC Protocol Works

### What is QUIC?

**QUIC (Quick UDP Internet Connections)** is a modern transport protocol developed by Google, now standardized as RFC 9000.

**Key characteristics:**
- Runs over UDP (not TCP)
- Encrypts all traffic by default (TLS 1.3 integrated)
- Multiplexes multiple streams in one connection
- Faster connection setup (1-RTT vs TCP's 3-RTT)

### QUIC Connection Handshake

**Normal QUIC connection:**

```
Client                                Server
  │                                      │
  │─────── Initial Packet ──────────────►│
  │  Contains: ClientHello (TLS 1.3)    │
  │  Size: ~1248 bytes                   │
  │  Encrypted: Partially                │
  │                                      │
  │◄──── Handshake Packet ───────────────│
  │  Contains: ServerHello + Certificate │
  │  Size: ~1872 bytes                   │
  │  Encrypted: Fully                    │
  │                                      │
  │─────── Handshake Packet ────────────►│
  │  Contains: Finished                  │
  │  Size: ~256 bytes                    │
  │                                      │
  │◄─────── 1-RTT Packet ────────────────│
  │  Contains: Application data ready    │
  │  Size: ~1872 bytes                   │
  │                                      │
  │                                      │
  Connection established! (SF state)
  Total time: 1-5ms on LAN
  Total roundtrips: ~11 packets each direction
```

**DoS attack - incomplete handshake:**

```
Attacker                              Server
  │                                      │
  │─────── Initial Packet ──────────────►│
  │  (Client immediately disconnects)    │
  │                                      │
  │  ✗ NO RESPONSE EXPECTED              │
  │                                      │
  Server tries to respond...
  │◄──── Handshake Packet ───────────────│
  │                                      │
  ✗ Attacker already gone!               │
  Connection timeout (S0 state)
  Total roundtrips: 0 (incomplete)
```

---

## How aioquic Library Works

### What is aioquic?

**aioquic** is a Python implementation of QUIC and HTTP/3 protocols. It handles all the complex protocol details:
- Packet framing
- Encryption/decryption (TLS 1.3)
- Flow control
- Connection management
- Stream multiplexing

### Code Architecture

**Internal structure:**

```python
aioquic/
├── quic/
│   ├── connection.py      # Main QUIC connection logic
│   ├── packet.py          # Packet encoding/decoding
│   ├── crypto.py          # TLS 1.3 integration
│   ├── recovery.py        # Loss detection & recovery
│   └── congestion.py      # Congestion control
├── h3/
│   └── connection.py      # HTTP/3 layer
└── asyncio/
    ├── client.py          # High-level client API
    └── server.py          # High-level server API
```

### How Packets Are Created

**When you call `connect()` in aioquic:**

```python
from aioquic.asyncio.client import connect

async with connect(server_ip, port, configuration):
    # What happens internally:
    pass
```

**Internal flow:**

1. **Create QUIC connection object** (`QuicConnection`)
   ```python
   # aioquic/quic/connection.py
   connection = QuicConnection(is_client=True)
   ```

2. **Generate Initial packet**
   ```python
   # aioquic/quic/packet_builder.py
   packet = QuicPacket(
       type=PACKET_TYPE_INITIAL,
       destination_connection_id=random_bytes(8),
       source_connection_id=random_bytes(8),
       payload=crypto_frame  # TLS ClientHello
   )
   ```

3. **Encrypt packet**
   ```python
   # aioquic/quic/crypto.py
   encrypted = encrypt_packet(
       packet,
       key=initial_key,  # Derived from connection IDs
       algorithm=AEAD_AES_128_GCM
   )
   ```

4. **Send UDP datagram**
   ```python
   # aioquic/asyncio/protocol.py
   transport.sendto(encrypted, (server_ip, port))
   ```

**Packet structure (Initial packet):**

```
┌────────────────────────────────────┐
│ Long Header (17 bytes)             │
│  - Flags (1 byte)                  │
│  - Version (4 bytes)               │
│  - DCID Length + DCID (9 bytes)    │
│  - SCID Length + SCID (1+2 bytes)  │
│  - Token Length (1 byte)           │
│  - Length (2 bytes)                │
│  - Packet Number (1 byte)          │
├────────────────────────────────────┤
│ Encrypted Payload (~1230 bytes)    │
│  ┌──────────────────────────────┐  │
│  │ CRYPTO Frame                 │  │
│  │  - Frame Type (1 byte)       │  │
│  │  - Offset (variable)         │  │
│  │  - Length (variable)         │  │
│  │  - TLS ClientHello Data      │  │
│  │    - Random (32 bytes)       │  │
│  │    - Cipher Suites           │  │
│  │    - Extensions (ALPN, etc)  │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │ PADDING Frame (fills to 1200)│  │
│  └──────────────────────────────┘  │
└────────────────────────────────────┘
Total: ~1248 bytes
```

**Why 1248 bytes?**
- QUIC requires Initial packets to be at least 1200 bytes (RFC 9000)
- Prevents amplification attacks
- UDP header (8 bytes) + IP header (20 bytes) + QUIC payload (1200) = 1228
- With Ethernet overhead: ~1248 bytes

---

## Traffic Generation Scripts

### 1. quic_server.py - The Target Server

**Purpose:** Runs a QUIC/HTTP3 server that responds to connection requests.

**What it does:**

```python
# Simplified version
class QuicServer:
    def __init__(self, certificate, private_key):
        self.config = QuicConfiguration(
            is_client=False,
            alpn_protocols=["h3"],  # HTTP/3
            certificate=certificate,
            private_key=private_key
        )
    
    async def handle_connection(self, protocol):
        # 1. Receive Initial packet
        # 2. Send Handshake packet (ServerHello + Certificate)
        # 3. Receive client Finished
        # 4. Send 1-RTT packet (connection ready)
        # 5. Handle HTTP/3 requests
        pass
```

**Key configuration:**
- **Host:** `0.0.0.0` (accept connections from any IP)
- **Port:** 4433 (standard QUIC port)
- **Certificate:** Self-signed RSA 2048-bit certificate
- **ALPN:** HTTP/3 (`h3`)

**Server behavior:**
- **Normal load:** Processes connections immediately (~1ms response)
- **Under attack:** Queue fills up, responses delayed (>100ms)
- **Overloaded:** Some connections timeout (S0 state)

---

### 2. quic_traffic_generator.py - Benign Traffic

**Purpose:** Simulates legitimate users browsing websites over QUIC.

**What it does:**

```python
async def benign_session():
    # 1. Establish QUIC connection (wait for handshake)
    async with connect(server, port, wait_connected=True):
        
        # 2. Make 1-5 HTTP/3 requests
        for i in range(random.randint(1, 5)):
            path = random.choice(["/", "/index.html", "/api/data"])
            await make_http3_request(path)
            
            # 3. Wait between requests (human-like behavior)
            await asyncio.sleep(random.uniform(0.1, 1.0))
        
        # 4. Keep connection alive for realistic duration
        await asyncio.sleep(random.uniform(1.0, 10.0))
    
    # Connection closes normally (SF state)
```

**Key parameters:**
- **Session rate:** 2 per second (realistic user behavior)
- **Requests per session:** 1-5 (randomized)
- **Session duration:** 1-10 seconds (randomized)
- **wait_connected=True:** Waits for complete handshake

**Resulting traffic characteristics:**
- **Connection state:** SF (complete)
- **Packets sent:** ~13
- **Packets received:** ~11
- **Roundtrips:** ~11 (bidirectional)
- **Duration:** 1-10 seconds
- **Bytes received:** Variable (handshake + HTTP responses)

---

### 3. quic_dos_realistic.py - Malicious Traffic

**Purpose:** Simulates DoS attack by overwhelming server with connection requests.

**What it does:**

```python
async def dos_attack():
    # 1. Create QUIC connection (send Initial packet)
    async with connect(server, port, wait_connected=False):
        # ^^^ KEY: wait_connected=False
        # Doesn't wait for server response!
        
        # 2. Exit immediately after sending Initial
        await asyncio.sleep(0.001)  # 1 millisecond
    
    # Connection abandoned (S0 state if server too slow)

# Launch thousands of attacks per second
async def flood():
    for i in range(20000):
        asyncio.create_task(dos_attack())  # Don't wait
        
        await asyncio.sleep(1/5000)  # 5000 attacks/second
```

**Key parameters:**
- **Attack rate:** 5,000 per second (overwhelming)
- **Duration:** 10 minutes
- **wait_connected=False:** Doesn't wait for handshake
- **asyncio.create_task:** Launches attacks without waiting

**Resulting traffic characteristics:**
- **Connection state:** S0 (53%) or SF (47%)
- **Packets sent:** ~2
- **Packets received:** ~0 (S0) or ~2 (SF)
- **Roundtrips:** 0 (S0) or 2 (SF)
- **Duration:** 0.001-0.01 seconds
- **Bytes received:** 0 (S0) or 1508 (SF handshake only)

**Why some complete (SF) and some don't (S0):**
- At 5000/sec rate, server can handle ~1000/sec
- 1000 connections: Server responds in time → SF
- 4000 connections: Server too slow/queue full → S0

---

## Network Setup

### Why Separate Machines Matter

**Problem with localhost:**
```
Client → Server (both on same machine)
Latency: 0.01ms (microseconds)
Result: Server responds before client abandons
Outcome: 100% complete handshakes (SF)
Attack signature: Only 27% ❌
```

**Solution with VM network:**
```
Client (WSL) → Network → Server (VM)
Latency: 1-5ms (milliseconds)
Result: Server response delayed by network
Outcome: Client abandons before response arrives
Attack signature: 53% incomplete (S0) ✅
```

### Network Configuration Steps

**1. VirtualBox network settings:**
- Adapter Type: Bridged Adapter
- Promiscuous Mode: Allow All
- Cable Connected: ✓

**2. Get VM IP address:**
```bash
# On VM
ip addr show
# Look for: inet 192.168.1.147/24
```

**3. Test connectivity:**
```bash
# From WSL
ping 192.168.1.147
# Should see: Reply from 192.168.1.147: time=1-5ms
```

**4. Start server on VM:**
```bash
python3 quic_server.py --host 0.0.0.0 --port 4433
# ^^^ 0.0.0.0 = accept connections from any IP
```

**5. Generate traffic from WSL:**
```bash
python3 quic_dos_realistic.py --server 192.168.1.147 --port 4433

```

---

## Feature Extraction Process

### Step 1: Packet Capture

**Tool:** tcpdump

**Command:**
```bash
sudo tcpdump -i any udp port 4433 -w traffic.pcap
```

**What it captures:**
- All UDP packets on port 4433
- Raw packet data (headers + payload)
- Timestamps (microsecond precision)
- Source/destination IPs and ports

**File format:** PCAP (standard packet capture format)

**File size:** ~50GB for 200K flows

---

### Step 2: Flow Extraction

**Tool:** Zeek (formerly Bro IDS)

**Command:**
```bash
zeek -C -r traffic.pcap
```

**What Zeek does:**

1. **Reads PCAP file** packet by packet
2. **Groups packets** into flows (connections)
3. **Analyzes protocols** (QUIC, UDP, IP)
4. **Tracks connection state** (Initial, Handshake, Data, Close)
5. **Calculates statistics** (packets, bytes, duration)
6. **Outputs conn.log** with flow records

**conn.log format:**
```
timestamp | uid | src_ip | src_port | dst_ip | dst_port | proto |
duration | orig_bytes | resp_bytes | conn_state | orig_pkts | resp_pkts
```

**Connection states:**
- **S0:** Initial packet seen, no response (incomplete handshake)
- **SF:** Complete connection (handshake + normal close)
- **S1:** Connection established but not terminated
- **RSTO/RSTR:** Connection reset
- **REJ:** Connection rejected

---

### Step 3: Feature Calculation

**Tool:** extract_features.py

**Input:** conn.log (Zeek output)
**Output:** flows.csv (44 features per flow)

**Process:**

```python
def extract_features(conn_log):
    # 1. Parse Zeek log
    df = pd.read_csv(conn_log, sep='\t', comment='#')
    
    # 2. Calculate basic features
    PACKETS = df['orig_pkts']
    PACKETS_REV = df['resp_pkts']
    BYTES = df['orig_bytes']
    BYTES_REV = df['resp_bytes']
    DURATION = df['duration']
    
    # 3. Calculate rate features
    PPI = PACKETS / DURATION  # Packets per second
    BPS = BYTES / DURATION    # Bytes per second
    
    # 4. Calculate ratio features
    FWD_BWD_RATIO = PACKETS / PACKETS_REV
    ASYMMETRY = |PACKETS - PACKETS_REV| / max(PACKETS, PACKETS_REV)
    
    # 5. Calculate handshake features
    ROUNDTRIPS = min(PACKETS, PACKETS_REV)
    IS_COMPLETE = (conn_state == 'SF')
    
    # 6. Calculate DoS signatures
    SHORT_LIVED = (DURATION < 1.0)
    NO_RESPONSE = (PACKETS_REV == 0)
    HIGH_RATE = (PPI > 100)
    
    # 7. Calculate DoS score
    DOS_SCORE = (
        0.25 * SHORT_LIVED +
        0.20 * NO_RESPONSE +
        0.15 * IS_INCOMPLETE +
        0.15 * HIGH_RATE +
        0.25 * HIGHLY_ASYMMETRIC
    )
    
    return features
```

**Feature categories:**

| Category | Count | Examples |
|----------|-------|----------|
| Basic | 7 | PACKETS, BYTES, DURATION |
| Rates | 4 | PPI, BPS |
| Ratios | 3 | FWD_BWD_RATIO, ASYMMETRY |
| Handshake | 2 | ROUNDTRIPS, IS_COMPLETE |
| State | 7 | FLOW_ENDREASON_IDLE, IS_RESET |
| DoS Signatures | 8 | SHORT_LIVED, NO_RESPONSE |
| Efficiency | 2 | PAYLOAD_RATIO |
| Derived | 1 | DOS_SCORE |
| **Total** | **44** | |

---

## Data Validation

### Quality Checks

**Script:** validate_features_advanced.py

**Checks performed:**

1. **Feature completeness:**
   - All 44 features present in both benign and malicious
   - No missing features

2. **Data quality:**
   - No NaN values
   - No Inf values
   - All numeric features have valid ranges

3. **Class balance:**
   - Benign: ~95%
   - Malicious: ~5%
   - Optimal for anomaly detection

4. **Feature separability:**
   - Calculate Cohen's d (effect size)
   - Identify most discriminative features
   - Ensure sufficient separation for ML

5. **DoS signatures:**
   - FLOW_ENDREASON_IDLE: tbd
   - NO_RESPONSE: tbd
   - HIGH_RATE: tbd

**Validation output:**
```
✓ Feature sets match: 44 features
✓ No NaN or Inf values detected
✓ Good balance for anomaly detection (95% benign)

---

## Summary

**Traffic Generation:**
- Benign: Uses aioquic with `wait_connected=True`, makes HTTP/3 requests
- Malicious: Uses aioquic with `wait_connected=False`, abandons immediately
- Network: VM + WSL setup provides realistic latency (1-5ms)

**Feature Extraction:**
- tcpdump captures raw packets
- Zeek extracts flow statistics
- Python script calculates 44 ML features
- Validation ensures quality

**Dataset:**
- 210,500 total flows
- 95% benign, 5% malicious
- 44 features per flow

---

