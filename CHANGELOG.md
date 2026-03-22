# Changelog

All notable changes to `quic-cid-flood-attack` will be documented in this file.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions and uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

> Changes staged for the next release go here.

---

## [0.1.0] — 2026-03-21

### Added

- **`raw` vector** — UDP Short Header CID flood targeting server hash-table CPU exhaustion (RFC 9000 §17.3).
- **`frames` vector** — NEW_CONNECTION_ID frame flood targeting server RAM via CID reservation (RFC 9000 §19.15).
- **`both` vector** — Combined CPU + RAM stress mode running both vectors simultaneously.
- **`MetricsCollector`** — Thread-safe, lock-free real-time metrics using `AtomicU64` counters with configurable sampling interval.
- **CSV exporter** (`metrics/exporter.rs`) — Time-series output with ISO 8601 timestamps, packets/bytes sent, active connections, and response latency.
- **TOML configuration** (`config/lab.toml`) — Full experiment parameterisation without CLI flags.
- **CLI interface** (`clap 4.x`) — All experiment parameters exposed as flags with sensible defaults.
- **Three CID generation modes** — `random_cid`, `sequential_cid`, `fixed_len_cid` for different research scenarios.
- **Integration test suite** (`tests/integration_test.rs`) — Smoke tests for configuration parsing and metrics collection.
- **`PAPER_TEMPLATE.md`** — LaTeX-ready academic paper template for reporting experimental results.
- **`README.md`** — Full documentation including architecture diagram, lab setup guides (Caddy & nginx), CLI reference, and CSV schema.
- **`LICENSE`** — MIT License.
- **`.gitignore`** — Standard Rust project ignores (`target/`, `results/*.csv`, etc.).

### Dependencies (initial set)

| Crate | Version |
|-------|---------|
| `tokio` | 1.x |
| `quinn` | 0.11 |
| `rustls` | 0.23 |
| `rand` | 0.8 |
| `clap` | 4.x |
| `serde` + `toml` | latest |
| `csv` + `chrono` | latest |
| `tracing` + `tracing-subscriber` | 0.1 / 0.3 |
| `anyhow` | latest |

---

[Unreleased]: https://github.com/Th3prof3ss0r/quic-cid-flood-attack/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Th3prof3ss0r/quic-cid-flood-attack/releases/tag/v0.1.0
