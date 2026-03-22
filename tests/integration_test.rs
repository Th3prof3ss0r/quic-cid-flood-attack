//! Testes de integração — validam os módulos principais sem necessidade
//! de um servidor QUIC real.

use quic_cid_flood_lab::utils::cid_gen::{
    build_short_header_packet, fixed_len_cid, random_cid, sequential_cid,
};
use quic_cid_flood_lab::config::LabConfig;
use quic_cid_flood_lab::metrics::MetricsCollector;

// ─── cid_gen ─────────────────────────────────────────────────────────────────

#[test]
fn cid_lengths_are_correct() {
    for len in [1usize, 4, 8, 16, 20] {
        assert_eq!(random_cid(len).len(), len);
        assert_eq!(sequential_cid(len, 0).len(), len);
        assert_eq!(fixed_len_cid(len).len(), len);
    }
}

#[test]
fn random_cids_are_not_all_equal() {
    // Probabilidade de colisão de 10 CIDs de 160 bits ≈ 0
    let cids: Vec<Vec<u8>> = (0..10).map(|_| random_cid(20)).collect();
    let unique: std::collections::HashSet<Vec<u8>> = cids.into_iter().collect();
    assert!(unique.len() > 1, "CIDs aleatórios não devem colidir");
}

#[test]
fn sequential_cids_are_deterministic() {
    for seq in 0u64..100 {
        let a = sequential_cid(20, seq);
        let b = sequential_cid(20, seq);
        assert_eq!(a, b, "CID sequencial deve ser determinístico para seq={}", seq);
    }
}

#[test]
fn packet_starts_with_correct_header_byte() {
    let cid = random_cid(20);
    let pkt = build_short_header_packet(&cid);
    assert_eq!(pkt[0], 0b01000001, "Header byte deve ser 0x41");
    assert_eq!(&pkt[1..21], cid.as_slice(), "CID deve estar nos bytes 1-20");
}

// ─── config ──────────────────────────────────────────────────────────────────

#[test]
fn default_config_is_valid() {
    let cfg = LabConfig::default();
    assert_eq!(cfg.target.ip, "127.0.0.1");
    assert_eq!(cfg.target.port, 4433);
    assert!(cfg.attack.workers >= 1);
    assert!(cfg.attack.cid_len >= 1 && cfg.attack.cid_len <= 20);
}

#[test]
fn target_addr_formats_correctly() {
    let cfg = LabConfig::default();
    assert_eq!(cfg.target.addr(), "127.0.0.1:4433");
}

// ─── metrics ─────────────────────────────────────────────────────────────────

#[test]
fn metrics_collector_increments_correctly() {
    let m = MetricsCollector::new("raw", 20);
    m.inc_packets(1000);
    m.inc_bytes(37_000);
    let (pkts, bytes) = m.totals();
    assert_eq!(pkts,  1000);
    assert_eq!(bytes, 37_000);
}

#[test]
fn metrics_collector_records_latency() {
    let m = MetricsCollector::new("frames", 20);
    m.record_latency_us(1_000); // 1ms
    m.record_latency_us(3_000); // 3ms
    // Apenas verifica que não pânica; validação numérica no summary
    let (pkts, _) = m.totals();
    assert_eq!(pkts, 0); // latência não afeta contador de pacotes
}
