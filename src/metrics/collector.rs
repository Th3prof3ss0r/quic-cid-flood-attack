//! Coleta de métricas em tempo real durante os experimentos.
//!
//! `MetricsCollector` é thread-safe e pode ser compartilhado entre workers
//! via `Arc<MetricsCollector>`.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::time;

// ─── Sample ──────────────────────────────────────────────────────────────────

/// Uma amostra de métricas capturada em determinado instante.
#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub timestamp:           DateTime<Utc>,
    pub attack_vector:       String,
    pub packets_sent:        u64,
    pub bytes_sent:          u64,
    pub active_connections:  u64,
    /// Latência de resposta do servidor em ms (0 se não disponível).
    pub response_latency_ms: f64,
    pub cid_len:             usize,
}

// ─── MetricsCollector ────────────────────────────────────────────────────────

pub struct MetricsCollector {
    packets_sent:       AtomicU64,
    bytes_sent:         AtomicU64,
    active_connections: AtomicU64,
    latency_sum_us:     AtomicU64,
    latency_count:      AtomicU64,
    samples:            Mutex<Vec<Sample>>,
    attack_vector:      String,
    cid_len:            usize,
}

impl MetricsCollector {
    pub fn new(attack_vector: &str, cid_len: usize) -> Arc<Self> {
        Arc::new(Self {
            packets_sent:       AtomicU64::new(0),
            bytes_sent:         AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            latency_sum_us:     AtomicU64::new(0),
            latency_count:      AtomicU64::new(0),
            samples:            Mutex::new(Vec::new()),
            attack_vector:      attack_vector.to_string(),
            cid_len,
        })
    }

    // ─── Incrementadores (chamados pelos workers) ─────────────────────────

    pub fn inc_packets(&self, count: u64) {
        self.packets_sent.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_bytes(&self, count: u64) {
        self.bytes_sent.fetch_add(count, Ordering::Relaxed);
    }

    pub fn set_active_connections(&self, count: u64) {
        self.active_connections.store(count, Ordering::Relaxed);
    }

    /// Registra latência de uma resposta do servidor (em microsegundos).
    #[allow(dead_code)] // API disponível para experimentos com medição de RTT
    pub fn record_latency_us(&self, us: u64) {
        self.latency_sum_us.fetch_add(us, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    // ─── Coleta de amostra ────────────────────────────────────────────────

    fn take_sample(&self) {
        let count = self.latency_count.load(Ordering::Relaxed);
        let avg_latency_ms = if count > 0 {
            let sum = self.latency_sum_us.load(Ordering::Relaxed);
            (sum as f64 / count as f64) / 1000.0
        } else {
            0.0
        };

        let sample = Sample {
            timestamp:           Utc::now(),
            attack_vector:       self.attack_vector.clone(),
            packets_sent:        self.packets_sent.load(Ordering::Relaxed),
            bytes_sent:          self.bytes_sent.load(Ordering::Relaxed),
            active_connections:  self.active_connections.load(Ordering::Relaxed),
            response_latency_ms: avg_latency_ms,
            cid_len:             self.cid_len,
        };

        self.samples.lock().unwrap().push(sample);
    }

    /// Inicia loop de amostragem periódica (roda como task Tokio em background).
    pub async fn run_sampling_loop(self: Arc<Self>, interval_ms: u64) {
        let mut ticker = time::interval(Duration::from_millis(interval_ms));
        loop {
            ticker.tick().await;
            self.take_sample();
        }
    }

    /// Retorna snapshot imutável de todas as amostras coletadas.
    pub fn snapshot(&self) -> Vec<Sample> {
        self.samples.lock().unwrap().clone()
    }

    /// Totais acumulados para o resumo final.
    pub fn totals(&self) -> (u64, u64) {
        (
            self.packets_sent.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
        )
    }
}
