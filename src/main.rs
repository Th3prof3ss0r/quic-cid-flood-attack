//! quic-cid-flood-attack — CLI entrypoint
//!
//! Academic security research tool for studying QUIC Connection ID (CID)
//! flooding vulnerabilities as described in RFC 9000.
//!
//! ETHICAL USE ONLY — see README.md for full usage policy.

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use quic_cid_flood_lab::{
      config::ExperimentConfig,
      experiment::{run_experiment, AttackVector},
};

/// QUIC CID Flood Attack — academic stress-test tool (RFC 9000)
#[derive(Parser, Debug)]
#[command(
      name = "quic-cid-flood-attack",
      version,
      about = "Academic QUIC CID flooding stress-test tool",
      long_about = "Replicates CID Flooding attack vectors against QUIC servers for security research.\n\
                    Use only in isolated lab environments with explicit written authorisation."
  )]
struct Cli {
      /// Target address (host:port)
    #[arg(long, default_value = "127.0.0.1:443")]
      target: SocketAddr,

      /// Attack vector: raw | frames | both
      #[arg(long, value_enum, default_value = "raw")]
      vector: AttackVector,

      /// Number of worker threads / async tasks
      #[arg(long, default_value_t = 4)]
      workers: usize,

      /// Packets (or frames) per second per worker (0 = unlimited)
      #[arg(long, default_value_t = 1_000)]
      rate: u64,

      /// Experiment duration in seconds (0 = run until Ctrl-C)
      #[arg(long, default_value_t = 30)]
      duration: u64,

      /// CID length in bytes (4–20, per RFC 9000 §17.2)
      #[arg(long, default_value_t = 20)]
      cid_len: usize,

      /// Path to TOML config file (overrides individual flags when provided)
      #[arg(long)]
      config: Option<PathBuf>,

      /// CSV output file for time-series metrics
      #[arg(long, default_value = "results/experiment.csv")]
      output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
      // Initialise structured logging; RUST_LOG controls verbosity.
    tracing_subscriber::fmt()
          .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
          .init();

    let cli = Cli::parse();

    // Build experiment configuration — TOML file takes precedence over flags.
    let cfg: ExperimentConfig = if let Some(path) = cli.config {
              info!("Loading configuration from {}", path.display());
              let raw = std::fs::read_to_string(&path)?;
              toml::from_str(&raw)?
    } else {
              ExperimentConfig {
                            target: cli.target,
                            vector: cli.vector,
                            workers: cli.workers,
                            rate_per_worker: cli.rate,
                            duration_secs: cli.duration,
                            cid_len: cli.cid_len,
                            output: cli.output,
              }
    };

    warn!(
              "⚠  Starting experiment against {} — AUTHORISED LAB USE ONLY",
              cfg.target
          );

    run_experiment(cfg).await?;

    info!("Experiment complete.");
      Ok(())
}
