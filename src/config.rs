//! Experiment configuration — TOML-deserializable and CLI-constructible.
//!
//! A single `ExperimentConfig` struct drives the entire tool, whether the
//! configuration comes from a TOML file (`--config`) or from individual
//! CLI flags.  When a TOML file is supplied it takes complete precedence.

use crate::experiment::AttackVector;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Full experiment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentConfig {
      /// Target QUIC server address (e.g. `127.0.0.1:443`).
    pub target: SocketAddr,

      /// Attack vector to execute.
      pub vector: AttackVector,

      /// Number of parallel async workers.
      #[serde(default = "default_workers")]
      pub workers: usize,

      /// Target packet / frame rate per worker (0 = unlimited).
      #[serde(default = "default_rate")]
      pub rate_per_worker: u64,

      /// Experiment wall-clock duration in seconds (0 = infinite).
      #[serde(default = "default_duration")]
      pub duration_secs: u64,

      /// CID length in bytes — must be in [4, 20] per RFC 9000.
      #[serde(default = "default_cid_len")]
      pub cid_len: usize,

      /// Destination file for time-series CSV output.
      #[serde(default = "default_output")]
      pub output: PathBuf,
}

fn default_workers() -> usize { 4 }
fn default_rate() -> u64 { 1_000 }
fn default_duration() -> u64 { 30 }
fn default_cid_len() -> usize { 20 }
fn default_output() -> PathBuf { PathBuf::from("results/experiment.csv") }

impl Default for ExperimentConfig {
      fn default() -> Self {
                Self {
                              target: "127.0.0.1:443".parse().unwrap(),
                              vector: AttackVector::Raw,
                              workers: default_workers(),
                              rate_per_worker: default_rate(),
                              duration_secs: default_duration(),
                              cid_len: default_cid_len(),
                              output: default_output(),
                }
      }
}
