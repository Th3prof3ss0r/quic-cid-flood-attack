//! Parsing e validação da configuração do laboratório via `config/lab.toml`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

// ─── Structs de configuração ────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct LabConfig {
    pub target:       TargetConfig,
    pub attack:       AttackConfig,
    pub frames_flood: FramesFloodConfig,
    pub metrics:      MetricsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TargetConfig {
    pub ip:   String,
    pub port: u16,
}

impl TargetConfig {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AttackVector {
    Raw,
    Frames,
    Both,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AttackConfig {
    pub vector:        AttackVector,
    pub duration_secs: u64,
    pub cid_len:       usize,
    pub workers:       usize,
    pub rate_pps:      u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FramesFloodConfig {
    pub connections:  usize,
    pub ids_per_conn: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MetricsConfig {
    pub sample_interval_ms: u64,
    pub output_csv:         String,
}

// ─── Carregamento ────────────────────────────────────────────────────────────

impl LabConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Não foi possível ler '{}'", path.display()))?;
        let cfg: LabConfig = toml::from_str(&content)
            .with_context(|| format!("Erro ao parsear '{}'", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.attack.cid_len >= 1 && self.attack.cid_len <= 20,
            "cid_len deve estar entre 1 e 20 bytes (RFC 9000)");
        anyhow::ensure!(self.attack.workers >= 1,
            "workers deve ser >= 1");
        anyhow::ensure!(self.attack.rate_pps >= 1,
            "rate_pps deve ser >= 1");
        anyhow::ensure!(self.attack.duration_secs >= 1,
            "duration_secs deve ser >= 1");
        Ok(())
    }
}

// ─── Default para testes ─────────────────────────────────────────────────────

impl Default for LabConfig {
    fn default() -> Self {
        Self {
            target: TargetConfig {
                ip:   "127.0.0.1".into(),
                port: 4433,
            },
            attack: AttackConfig {
                vector:        AttackVector::Raw,
                duration_secs: 30,
                cid_len:       20,
                workers:       4,
                rate_pps:      10_000,
            },
            frames_flood: FramesFloodConfig {
                connections:  10,
                ids_per_conn: 100,
            },
            metrics: MetricsConfig {
                sample_interval_ms: 500,
                output_csv:         "results/experiment.csv".into(),
            },
        }
    }
}
