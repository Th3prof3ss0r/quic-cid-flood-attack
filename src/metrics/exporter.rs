//! Exportação das amostras coletadas para CSV.
//!
//! O formato gerado é compatível com pandas (Python) e R para
//! análise estatística e geração de gráficos acadêmicos.

use anyhow::Result;
use std::path::Path;

use super::Sample;

/// Exporta `samples` para um arquivo CSV no caminho `output`.
/// Cria os diretórios intermediários se necessário.
pub fn export_csv(samples: &[Sample], output: &Path) -> Result<()> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut writer = csv::Writer::from_path(output)?;

    // Cabeçalho explícito para clareza no material acadêmico
    writer.write_record([
        "timestamp",
        "attack_vector",
        "packets_sent",
        "bytes_sent",
        "active_connections",
        "response_latency_ms",
        "cid_len",
    ])?;

    for s in samples {
        writer.write_record(&[
            s.timestamp.to_rfc3339(),
            s.attack_vector.clone(),
            s.packets_sent.to_string(),
            s.bytes_sent.to_string(),
            s.active_connections.to_string(),
            format!("{:.3}", s.response_latency_ms),
            s.cid_len.to_string(),
        ])?;
    }

    writer.flush()?;
    Ok(())
}

/// Imprime um resumo estatístico básico das amostras no terminal.
pub fn print_summary(samples: &[Sample]) {
    if samples.is_empty() {
        println!("  Nenhuma amostra coletada.");
        return;
    }

    let total_packets = samples.last().map(|s| s.packets_sent).unwrap_or(0);
    let total_bytes   = samples.last().map(|s| s.bytes_sent).unwrap_or(0);

    let latencies: Vec<f64> = samples
        .iter()
        .filter(|s| s.response_latency_ms > 0.0)
        .map(|s| s.response_latency_ms)
        .collect();

    let avg_latency = if latencies.is_empty() {
        0.0
    } else {
        latencies.iter().sum::<f64>() / latencies.len() as f64
    };

    let max_latency = latencies.iter().cloned().fold(0.0_f64, f64::max);

    println!("  Pacotes totais  : {}", total_packets);
    println!("  Bytes totais    : {} ({:.2} MB)", total_bytes, total_bytes as f64 / 1_048_576.0);
    println!("  Amostras        : {}", samples.len());
    println!("  Latência média  : {:.3} ms", avg_latency);
    println!("  Latência máxima : {:.3} ms", max_latency);
}
