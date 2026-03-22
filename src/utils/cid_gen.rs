//! Geração de Connection IDs para simulação acadêmica de CID Flooding.
//!
//! Oferece três modos:
//! - `random_cid`     : entropia máxima, simula ataque real
//! - `sequential_cid` : determinístico, garante reprodutibilidade do experimento
//! - `fixed_len_cid`  : comprimento fixo, para testar defesa de CID estrito

use rand::Rng;

/// CID totalmente aleatório — simula geração de entropia do atacante.
/// `len` em bytes (padrão: 20 = 160 bits).
pub fn random_cid(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

#[allow(dead_code)] // usada em tests/integration_test.rs
/// CID determinístico baseado em sequência — para testes reproduzíveis.
/// Garante que o mesmo `seq` sempre gere o mesmo CID dado o mesmo `len`.
pub fn sequential_cid(len: usize, seq: u64) -> Vec<u8> {
    let seq_bytes = seq.to_be_bytes();
    let mut cid = vec![0u8; len];
    for (i, byte) in cid.iter_mut().enumerate() {
        *byte = seq_bytes[i % 8] ^ (i as u8).wrapping_mul(0x6D);
    }
    cid
}

#[allow(dead_code)] // usada em tests/integration_test.rs
/// CID de comprimento fixo (todos zero) — baseline para testar
/// defesa de comprimento estrito no servidor.
pub fn fixed_len_cid(len: usize) -> Vec<u8> {
    vec![0u8; len]
}

/// Monta um pacote QUIC Short Header mínimo com o CID fornecido.
///
/// Estrutura do Short Header (RFC 9000, Seção 17.3):
///   [1 byte: header byte] [CID bytes] [payload mínimo]
///
/// O header byte: bit 7 = 0 (short), bit 6 = 1 (fixed), bits 0-1 = packet number length
pub fn build_short_header_packet(cid: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    // Header byte: 0b01000001 = short header + fixed bit + 2-byte packet number
    let header_byte: u8 = 0b01000001;

    // Payload mínimo: 16 bytes de lixo (simula payload cifrado)
    let payload: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();

    let mut packet = Vec::with_capacity(1 + cid.len() + payload.len());
    packet.push(header_byte);
    packet.extend_from_slice(cid);
    packet.extend_from_slice(&payload);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_cid_has_correct_len() {
        let cid = random_cid(20);
        assert_eq!(cid.len(), 20);
    }

    #[test]
    fn sequential_cid_is_deterministic() {
        let a = sequential_cid(20, 42);
        let b = sequential_cid(20, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn sequential_cid_differs_by_seq() {
        let a = sequential_cid(20, 1);
        let b = sequential_cid(20, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn short_header_packet_structure() {
        let cid = random_cid(20);
        let pkt = build_short_header_packet(&cid);
        // byte[0]: header; bytes[1..21]: CID; bytes[21..]: payload
        assert_eq!(pkt[0], 0b01000001);
        assert_eq!(&pkt[1..21], cid.as_slice());
        assert!(pkt.len() >= 37);
    }
}
