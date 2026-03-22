//! CID generation strategies for QUIC flooding experiments.
//!
//! Three modes are provided to cover different research scenarios:
//!
//! | Function             | Entropy        | Use case                              |
//! |----------------------|----------------|---------------------------------------|
//! | `random_cid`         | Full (CSPRNG)  | Simulate real attacker behaviour      |
//! | `sequential_cid`     | Deterministic  | Reproducible, comparable experiments  |
//! | `fixed_len_cid`      | Zero           | Baseline / strict-length defence test |
//!
//! All lengths must be in `[4, 20]` bytes — the range mandated by RFC 9000 §17.2.

use rand::{RngCore, SeedableRng};
use rand::rngs::SmallRng;

/// Valid CID length range per RFC 9000 §17.2.
pub const CID_MIN_LEN: usize = 4;
pub const CID_MAX_LEN: usize = 20;

/// Generate a cryptographically random CID of `len` bytes.
///
/// Uses the thread-local CSPRNG from the `rand` crate.
///
/// # Panics
/// Panics if `len` is outside `[CID_MIN_LEN, CID_MAX_LEN]`.
pub fn random_cid(len: usize) -> Vec<u8> {
    assert!(
        (CID_MIN_LEN..=CID_MAX_LEN).contains(&len),
        "CID length {len} outside RFC 9000 range [{CID_MIN_LEN}, {CID_MAX_LEN}]"
    );
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
      }

/// Generate a deterministic CID from a monotonically increasing sequence number.
///
/// The sequence number is written in little-endian order into a zero-padded
/// buffer, ensuring reproducibility across runs with the same seed / range.
///
/// # Panics
/// Panics if `len` is outside `[CID_MIN_LEN, CID_MAX_LEN]`.
pub fn sequential_cid(len: usize, seq: u64) -> Vec<u8> {
      assert!(
        (CID_MIN_LEN..=CID_MAX_LEN).contains(&len),
        "CID length {len} outside RFC 9000 range [{CID_MIN_LEN}, {CID_MAX_LEN}]"
    );
    let mut buf = vec![0u8; len];
    let seq_bytes = seq.to_le_bytes();
    let copy_len = seq_bytes.len().min(len);
    buf[..copy_len].copy_from_slice(&seq_bytes[..copy_len]);
    buf
}

/// Generate an all-zero CID of `len` bytes.
///
/// Useful for testing servers that enforce strict CID uniqueness or
/// minimum-entropy requirements.
///
/// # Panics
/// Panics if `len` is outside `[CID_MIN_LEN, CID_MAX_LEN]`.
pub fn fixed_len_cid(len: usize) -> Vec<u8> {
    assert!(
        (CID_MIN_LEN..=CID_MAX_LEN).contains(&len),
        "CID length {len} outside RFC 9000 range [{CID_MIN_LEN}, {CID_MAX_LEN}]"
    );
    vec![0u8; len]
}

/// Generate a batch of `count` random CIDs, each of `len` bytes.
///
/// Uses a seeded `SmallRng` for fast batch generation when the caller
/// does not need cryptographic quality (e.g., load generation).
pub fn random_cid_batch(len: usize, count: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = SmallRng::seed_from_u64(seed);
    (0..count)
        .map(|_| {
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            buf
})
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_cid_correct_length() {
        for len in CID_MIN_LEN..=CID_MAX_LEN {
            assert_eq!(random_cid(len).len(), len);
}
}

    #[test]
    fn sequential_cid_deterministic() {
        assert_eq!(sequential_cid(8, 42), sequential_cid(8, 42));
        assert_ne!(sequential_cid(8, 1), sequential_cid(8, 2));
}

    #[test]
    fn fixed_len_cid_all_zeros() {
        assert!(fixed_len_cid(8).iter().all(|&b| b == 0));
}

    #[test]
    #[should_panic]
    fn random_cid_invalid_length() {
        random_cid(3); // below minimum
}
}
