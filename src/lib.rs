//! quic-cid-flood-lab — library root
//!
//! Exposes the core modules used by the binary and (optionally) by
//! integration tests or external benchmarking harnesses.

pub mod cid;
pub mod config;
pub mod experiment;
pub mod metrics;
pub mod raw_flood;
pub mod frame_flood;
