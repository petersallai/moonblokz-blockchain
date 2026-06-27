//! `node_info.rs` — FR6, FR50, FR67, FR69.
//!
//! Owns the 4 parallel struct-of-arrays per-node projections (~44 KB Schnorr /
//! ~108 KB BLS at the default `MAX_NODES = 1000`):
//! - `public_keys: [[u8; PUBLIC_KEY_SIZE]; MAX_NODES]`
//! - `balances: [u64; MAX_NODES]`
//! - `seed_source_idx: [u32; MAX_NODES]` (FR50 per-node seed-source projection)
//! - plus the FR37 accumulated-vote registry (owned by the `moonblokz-vote`
//!   sub-crate but indexed identically).
//!
//! Skeleton placeholder (Story 1.2). SoA layouts and the six derived
//! projections (FR34) arrive in Story 7.1; FR50 `seed_source_sequence` in
//! Story 9.3.

#[allow(dead_code)]
pub(crate) struct NodeInfoState;
