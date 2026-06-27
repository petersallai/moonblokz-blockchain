//! `blocks.rs` — FR18.
//!
//! Owns the bounded `BlockTable { blocks: [BlockEntry; MAX_BLOCKS] }` (~44.5 KB
//! at the default `MAX_BLOCKS = 600`) — every retained block with its ancestry
//! metadata, the single authoritative `(sequence, block_hash)` duplicate-
//! detection index, and the co-located ADR-016 spent-bit vectors.
//!
//! Skeleton placeholder (Story 1.2). `BlockEntry` layout and the
//! duplicate-detection index arrive in Story 4.1.

#[allow(dead_code)]
pub(crate) struct BlocksState;
