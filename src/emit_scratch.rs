//! `emit_scratch.rs` — FR45 / FR27 emit source.
//!
//! Owns the `EmitScratch { block_buffer: [u8; MAX_BLOCK_SIZE] }` (~2 KB)
//! into which locally created blocks (ordinary + replay) and approval-
//! evidence blocks are serialized. Outcome enum variants borrow
//! `BlockView<'_>` from this buffer to keep enum sizes ~16 B instead of ~2 KB
//! owned (architecture §6.2).
//!
//! Skeleton placeholder (Story 1.2). The `EmitScratch` struct and emit-source
//! contract land in Story 4.3 / Story 8.3 as the assembly pipeline arrives.

#[allow(dead_code)]
pub(crate) struct EmitScratchState;
