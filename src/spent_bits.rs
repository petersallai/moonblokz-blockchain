//! `spent_bits.rs` — ADR-016, FR3, FR51.
//!
//! Stateless — operates on the `BlockEntry.spent_bits` bitfields co-located
//! in `BlockTable`. Tracks per-block UTXO spent-bit vectors used by FR51
//! zero-input carry-forward and Tier 3 UTXO validation.
//!
//! Skeleton placeholder (Story 1.2). Spent-bit layout and access primitives
//! arrive in Story 7.1; carry-forward driver in Story 9.5.

// stateless
