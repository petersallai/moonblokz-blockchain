//! `snake_chain.rs` — FR48–FR53.
//!
//! Owns two `u32` fields on `Blockchain` (head/tail sequence) defining the
//! `snake_chain` window of length `W = SNAKE_CHAIN_LENGTH`, plus the
//! tail-drop classification and `sequence` monotonicity bookkeeping
//! (`u32::MAX` refusal ceiling).
//!
//! Skeleton placeholder (Story 1.2). Window mechanics + tail-drop arrive in
//! Story 9.1; the `u32::MAX` refusal rule in Story 8.1; replay generators in
//! Stories 9.2–9.5.

#[allow(dead_code)]
pub(crate) struct SnakeChainState;
