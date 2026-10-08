//! `snake_chain.rs` — FR48–FR53.
//!
//! Owns two `u32` fields on `Blockchain` (head/tail sequence) defining the
//! `snake_chain` window, plus the tail-drop classification and `sequence`
//! monotonicity bookkeeping (`u32::MAX` refusal ceiling).
//!
//! The window length `W` is chain configuration, read through the
//! configuration handle where it is needed (FR56); `SNAKE_CHAIN_LENGTH_MAX` is
//! only the build's capacity, which acceptance holds `W` within (FR8). The
//! `S_tail` derivation and the tail advance are over `W`, never the capacity.
//!
//! Skeleton placeholder (Story 1.2). Window mechanics + tail-drop arrive in
//! Story 9.1; the `u32::MAX` refusal rule in Story 8.1; replay generators in
//! Stories 9.2–9.5.

#[allow(dead_code)]
pub(crate) struct SnakeChainState;
