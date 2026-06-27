#![no_std]

//! # moonblokz-blockchain
//!
//! Authoritative MoonBlokz blockchain interpretation crate (`no_std`, no-alloc,
//! embassy-free). The single public surface is the [`api`] module — every
//! internal module is crate-private (FR66, AC5).

pub mod api;

// Internal modules — crate-private; never `pub mod` (FR66 boundary).
pub(crate) mod approval;
pub(crate) mod blocks;
pub(crate) mod branch_value;
pub(crate) mod chain_heads;
pub(crate) mod creator;
pub(crate) mod emit_scratch;
pub(crate) mod intake;
pub(crate) mod lifecycle;
pub(crate) mod node_info;
pub(crate) mod queries;
pub(crate) mod reconciliation;
pub(crate) mod scheduler;
pub(crate) mod snake_chain;
pub(crate) mod spent_bits;
pub(crate) mod staged_validation;

pub use api::{Blockchain, CallResult, LifecyclePhase, NextCall};

#[cfg(test)]
mod tests {
    #[test]
    fn module_skeleton_compiles() {}
}
