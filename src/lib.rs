#![no_std]

//! # moonblokz-blockchain
//!
//! Authoritative MoonBlokz blockchain interpretation crate (`no_std`, no-alloc,
//! embassy-free). The public surface is the [`api`] module; every other
//! internal module is crate-private (FR66, AC5). The chain-configuration seam
//! is `moonblokz_configuration::ChainConfigTrait` — this crate is generic over
//! it and never depends on a concrete configuration implementation (FR56).
//!
//! ## Replay determinism (FR62 / FR63 precondition)
//!
//! The module performs **no internal wall-clock reads and no internal entropy
//! source**. Callers supply `prng_seed: u64` at construction (rooting the
//! Xoshiro256PlusPlus PRNG hierarchy, AR11) and `now: u64` to every
//! time-dependent state-changing method (the one-shot `process_genesis`
//! bootstrap needs none). Identical construction inputs + identical event sequence yield
//! identical state and outcomes across runs and across nodes (when seeded
//! identically) — the seam every later replay/simulator story (Epic 11)
//! builds on.

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
pub(crate) mod prng;
pub(crate) mod queries;
pub(crate) mod reconciliation;
pub(crate) mod scheduler;
pub(crate) mod snake_chain;
pub(crate) mod spent_bits;
pub(crate) mod staged_validation;
pub(crate) mod uninit;

pub use api::{
    BalanceQueryError, BlockQueryError, Blockchain, CallResult, GenesisBlocks, GenesisRejectReason,
    InitOutcome, LifecyclePhase, LocalTransactionOutcome, NextCall, ParentRecoveryRequest,
    ReceiveBlockOutcome, ReceiveTransactionOutcome, RejectReason, TickOutcome, TransactionState,
    TxStateQueryError,
};

#[cfg(test)]
mod tests {
    #[test]
    fn module_skeleton_compiles() {}
}
