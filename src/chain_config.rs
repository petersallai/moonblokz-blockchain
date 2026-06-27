//! Chain-configuration trait + AR14 fixed-value stub.
//!
//! [`ChainConfigTrait`] is the seam by which the blockchain reads the active
//! chain-configurable parameters (architecture §11). [`FixedChainConfig`] is
//! the AR14 stub used in tests and the std-host simulator; the programmable
//! `moonblokz-configuration` crate will replace it later (FR7, FR8, FR17,
//! FR49, FR56 — owned by Story 5.6 / 9.2 / future BMAD).
//!
//! Scope (Story 1.3): only the 7 active-config accessors required by AC3.
//! The broader §11 surface (`validate_signature`, `try_propose_change`,
//! `promote_tentative_to_durable`, `discard_pending_tentative`,
//! `handle_window_drop_replay`, `supports_vm_extension`) arrives in the
//! owning story for each FR.

/// Active-config accessors that the blockchain consumes per architecture §11.
///
/// Deliberately omits derives — every trait impl costs binary size on
/// embedded targets.
pub trait ChainConfigTrait {
    /// FR45 (b) inter-block creation wait time, milliseconds.
    fn current_inter_block_interval_ms(&self) -> u64;

    /// FR47 grace-period window length, milliseconds.
    fn current_grace_period_window_ms(&self) -> u64;

    /// Chain-config-derived block-size limit
    /// (upper-bounded by `moonblokz_chain_types::MAX_BLOCK_SIZE`).
    fn current_block_size_limit(&self) -> u16;

    /// Maximum UTXO outputs per block (ADR-016 / `MAX_BLOCK_UTXO_OUTPUT`).
    fn current_max_utxo_outputs(&self) -> u8;

    /// Maximum aggregated signatures per approval-evidence block (ADR-015).
    fn current_max_aggregated_signatures(&self) -> u8;

    /// FR54 initial total network currency.
    fn current_initial_total_network_currency(&self) -> u64;

    /// FR8 durable-lock status. The MVP stub returns `true` (FR56\*).
    fn is_durable_locked(&self) -> bool;
}

const FIXED_BLOCK_SIZE_LIMIT: u16 = 2016;
const _: () = assert!(moonblokz_chain_types::MAX_BLOCK_SIZE == FIXED_BLOCK_SIZE_LIMIT as usize);

/// AR14 fixed-value stub used in tests / simulation / std-host harness.
///
/// All accessors return hard-coded constants per the AR14 contract. The
/// programmable `moonblokz-configuration` impl supersedes this when that
/// crate ships.
pub struct FixedChainConfig;

impl FixedChainConfig {
    /// Constructs the fixed-value stub.
    pub const fn new() -> Self {
        Self
    }
}

impl ChainConfigTrait for FixedChainConfig {
    fn current_inter_block_interval_ms(&self) -> u64 {
        60_000
    }

    fn current_grace_period_window_ms(&self) -> u64 {
        30_000
    }

    fn current_block_size_limit(&self) -> u16 {
        FIXED_BLOCK_SIZE_LIMIT
    }

    fn current_max_utxo_outputs(&self) -> u8 {
        255
    }

    fn current_max_aggregated_signatures(&self) -> u8 {
        50
    }

    fn current_initial_total_network_currency(&self) -> u64 {
        1_000_000_000
    }

    fn is_durable_locked(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_returns_expected_constants() {
        let cfg = FixedChainConfig::new();
        assert_eq!(cfg.current_inter_block_interval_ms(), 60_000);
        assert_eq!(cfg.current_grace_period_window_ms(), 30_000);
        assert_eq!(cfg.current_block_size_limit(), 2016);
        assert_eq!(cfg.current_max_utxo_outputs(), 255);
        assert_eq!(cfg.current_max_aggregated_signatures(), 50);
        assert_eq!(cfg.current_initial_total_network_currency(), 1_000_000_000);
        assert!(cfg.is_durable_locked());
    }
}
