//! Chain-configuration trait + AR14 fixed-value stub.
//!
//! [`ChainConfigTrait`] is the seam by which the blockchain reads the active
//! chain-configurable parameters (architecture §11). [`FixedChainConfig`] is
//! the AR14 stub used in tests and the std-host simulator; the programmable
//! `moonblokz-configuration` crate will replace it later (FR7, FR8, FR17,
//! FR49, FR56 — owned by Story 5.6 / 9.2 / future BMAD).
//!
//! Scope (Story 1.3 / 1.4): the active-config accessors required by AC3,
//! plus bounded retention of `initial_chain_config_bytes` for the Story 1.4
//! genesis two-block split. The broader §11 surface (`validate_signature`,
//! `try_propose_change`, `promote_tentative_to_durable`,
//! `discard_pending_tentative`, `handle_window_drop_replay`,
//! `supports_vm_extension`) arrives in the owning story for each FR.

use moonblokz_chain_types::{MAX_BLOCK_SIZE, MAX_PAYLOAD_SIZE};

const FIXED_BLOCK_SIZE_LIMIT: u16 = 2016;
const _: () = assert!(MAX_BLOCK_SIZE == FIXED_BLOCK_SIZE_LIMIT as usize);

/// Maximum retained byte length for the genesis chain-config payload.
///
/// Architecture §3.6 emits `initial_chain_config_bytes` as Block #1's
/// chain-config payload, so the bounded retention capacity is the maximum
/// block payload size, not the full block size.
pub const INITIAL_CHAIN_CONFIG_BYTES_CAPACITY: usize = MAX_PAYLOAD_SIZE;

/// Errors surfaced by the temporary chain-config seam.
///
/// Deliberately omits derives outside tests — every trait impl costs binary
/// size on embedded targets.
#[cfg_attr(test, derive(Debug))]
pub enum ChainConfigError {
    /// The genesis chain-config payload would not fit in one chain-config
    /// block payload.
    InitialChainConfigTooLarge,
    /// The genesis chain-config payload has already been retained and must
    /// not be overwritten.
    InitialChainConfigAlreadyStored,
}

/// Bounded no-alloc retention for genesis chain-config bytes.
///
/// This is the Story 1.4 substitute for the future `moonblokz-configuration`
/// module state. It only retains the initial bytes for the later Block #1
/// emit; validation/durable-lock semantics land in Story 5.6+.
pub struct PendingInitialChainConfig {
    bytes: [u8; INITIAL_CHAIN_CONFIG_BYTES_CAPACITY],
    len: usize,
    present: bool,
}

impl PendingInitialChainConfig {
    /// Constructs an empty pending genesis chain-config store.
    pub const fn empty() -> Self {
        Self {
            bytes: [0u8; INITIAL_CHAIN_CONFIG_BYTES_CAPACITY],
            len: 0,
            present: false,
        }
    }

    /// Stores the initial chain-config payload bytes for the later Block #1
    /// emit.
    pub fn store(&mut self, bytes: &[u8]) -> Result<(), ChainConfigError> {
        if self.present {
            return Err(ChainConfigError::InitialChainConfigAlreadyStored);
        }
        if bytes.len() > INITIAL_CHAIN_CONFIG_BYTES_CAPACITY {
            return Err(ChainConfigError::InitialChainConfigTooLarge);
        }

        self.bytes = [0u8; INITIAL_CHAIN_CONFIG_BYTES_CAPACITY];
        self.bytes[..bytes.len()].copy_from_slice(bytes);
        self.len = bytes.len();
        self.present = true;
        Ok(())
    }

    /// Returns the retained bytes if `store(...)` has been called.
    pub fn bytes(&self) -> Option<&[u8]> {
        if self.present {
            Some(&self.bytes[..self.len])
        } else {
            None
        }
    }
}

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

    /// FR8 durable-lock status. The MVP stub returns `true` (FR56*).
    fn is_durable_locked(&self) -> bool;

    /// Retains the genesis chain-config payload bytes for the later Block #1
    /// emit.
    fn store_initial_chain_config_bytes(&mut self, bytes: &[u8]) -> Result<(), ChainConfigError>;

    /// Returns the retained genesis chain-config payload bytes, if present.
    fn initial_chain_config_bytes(&self) -> Option<&[u8]>;
}

/// AR14 fixed-value stub used in tests / simulation / std-host harness.
///
/// All accessors return hard-coded constants per the AR14 contract. The
/// programmable `moonblokz-configuration` impl supersedes this when that
/// crate ships.
pub struct FixedChainConfig {
    initial_chain_config: PendingInitialChainConfig,
}

impl FixedChainConfig {
    /// Constructs the fixed-value stub.
    pub const fn new() -> Self {
        Self {
            initial_chain_config: PendingInitialChainConfig::empty(),
        }
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

    fn is_durable_locked(&self) -> bool {
        true
    }

    fn store_initial_chain_config_bytes(&mut self, bytes: &[u8]) -> Result<(), ChainConfigError> {
        self.initial_chain_config.store(bytes)
    }

    fn initial_chain_config_bytes(&self) -> Option<&[u8]> {
        self.initial_chain_config.bytes()
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
        assert!(cfg.is_durable_locked());
    }

    #[test]
    fn fixed_stores_initial_chain_config_bytes() {
        let mut cfg = FixedChainConfig::new();
        let bytes = [0xA5, 0xC0, 0x01, 0x54];

        cfg.store_initial_chain_config_bytes(&bytes).unwrap();

        assert_eq!(cfg.initial_chain_config_bytes(), Some(&bytes[..]));
    }

    #[test]
    fn fixed_stores_empty_initial_chain_config_as_present() {
        let mut cfg = FixedChainConfig::new();

        cfg.store_initial_chain_config_bytes(&[]).unwrap();

        assert_eq!(cfg.initial_chain_config_bytes(), Some(&[][..]));
    }

    #[test]
    fn fixed_rejects_second_initial_chain_config_store() {
        let mut cfg = FixedChainConfig::new();
        let first = [0xA5, 0x01];
        let second = [0x5A, 0x02];

        cfg.store_initial_chain_config_bytes(&first).unwrap();
        let result = cfg.store_initial_chain_config_bytes(&second);

        assert!(matches!(
            result,
            Err(ChainConfigError::InitialChainConfigAlreadyStored)
        ));
        assert_eq!(cfg.initial_chain_config_bytes(), Some(&first[..]));
    }

    #[test]
    fn fixed_rejects_oversized_initial_chain_config_bytes() {
        let mut cfg = FixedChainConfig::new();
        let oversized = [0u8; INITIAL_CHAIN_CONFIG_BYTES_CAPACITY + 1];

        let result = cfg.store_initial_chain_config_bytes(&oversized);

        assert!(matches!(
            result,
            Err(ChainConfigError::InitialChainConfigTooLarge)
        ));
        assert!(cfg.initial_chain_config_bytes().is_none());
    }
}
