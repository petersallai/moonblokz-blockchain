//! `node_info.rs` — FR6, FR50, FR67, FR69.
//!
//! Struct-of-arrays per-node derived projection, indexed by `node_id`
//! (~44 KB Schnorr / ~108 KB BLS at the default `MAX_NODES = 1000`):
//! - `public_keys: [[u8; PUBLIC_KEY_SIZE]; MAX_NODES]` — `node_id → public_key`
//! - `balances: [u64; MAX_NODES]` — per-node money balance (FR36)
//! - `seed_source_idx: [u32; MAX_NODES]` — FR50 per-node seed-source block-table
//!   index (`NONE_REF` = node not yet seeded in the current pass)
//! - `max_known_node_id: u32` — FR34 registration-sequence watermark
//!
//! **Scope split.** Story 5.3 (FR3) *introduces* this substrate to the extent
//! the processing-pass reconstruction needs it. The FR34 *queryable surface*
//! and the block-navigation / UTXO cache are added on top by Story 7.1; the
//! FR50 `seed_source_sequence` two-trigger machinery by Story 9.3. The FR37
//! accumulated-vote registry is **owned by the `moonblokz-vote` crate**
//! (`VoteEngine`, held separately on `Blockchain`), indexed by the same
//! `node_id` — it is deliberately *not* duplicated here.

use crate::blocks::NONE_REF;
use moonblokz_crypto::PUBLIC_KEY_SIZE;

/// Per-node derived projection (SoA). See the module doc for the field roles
/// and the Story-5.3-vs-7.1/9.3 scope split.
pub(crate) struct NodeInfoState<const MAX_NODES: usize> {
    public_keys: [[u8; PUBLIC_KEY_SIZE]; MAX_NODES],
    balances: [u64; MAX_NODES],
    seed_source_idx: [u32; MAX_NODES],
    max_known_node_id: u32,
}

impl<const MAX_NODES: usize> NodeInfoState<MAX_NODES> {
    /// In-place construction of the empty baseline, mirroring
    /// `Blockchain::init_in_place` / `VoteEngine::init_in_place`: writes
    /// directly into `dst` with `write_bytes` (memset) for the arrays so a
    /// `MAX_NODES`-scaled value is **never materialized on the stack** (the
    /// Epic-4-retro §8 RAM watch-item for this SoA).
    ///
    /// # Safety
    /// `dst` must be valid for writes of `Self` and not yet initialized.
    /// Every field is written exactly once; no field is read before its write.
    pub(crate) unsafe fn init_in_place(dst: *mut Self) {
        unsafe {
            // Empty-slot sentinel is the all-zero public key (FR67/FR69: the
            // trust anchor at slot 0 is non-zero once seeded).
            let public_keys_ptr = core::ptr::addr_of_mut!((*dst).public_keys) as *mut u8;
            public_keys_ptr.write_bytes(0u8, MAX_NODES * PUBLIC_KEY_SIZE);

            let balances_ptr = core::ptr::addr_of_mut!((*dst).balances) as *mut u64;
            balances_ptr.write_bytes(0u8, MAX_NODES);

            // `seed_source_idx` sentinel is `NONE_REF == u32::MAX == 0xFFFF_FFFF`
            // → a `0xFF` byte-fill yields `u32::MAX` in every element.
            let seed_ptr = core::ptr::addr_of_mut!((*dst).seed_source_idx) as *mut u32;
            seed_ptr.write_bytes(0xFFu8, MAX_NODES);

            core::ptr::addr_of_mut!((*dst).max_known_node_id).write(0);
        }
    }

    /// Resets to the empty baseline in place (no stack temporary), for the
    /// FR3 "not resumable — clean working set on re-entry" guarantee (AC5).
    pub(crate) fn reset(&mut self) {
        for key in self.public_keys.iter_mut() {
            *key = [0u8; PUBLIC_KEY_SIZE];
        }
        for balance in self.balances.iter_mut() {
            *balance = 0;
        }
        for seed in self.seed_source_idx.iter_mut() {
            *seed = NONE_REF;
        }
        self.max_known_node_id = 0;
    }

    /// Seeds a node's derived state from a balance-block `NodeInfo` entry (FR50):
    /// public key, balance, and the block-table index of the seeding block.
    pub(crate) fn seed_node(
        &mut self,
        node_id: u32,
        public_key: &[u8],
        balance: u64,
        seed_idx: u32,
    ) {
        let Some(slot) = self.slot(node_id) else {
            return;
        };
        self.public_keys[slot][..public_key.len().min(PUBLIC_KEY_SIZE)]
            .copy_from_slice(&public_key[..public_key.len().min(PUBLIC_KEY_SIZE)]);
        self.balances[slot] = balance;
        self.seed_source_idx[slot] = seed_idx;
    }

    /// Seeds a newly-registered node (FR50 registration-as-seed: balance 0,
    /// public key = `new_public_key`).
    pub(crate) fn register_node(&mut self, node_id: u32, public_key: &[u8], seed_idx: u32) {
        self.seed_node(node_id, public_key, 0, seed_idx);
    }

    /// Whether `node_id` has been seeded in the current pass (FR3 pre-seed-zone
    /// discrimination, AC4).
    pub(crate) fn is_seeded(&self, node_id: u32) -> bool {
        self.slot(node_id)
            .is_some_and(|slot| self.seed_source_idx[slot] != NONE_REF)
    }

    /// Credits `amount` to a node's balance (saturating — FR6 overflow
    /// validation is Story 5.4; the derivation must not panic).
    pub(crate) fn credit(&mut self, node_id: u32, amount: u64) {
        if let Some(slot) = self.slot(node_id) {
            self.balances[slot] = self.balances[slot].saturating_add(amount);
        }
    }

    /// Debits `amount` from a node's balance (saturating — FR6 negative-balance
    /// validation is Story 5.4).
    pub(crate) fn debit(&mut self, node_id: u32, amount: u64) {
        if let Some(slot) = self.slot(node_id) {
            self.balances[slot] = self.balances[slot].saturating_sub(amount);
        }
    }

    /// Current derived balance of a node (`0` for an out-of-range / unseeded id).
    /// Read surface for the FR6 validation (Story 5.4) and FR34 queries (7.1);
    /// exercised by the Story-5.3 tests today.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn balance_of(&self, node_id: u32) -> u64 {
        self.slot(node_id).map_or(0, |slot| self.balances[slot])
    }

    /// Derived public key of a node, or `None` if the slot is empty / out of range.
    /// Read surface for the FR6 signature validation (Story 5.4); exercised by
    /// the Story-5.3 roster tests today.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn public_key_of(&self, node_id: u32) -> Option<&[u8; PUBLIC_KEY_SIZE]> {
        let slot = self.slot(node_id)?;
        if self.public_keys[slot] == [0u8; PUBLIC_KEY_SIZE] {
            None
        } else {
            Some(&self.public_keys[slot])
        }
    }

    /// FR34 registration-sequence watermark.
    /// Read surface for the FR6 registration-monotonicity validation (Story 5.4);
    /// exercised by the Story-5.3 watermark tests today.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn max_known_node_id(&self) -> u32 {
        self.max_known_node_id
    }

    /// Sets the FR34 watermark (FR3 initialization from the earliest balance
    /// block's `max_node_id`, or per-registration increment).
    pub(crate) fn set_max_known_node_id(&mut self, value: u32) {
        self.max_known_node_id = value;
    }

    /// Bounds-checks `node_id` against `MAX_NODES`, returning the array slot.
    fn slot(&self, node_id: u32) -> Option<usize> {
        let slot = node_id as usize;
        (slot < MAX_NODES).then_some(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructs a `NodeInfoState<16>` through the `unsafe` in-place path (the
    /// raw-pointer / `write_bytes` init this story introduces). Crypto-free, so
    /// this is the tractable Miri target for the new `unsafe` (schnorr-bigint
    /// under the Miri interpreter is impractically slow — the full FR3 tests are
    /// covered by the ordinary `cargo test` run instead).
    fn make() -> NodeInfoState<16> {
        let mut slot = core::mem::MaybeUninit::<NodeInfoState<16>>::uninit();
        unsafe {
            NodeInfoState::init_in_place(slot.as_mut_ptr());
            slot.assume_init()
        }
    }

    #[test]
    fn init_in_place_sets_empty_baseline() {
        let ni = make();
        assert_eq!(ni.max_known_node_id(), 0);
        assert!(
            !ni.is_seeded(0),
            "seed_source sentinel is NONE_REF (unseeded)"
        );
        assert!(!ni.is_seeded(15));
        assert_eq!(ni.balance_of(7), 0);
        assert!(
            ni.public_key_of(7).is_none(),
            "empty-slot sentinel is all-zero key"
        );
    }

    #[test]
    fn seed_credit_debit_watermark_and_reset() {
        let mut ni = make();
        ni.seed_node(2, &[7u8; PUBLIC_KEY_SIZE], 100, 4);
        assert!(ni.is_seeded(2));
        assert_eq!(ni.balance_of(2), 100);
        assert!(ni.public_key_of(2).is_some());
        ni.credit(2, 50);
        ni.debit(2, 30);
        assert_eq!(ni.balance_of(2), 120);
        ni.debit(2, u64::MAX); // saturating — no panic/underflow
        assert_eq!(ni.balance_of(2), 0);
        ni.set_max_known_node_id(9);
        assert_eq!(ni.max_known_node_id(), 9);

        // AC5 clean-baseline reset.
        ni.reset();
        assert_eq!(ni.max_known_node_id(), 0);
        assert!(!ni.is_seeded(2));
        assert_eq!(ni.balance_of(2), 0);
        assert!(ni.public_key_of(2).is_none());
    }

    #[test]
    fn out_of_range_node_id_is_ignored() {
        let mut ni = make();
        // node_id >= MAX_NODES (16) — every accessor is a bounds-checked no-op.
        ni.seed_node(999, &[1u8; PUBLIC_KEY_SIZE], 5, 0);
        ni.credit(999, 10);
        assert!(!ni.is_seeded(999));
        assert_eq!(ni.balance_of(999), 0);
        assert!(ni.public_key_of(999).is_none());
    }
}
