//! `snake_chain.rs` — FR48–FR53.
//!
//! The `snake_chain` window is two block-table indices on `Blockchain`: the
//! active head (`active_chain_head_idx`) and the tail (`snake_chain_tail_idx`,
//! `NONE_REF` = no window). `S_head` / `S_tail` are those blocks' sequences, and
//! `S_tail ≤ S_head` holds because the tail is an ancestor of the head. The
//! window length `W` is chain configuration, read through the configuration
//! handle where it is needed (FR56); `SNAKE_CHAIN_LENGTH_MAX` is only the
//! build's capacity, which acceptance holds `W` within (FR8). The tail is
//! derived and advanced over `W`, never over the capacity.
//!
//! The window state and the release step live on `Blockchain` (Story 9.1):
//! establishing the tail wherever the node enters Ready, and the window-advance
//! step that releases the dropped tail block. This module holds the pure parts
//! of the FR48 tail drop: the classification of the dropping block and the
//! preservation-binding decision on a head extension. The `u32::MAX` refusal
//! rule is Story 8.1; the replay generators are Stories 9.2–9.5.

use moonblokz_chain_types::{BlockView, PAYLOAD_TYPE_BALANCE, PAYLOAD_TYPE_CHAIN_CONFIG};

use crate::blocks::BlockTable;
use crate::node_info::NodeInfoState;

/// Below-tail retention `R`: how many released blocks stay in the block-tree
/// below `S_tail`. A code constant, not chain configuration and not a const
/// generic. `0` means the release step frees the dropped block at once, which
/// is what it does; Story 9.7 derives `R` from the verification horizon `H`
/// and brings the retention that a non-zero value needs.
pub(crate) const BELOW_TAIL_RETENTION: u32 = 0;
const _: () = assert!(
    BELOW_TAIL_RETENTION == 0,
    "the tail release frees immediately; a non-zero R needs Story 9.7's retention"
);

/// FR48 essential-state obligation of the block about to drop off the tail.
/// At most one applies to a block (single-block conservation: a chain-config
/// block carries no transactions, a seed source is a balance or registration
/// block, and Tier 1 keeps registrations and complex transactions apart).
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TailObligation {
    /// Nothing to preserve; the block may drop.
    None,
    /// FR49: a chain-config block — its content must be replayed.
    ChainConfig,
    /// FR50: some node's seed source — a balance block must re-seed it.
    SeedSource,
    /// FR51: a block with an unspent UTXO output — a zero-input complex
    /// transaction must carry it forward.
    Utxo,
}

/// The tail block could not be classified: its slot is empty. Never "no
/// obligation" — a node's own inconsistency must not release a block whose
/// state it could not check.
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct TailUnreadable;

/// FR48 classification of the block at `tail_idx` (AC7).
///
/// Fixed order, cheapest first, first match wins:
/// 1. `ChainConfig` — from the payload type cached in `BlockEntry.flags`;
/// 2. `SeedSource` — some node's `seed_source_idx` is this slot, O(`MAX_NODES`);
/// 3. `Utxo` — any of the block's available-UTXO bits is set. A set bit means
///    an unspent output exists (DEC-132), and Tier 1 keeps every output within
///    the bitfield, so no storage read is needed (Story 6.11).
///
/// The shared per-block step keeps both inputs current — `seed_source_idx`
/// and the available-UTXO bits — in the FR3 pass and on every Ready head
/// extension (Story 6.0), and the chain switch restores them through its exact
/// inverses (Story 6.3).
pub(crate) fn classify_tail_drop<const MAX_BLOCKS: usize, const MAX_NODES: usize>(
    blocks: &BlockTable<MAX_BLOCKS>,
    node_info: &NodeInfoState<MAX_NODES>,
    tail_idx: u32,
) -> Result<TailObligation, TailUnreadable> {
    let entry = blocks.get(tail_idx).ok_or(TailUnreadable)?;
    if entry.payload_type() == PAYLOAD_TYPE_CHAIN_CONFIG {
        return Ok(TailObligation::ChainConfig);
    }
    if node_info.is_seed_source(tail_idx) {
        return Ok(TailObligation::SeedSource);
    }
    if blocks.has_available_utxo(tail_idx) == Some(true) {
        return Ok(TailObligation::Utxo);
    }
    Ok(TailObligation::None)
}

/// FR48 preservation-binding decision on a prospective head extension.
#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TailBinding {
    /// The window may advance: there is no obligation, or the extension is the
    /// matching replay kind.
    Advance,
    /// The extension would drop an obligated block without preserving it —
    /// exact evidence of invalidity (FR16).
    Invalid,
}

/// FR48 binding (AC8): does `extension` — the block that would become the new
/// head and push the tail block out — preserve that block's `obligation`?
///
/// Only the *kind* is matched here: a chain-config block for FR49, a balance
/// block for FR50, a block carrying a zero-input complex transaction for FR51.
/// Content equivalence is Stories 9.2 / 9.3 / 9.5. Story 6.0 enforces
/// `Invalid` as a Tier-3 failure; Story 8.3 consults it on the creator side.
pub(crate) fn tail_drop_binding(obligation: TailObligation, extension: &BlockView) -> TailBinding {
    let preserved = match obligation {
        TailObligation::None => true,
        TailObligation::ChainConfig => extension.payload_type() == PAYLOAD_TYPE_CHAIN_CONFIG,
        TailObligation::SeedSource => extension.payload_type() == PAYLOAD_TYPE_BALANCE,
        TailObligation::Utxo => extension.transactions().is_some_and(|txs| {
            txs.iter()
                .any(|tx| tx.as_complex().is_some_and(|cx| cx.input_count() == 0))
        }),
    };
    if preserved {
        TailBinding::Advance
    } else {
        TailBinding::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::{BlockEntry, NONE_REF};
    use moonblokz_chain_types::{
        Block, BlockBuilder, BlockHeader, ChainConfigPayloadBuilder, ComplexTransaction, NodeInfo,
        NodeTransfer, PAYLOAD_TYPE_TRANSACTION,
    };
    use moonblokz_crypto::{Crypto, CryptoTrait, PRIVATE_KEY_SIZE};

    fn signer() -> Crypto {
        Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key")
    }

    fn blocks() -> BlockTable<8> {
        let mut slot = core::mem::MaybeUninit::<BlockTable<8>>::uninit();
        BlockTable::init(&mut slot);
        // SAFETY: `init` returned, so every entry of `slot` is initialized.
        unsafe { slot.assume_init() }
    }

    fn node_info() -> NodeInfoState<8> {
        let mut slot = core::mem::MaybeUninit::<NodeInfoState<8>>::uninit();
        NodeInfoState::init(&mut slot);
        // SAFETY: `init` returned, so every field of `slot` is initialized.
        unsafe { slot.assume_init() }
    }

    fn header(payload_type: u8) -> BlockHeader {
        BlockHeader {
            version: 1,
            sequence: 7,
            creator: 0,
            mined_amount: 0,
            payload_type,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    fn transfer_block() -> Block {
        let signer = signer();
        let nt = NodeTransfer::new_signed(3, 6, 7, 9, 100, 1, 0, &signer);
        let mut builder = BlockBuilder::new().header(header(PAYLOAD_TYPE_TRANSACTION));
        builder.add_node_transfer(&nt).ok().expect("add transfer");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// A transaction block with one complex transaction: `inputs` UTXO inputs
    /// and two UTXO outputs.
    fn complex_block(inputs: u8) -> Block {
        let signer = signer();
        let mut cx = ComplexTransaction::new(3);
        for i in 0..inputs {
            cx.add_utxo_input(u32::from(i), 0, 0, &[0u8; 64])
                .ok()
                .expect("add input");
        }
        cx.add_utxo_output(&[1u8; 32], 10).ok().expect("add output");
        cx.add_utxo_output(&[2u8; 32], 20).ok().expect("add output");
        let mut builder = BlockBuilder::new().header(header(PAYLOAD_TYPE_TRANSACTION));
        builder
            .add_complex_transaction(&cx)
            .ok()
            .expect("add complex");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    fn balance_block() -> Block {
        let signer = signer();
        let mut builder = BlockBuilder::new().header(header(PAYLOAD_TYPE_BALANCE));
        let ni = NodeInfo::new(1, 50, 0, &[5u8; 32]);
        builder.add_node_info(&ni).ok().expect("add node info");
        builder.set_max_node_id(1).ok().expect("set max node id");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    fn config_block() -> Block {
        let signer = signer();
        let mut payload = ChainConfigPayloadBuilder::new();
        let mut builder = BlockBuilder::new().header(header(PAYLOAD_TYPE_CHAIN_CONFIG));
        builder
            .set_chain_config_payload(payload.build_signed(&signer))
            .ok()
            .expect("empty override set fits");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// Admits `block` at slot 0 of `table` as the intake path would: the
    /// payload type is stamped into the entry. Nothing is stored durably — the
    /// classification takes no storage (Story 6.11).
    fn place(table: &mut BlockTable<8>, block: &Block) -> u32 {
        let view = block.view();
        let mut entry = BlockEntry::new(view.hash(), NONE_REF, view.sequence());
        entry.set_payload_type(view.payload_type());
        table.insert(entry).expect("insert")
    }

    // --- AC7: classification ------------------------------------------------

    #[test]
    fn classifies_a_chain_config_block_first() {
        let mut table = blocks();
        let idx = place(&mut table, &config_block());
        // Even listed as a seed source, the first rule in the fixed order wins.
        let mut info = node_info();
        info.seed_node(1, &[1u8; 32], 0, idx);
        assert_eq!(
            classify_tail_drop(&table, &info, idx),
            Ok(TailObligation::ChainConfig)
        );
    }

    #[test]
    fn classifies_a_seed_source() {
        let mut table = blocks();
        let idx = place(&mut table, &balance_block());
        let mut info = node_info();
        assert_eq!(
            classify_tail_drop(&table, &info, idx),
            Ok(TailObligation::None),
            "a balance block nobody is seeded from carries no obligation"
        );
        info.seed_node(1, &[1u8; 32], 50, idx);
        assert_eq!(
            classify_tail_drop(&table, &info, idx),
            Ok(TailObligation::SeedSource)
        );
    }

    /// Story 6.11 (AC4): the UTXO obligation is "any available-UTXO bit set",
    /// decided from RAM alone.
    #[test]
    fn classifies_an_available_utxo_output_and_clears_once_all_are_spent() {
        let mut table = blocks();
        let idx = place(&mut table, &complex_block(1));
        let info = node_info();
        assert_eq!(
            classify_tail_drop(&table, &info, idx),
            Ok(TailObligation::None),
            "a block never derived has no available output"
        );
        table.set_utxo_available(idx, 0, true);
        table.set_utxo_available(idx, 1, true);
        assert_eq!(
            classify_tail_drop(&table, &info, idx),
            Ok(TailObligation::Utxo)
        );
        table.set_utxo_available(idx, 0, false);
        assert_eq!(
            classify_tail_drop(&table, &info, idx),
            Ok(TailObligation::Utxo),
            "output 1 is still unspent"
        );
        table.set_utxo_available(idx, 1, false);
        assert_eq!(
            classify_tail_drop(&table, &info, idx),
            Ok(TailObligation::None),
            "every output spent: nothing to carry forward"
        );
    }

    #[test]
    fn classifies_a_plain_transfer_block_as_no_obligation() {
        let mut table = blocks();
        let idx = place(&mut table, &transfer_block());
        assert_eq!(
            classify_tail_drop(&table, &node_info(), idx),
            Ok(TailObligation::None)
        );
    }

    /// An empty slot is an error, never "no obligation" (retro §3.5).
    #[test]
    fn an_empty_slot_is_an_error_not_no_obligation() {
        let table = blocks();
        assert_eq!(
            classify_tail_drop(&table, &node_info(), 5),
            Err(TailUnreadable)
        );
    }

    // --- AC8: binding -------------------------------------------------------

    #[test]
    fn binding_covers_every_row() {
        let transfer = transfer_block();
        let config = config_block();
        let balance = balance_block();
        let carry = complex_block(0);
        let spend = complex_block(1);
        let extensions = [
            transfer.view(),
            config.view(),
            balance.view(),
            carry.view(),
            spend.view(),
        ];
        // Rows: obligation × [transfer, config, balance, zero-input complex,
        // complex with an input].
        use TailBinding::{Advance as A, Invalid as I};
        let table = [
            (TailObligation::None, [A, A, A, A, A]),
            (TailObligation::ChainConfig, [I, A, I, I, I]),
            (TailObligation::SeedSource, [I, I, A, I, I]),
            (TailObligation::Utxo, [I, I, I, A, I]),
        ];
        for (obligation, expected) in table {
            for (extension, want) in extensions.iter().zip(expected) {
                assert_eq!(
                    tail_drop_binding(obligation, extension),
                    want,
                    "{obligation:?} on a payload-type-{} extension",
                    extension.payload_type()
                );
            }
        }
    }
}
