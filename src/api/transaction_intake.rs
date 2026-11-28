//! FR14 ready-state transaction intake (Story 7.3; DEC-350..355): one
//! deterministic outcome per submitted transaction, derived from the active
//! chain at the head, and the FR31 admission of an Accepted or Deferred one.
//!
//! The classification is the shared per-block step evaluated for a block at
//! `h + 1` (DEC-350): the per-transaction Tier 1, the mempool key search, the
//! window duplicate scan, then [`Blockchain::apply_transaction`] run in place
//! on the head's post-state and undone by its exact inverse. One table maps
//! the step's reasons to the outcome, so intake and validation never drift.

use super::duplicate::{inclusion_floor, is_balance_only, same_key};
use super::step::transaction_fee;
use super::*;
use crate::staged_validation::tier1_transaction;

/// DEC-223: whether a transaction of `len` bytes cannot fit into a block of
/// the chain's `block_size_limit` — the header and the transaction-count
/// prefix take the rest. Such a transaction is Rejected at intake, never
/// admitted: the bound is the chain's, so every node judges it alike.
pub(super) fn exceeds_block_room(len: usize, block_size_limit: u32) -> bool {
    len > (block_size_limit as usize).saturating_sub(HEADER_SIZE + 2)
}

/// The FR14 outcome of a step failure at intake (DEC-350's table): `Deferred`
/// where a later chain state can cure it — an unknown or unseeded node, a vote
/// target not yet registered, a balance short of the debit, a registration for
/// a later slot, a spent UTXO input — and `Rejected` for every other reason.
/// A registered key is Already-confirmed (DEC-352). `max_known` is the
/// pre-state watermark (a failing registration moves nothing).
fn outcome_of(
    reason: ValidationReason,
    tx: &TransactionView<'_>,
    max_known: u32,
) -> ReceiveTransactionOutcome {
    use ReceiveTransactionOutcome as O;
    use ValidationReason as R;
    match reason {
        R::NodeIdOutOfRange
        | R::UnseededActor
        | R::VoteTargetUnknown
        | R::InsufficientBalance
        | R::UtxoUnavailable => O::Deferred,
        R::RegistrationWatermark => match tx.as_registration() {
            Some(reg) if reg.new_node_id() > max_known.saturating_add(1) => O::Deferred,
            _ => O::Rejected,
        },
        R::DuplicatePublicKey => O::AlreadyConfirmed,
        _ => O::Rejected,
    }
}

impl<
    Crypto: CryptoTrait,
    Storage: StorageTrait,
    Config: ChainConfigTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH_MAX: u32,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const AVAILABLE_UTXO_BYTES: usize,
    const MEMPOOL_COMPACT_BYTES: usize,
    const MEMPOOL_MAX_ENTRIES: usize,
>
    Blockchain<
        Crypto,
        Storage,
        Config,
        MAX_NODES,
        SNAKE_CHAIN_LENGTH_MAX,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        AVAILABLE_UTXO_BYTES,
        MEMPOOL_COMPACT_BYTES,
        MEMPOOL_MAX_ENTRIES,
    >
{
    /// FR14 in Ready (Story 7.3 AC9): classifies `tx` and, when it is
    /// Accepted or Deferred, adds it to the mempool with its fee and marker
    /// (FR31); an FR33 refusal is Rejected (DEC-351).
    pub(super) fn classify_and_admit(
        &mut self,
        tx: TransactionView<'_>,
    ) -> ReceiveTransactionOutcome {
        use ReceiveTransactionOutcome as O;
        let is_deferred = match self.classify_transaction(&tx) {
            O::AcceptedToMempool => false,
            O::Deferred => true,
            settled => return settled,
        };
        let fee = transaction_fee(&tx, false);
        match self.mempool.try_add(tx, fee, is_deferred) {
            AddResult::Admitted if is_deferred => O::Deferred,
            AddResult::Admitted => O::AcceptedToMempool,
            AddResult::Rejected => O::Rejected,
        }
    }

    /// The FR14 classification of `tx` against the head `h`, in DEC-350's
    /// cheap-first order; the first step that decides wins. Mutates nothing it
    /// does not restore: the dry-run is undone by the step's exact inverse.
    fn classify_transaction(&mut self, tx: &TransactionView<'_>) -> ReceiveTransactionOutcome {
        use ReceiveTransactionOutcome as O;
        let head = self.active_chain_head_idx;
        let Some(h) = self.blocks.get(head).map(|entry| entry.sequence()) else {
            // A Ready node always holds its head; were it missing, nothing
            // can be judged now.
            return O::Deferred;
        };
        let Some(s) = h.checked_add(1).filter(|s| *s != u32::MAX) else {
            return O::Rejected; // FR53: no block can follow the ceiling.
        };

        // 1. The transaction alone (AC3): DEC-223's size, the per-transaction
        //    Tier 1 at `s`, and no carry-forward — a zero-input complex
        //    transaction is the block creator's own (FR51), never submitted.
        if exceeds_block_room(tx.len(), self.enforceable_block_size_limit())
            || tx.as_complex().is_some_and(|cx| cx.input_count() == 0)
        {
            return O::Rejected;
        }
        match tier1_transaction(
            tx,
            s,
            self.enforceable_active_chain_length(),
            &self.node_zero_public_key,
            &self.crypto,
        ) {
            Ok(utxo_outputs) if utxo_outputs > u32::from(self.enforceable_max_utxo_outputs()) => {
                return O::Rejected;
            }
            Ok(_) => {}
            // FR14 has no upper bound: an anchor or a UTXO block at or above
            // `h + 1` waits for the chain.
            Err(
                Tier1Failure::AnchorSequenceNotBeforeBlock | Tier1Failure::UtxoInputNotBeforeBlock,
            ) => return O::Deferred,
            Err(_) => return O::Rejected,
        }

        // 2. The mempool, Deferred entries included (AC10, DEC-354 keys).
        if self
            .mempool
            .entries_iter()
            .any(|entry| same_key(&entry, tx))
        {
            return O::DuplicateInMempool;
        }

        // 3. Already on the active chain (DEC-349, DEC-352, DEC-353). A
        //    failed read is the node's own fault, never a verdict: the
        //    transaction may be on the chain, so it is at most Deferred — after
        //    the dry-run has verified its signatures (DEC-350).
        let scan_fault = match self.already_confirmed(tx, head, s) {
            Ok(true) => return O::AlreadyConfirmed,
            Ok(false) => false,
            Err(()) => true,
        };

        // 4. The dry-run of the shared step for `h + 1` on the head's
        //    post-state: served chain-info (`h + 1`'s pre-state, R1), every
        //    signature verified, then undone exactly.
        let max_known = self.node_info.max_known_node_id();
        let mut derivation = BlockDerivation {
            chain_info_count: self.registered_count(true),
            total_fees: 0,
            replay_reward: 0,
            utxo_outputs: 0,
            liveness: None,
            hold_exit: None,
        };
        let projection = Projection::COMPLETE;
        let outcome =
            match self.apply_transaction(tx, NONE_REF, head, s, &projection, &mut derivation) {
                Ok(()) => {
                    self.invert_transaction(tx, head, false);
                    O::AcceptedToMempool
                }
                Err(ProcessingError::Invalid { reason, .. }) => outcome_of(reason, tx, max_known),
                // A failed read or an inconsistent ancestry is the node's own.
                Err(_) => O::Deferred,
            };
        if scan_fault && outcome == O::AcceptedToMempool {
            O::Deferred
        } else {
            outcome
        }
    }

    /// Whether a transaction with `tx`'s uniqueness key is on the active chain
    /// (ending at `head`) above its inclusion floor and the window's of the
    /// next block `s` (DEC-349): a registration by its registered key
    /// (DEC-352); a balance-only one by the window scan; a UTXO-bearing one
    /// only when every UTXO input's available bit is 0 — an equivalent on the
    /// chain spent them all, so one set bit rules it out with no read
    /// (DEC-353). `Err` on a failed read.
    pub(super) fn already_confirmed(
        &self,
        tx: &TransactionView<'_>,
        head: u32,
        s: u32,
    ) -> Result<bool, ()> {
        if let Some(reg) = tx.as_registration() {
            return Ok(self.node_info.key_is_registered(reg.new_public_key()));
        }
        if !is_balance_only(tx) {
            let Some(cx) = tx.as_complex() else {
                return Ok(false);
            };
            let every_utxo_spent = cx.inputs().filter_map(|input| input.as_utxo()).all(|ui| {
                matches!(
                    self.ancestor_at(head, ui.block_sequence()),
                    Ok(Some(slot)) if self.blocks.utxo_available(slot, ui.output_index() as usize)
                        != Some(true)
                )
            });
            if !every_utxo_spent {
                return Ok(false);
            }
        }
        let floor = inclusion_floor(tx).max(self.window_floor(s));
        self.ancestry_carries(head, floor, &mut |included| same_key(included, tx))
    }
}
