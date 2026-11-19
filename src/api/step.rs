//! The FR6 per-block step: derive and commit a block, transaction apply and
//! inverse, signature and UTXO checks (Stories 5.3, 6.0, 6.8).

use super::*;

/// FR36(b): the transaction-fee total the per-block step credited to the
/// block's creator, recomputed from the payload for the committed-block undo
/// (Story 6.3 AC2) — the sums of `apply_transaction` / `apply_complex`, whose
/// checks made them exact — and the block's UTXO-output count, its own
/// available-UTXO bits (the AC2 precondition of the undo).
pub(super) fn fees_and_utxo_outputs(view: &BlockView<'_>) -> (u64, usize) {
    let Some(txs) = view.transactions() else {
        return (0, 0);
    };
    let mut outputs = 0usize;
    let is_genesis_zero = view.sequence() == 0;
    let mut total = 0u64;
    for tx in txs.iter() {
        if let Some(nt) = tx.as_node_transfer() {
            total = total.wrapping_add(nt.fee() as u64);
        } else if let Some(reg) = tx.as_registration() {
            if !is_genesis_zero {
                total = total.wrapping_add(reg.fee());
            }
        } else if let Some(cx) = tx.as_complex() {
            outputs += cx
                .outputs()
                .filter(|output| output.as_utxo().is_some())
                .count();
            if cx.input_count() == 0 {
                continue;
            }
            let mut in_sum: u64 = 0;
            for input in cx.inputs() {
                if let Some(bi) = input.as_balance() {
                    in_sum = in_sum.saturating_add(bi.amount());
                } else if let Some(ui) = input.as_utxo() {
                    in_sum = in_sum.saturating_add(ui.amount());
                }
            }
            let mut out_sum: u64 = 0;
            for output in cx.outputs() {
                if let Some(uo) = output.as_utxo() {
                    out_sum = out_sum.saturating_add(uo.amount());
                } else if let Some(bo) = output.as_balance() {
                    out_sum = out_sum.saturating_add(bo.amount());
                }
            }
            total = total.wrapping_add(in_sum.saturating_sub(out_sum));
        }
    }
    (total, outputs)
}

impl<
    Crypto: CryptoTrait,
    Storage: StorageTrait,
    Config: ChainConfigTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH_MAX: u32,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const MAX_BLOCK_UTXO_OUTPUT: usize,
>
    Blockchain<
        Crypto,
        Storage,
        Config,
        MAX_NODES,
        SNAKE_CHAIN_LENGTH_MAX,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        MAX_BLOCK_UTXO_OUTPUT,
    >
{
    /// The FR6 per-block step (Story 6.0 AC1): validates one block against the
    /// FR6 invariant set **and** applies its effects to the derived projection.
    /// Shared by the FR3 forward walk, the Ready forward extension and the
    /// genesis node (D6), so there is one implementation of both.
    ///
    /// Two halves, so the direct head extension can persist the block between
    /// them (AC3): [`Self::derive_block`] runs every check and every invertible
    /// effect, and [`Self::commit_block`] the vote apply and the commit tail.
    /// Either half leaves `node_info`, the vote engine, every available-UTXO
    /// bit and the watermark exactly as it found them when it returns `Err`
    /// (D1); the one exception is the floor seeding of a non-complete FR3
    /// pass, whose failure resets the whole pass.
    pub(super) fn validate_and_derive_block(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        prev_hash: Option<[u8; 32]>,
        projection: &mut Projection,
    ) -> Result<(), ProcessingError> {
        let derivation = self.derive_block(view, idx, prev_hash, projection)?;
        self.commit_block(view, idx, derivation)
    }

    /// The fallible half of the per-block step, in the D1 order: block-level
    /// checks; per transaction, its checks and then its invertible effects;
    /// the balance-block checks (D9); the creator-credit overflow check. On
    /// `Err` the effects already applied are inverted, newest first.
    ///
    /// Every check reads the state derived from the preceding blocks and from
    /// the earlier transactions of this block, so a balance spent by tx 1
    /// limits tx 2, and a key registered by tx 1 is a duplicate in tx 2. In a
    /// non-complete FR3 projection (D3) the per-node state-dependent checks
    /// are gated on the actor being seeded: a window-anchored candidate trusts
    /// history it cannot re-derive.
    pub(super) fn derive_block(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        prev_hash: Option<[u8; 32]>,
        projection: &mut Projection,
    ) -> Result<BlockDerivation, ProcessingError> {
        let seq = view.sequence();
        // FR54 genesis exceptions: block #0 waives no-self-vote / anchor /
        // watermark-`+1` and mints currency (FR54(d)); blocks #0/#1 are
        // FR36-exempt.
        let is_genesis_zero = seq == 0;
        let is_genesis = is_genesis_zero || seq == 1;
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };

        // --- FR6 block-level invariants (AC2) ---------------------------------
        // (a) size ≤ chain-config limit — but only once that limit is durably
        // locked (FR9). While the configuration is merely tentative this yields
        // the structural ceiling, so the check cannot produce `Invalid` and
        // cannot delete; the enforcement is re-run against the real limit at the
        // durable lock, which is one of the two moments FR9 names.
        if view.len() > self.enforceable_block_size_limit() as usize {
            return Err(invalid(ValidationReason::BlockTooLarge));
        }
        // (b) previous_hash links to the immediately-preceding block (the FR3
        //     anchor has no in-segment predecessor → `prev_hash == None`).
        if let Some(ph) = prev_hash
            && view.previous_hash() != &ph[..]
        {
            return Err(invalid(ValidationReason::PreviousHashMismatch));
        }
        // (b2) Story 6.7 AC4: the FR27 rules of a deviation-bearing branch and
        //      the FR48 clean slot, against the run state below this block
        //      (`active_open_run`, the parent's): RAM unless a run is open.
        self.check_run_rules(view, idx, projection)?;
        // (c) block-creator signature. Skipped when the creator's key is not
        //     yet derivable (pre-seed zone → trusted); node #0 always resolves
        //     to the FR69 trust anchor. In a complete projection a non-derivable
        //     creator past block #0 is exact evidence of invalidity (D3).
        //     A block whose signature already verified against its own
        //     ancestry key is not verified again (Story 6.2 D6, DEC-157).
        if !self
            .blocks
            .get(idx)
            .is_some_and(|entry| entry.is_signature_verified())
        {
            match self.verify_block_creator_signature(view) {
                Some(false) => return Err(invalid(ValidationReason::CreatorSignatureInvalid)),
                Some(true) => {
                    self.blocks.mark_signature_verified(idx);
                }
                None if projection.complete && !is_genesis_zero => {
                    return Err(invalid(ValidationReason::UnseededActor));
                }
                None => {}
            }
        }

        let mut derivation = BlockDerivation {
            total_fees: 0,
            utxo_outputs: 0,
        };
        // How many transactions have applied their effects, for the prefix
        // inversion on a later failure.
        let mut applied = 0usize;

        match view.payload_type() {
            PAYLOAD_TYPE_BALANCE => {
                let payload = view
                    .balances()
                    .ok_or(invalid(ValidationReason::MalformedPayload))?;
                // FR6 node cap (DEC-228): no balance block names an id at or
                // above the chain's `max_node_count`.
                if payload.max_node_id() >= self.max_node_count() {
                    return Err(invalid(ValidationReason::NodeCountExceeded));
                }
                if projection.complete || projection.saw_balance_block {
                    // Every balance block carries `max_node_id` == the
                    // forward-tracked watermark at its sequence (FR50).
                    if payload.max_node_id() != self.node_info.max_known_node_id() {
                        return Err(invalid(ValidationReason::BalanceMaxNodeIdMismatch));
                    }
                } else {
                    // The earliest balance block of a non-complete FR3 pass
                    // initializes the watermark (FR3/FR54(h)).
                    let advanced = self
                        .node_info
                        .max_known_node_id()
                        .max(payload.max_node_id());
                    self.node_info.set_max_known_node_id(advanced);
                    projection.saw_balance_block = true;
                }
                // D9: the payload repeats the pre-state; it seeds only what a
                // non-complete projection does not know yet. DEC-177: a seeded
                // node whose vote is not yet known has its vote seeded by its
                // first entry at or after `a + H`, not compared.
                let mut floor_seeded = false;
                let mut vote_seeded_here = false;
                for info in payload.iter() {
                    let owner = info.owner();
                    // Node ids are contiguous: an entry beyond the watermark
                    // names no node (and would occupy a slot a later
                    // registration needs empty, D1 precondition 2).
                    if owner > payload.max_node_id() {
                        return Err(invalid(ValidationReason::NodeIdOutOfRange));
                    }
                    if self.node_info.is_seeded(owner) {
                        let vote_known = self.vote_seeded(owner, projection);
                        if !vote_known && seq >= projection.vote_seed_from {
                            vote_seeded_here = true;
                        }
                        let matches = self.node_info.balance_of(owner) == info.balance()
                            && (!vote_known
                                || self.vote_engine.accumulated_vote_of(owner)
                                    == info.vote_count())
                            && self
                                .node_info
                                .public_key_of(owner)
                                .is_some_and(|key| key[..] == *info.public_key());
                        if !matches {
                            return Err(invalid(ValidationReason::BalanceSnapshotMismatch));
                        }
                    } else if projection.complete {
                        // Defensive: unreachable while stride-1 registration
                        // and the owner bound hold. FR50 coverage: every
                        // registered node is seeded in a
                        // complete projection (D3).
                        return Err(invalid(ValidationReason::UnseededActor));
                    } else {
                        self.node_info
                            .seed_node(owner, info.public_key(), info.balance(), idx);
                        floor_seeded = true;
                    }
                }
                // The vote half of the floor seeding, and the DEC-177 vote seed.
                // A vote-seeded entry's `vote_count` was just shown equal, so
                // re-seeding it is a no-op.
                if (floor_seeded || vote_seeded_here)
                    && let Ok(v) = BlockView::from_bytes(view.serialized_bytes())
                {
                    self.vote_engine.seed_from_balance_block(v);
                }
            }
            PAYLOAD_TYPE_TRANSACTION => {
                let txs = view
                    .transactions()
                    .ok_or(invalid(ValidationReason::MalformedPayload))?;
                for tx in txs.iter() {
                    if let Err(e) =
                        self.apply_transaction(&tx, idx, seq, projection, &mut derivation)
                    {
                        self.invert_transactions(view, idx, applied);
                        return Err(e);
                    }
                    applied += 1;
                }
                // DEC-177: the first registration inside a non-complete segment
                // marks every later node id as registered here.
                if !projection.complete && projection.first_segment_registration == u32::MAX {
                    for tx in txs.iter() {
                        if let Some(reg) = tx.as_registration() {
                            projection.first_segment_registration = reg.new_node_id();
                            break;
                        }
                    }
                }
                // FR6 registration/complex mutual-exclusivity is intrinsic (decided
                // from block bytes) and owned by the Tier-1 intake gate, which every
                // admitted block passed — not re-checked here.
            }
            PAYLOAD_TYPE_CHAIN_CONFIG => {
                // FR6 chain-config compliance + the FR8 final check, content half
                // (Story 5.9, AC3): every chain-config block on the candidate must
                // carry content byte-identical to the configuration this node
                // holds — the durable-locked one once the FR8 lock is engaged, and
                // the tentatively-loaded one while still Collecting. One
                // comparison serves both: FR8's final check *is* FR6 compliance
                // measured against the not-yet-committed content.
                //
                // The comparison is over the **content region**, not the whole
                // payload: the payload also carries node #0's content signature,
                // which the FR7 Tier-1 gate owns. A payload whose envelope does
                // not frame carries no content region and so cannot match.
                if let Some(held) = self.held_chain_config_content()
                    && view.chain_config().map(|config| config.content()) != Some(held)
                {
                    return Err(invalid(ValidationReason::ChainConfigMismatch));
                }
            }
            _ => {
                // Approval evidence (payload_type 4): its Tier 3 (Story 6.7
                // AC5) runs after this step at the two Tier-3 drivers
                // (`judge_evidence_step`), off genesis' static path (D6). The
                // shared tail applies its FR37 vote effects.
            }
        }

        // I-09 (FR9 Tier 3; Story 6.2 D5, DEC-156): the vote header snapshots
        // against the parent state, which the vote engine still holds — its
        // apply runs in `commit_block`. After the balance-block seeding above,
        // so a floor-seeded creator is judged. Genesis #0 holds as built: I(0) = 0.
        // A deviation's first-voted node must exist, as every node id a
        // transaction names must (FR6): a partial projection cannot judge its
        // snapshot, but it can bound the id.
        let first_voted = view.first_voted_node();
        if first_voted != view.creator()
            && let Err(reason) = self.check_node_id_in_range(first_voted)
        {
            self.invert_transactions(view, idx, applied);
            return Err(invalid(reason));
        }
        // DEC-177: a node's vote is judged only once it is vote-seeded — by an
        // earlier block, or by this balance block's own entry at or after
        // `a + H` (its pointer moves only at the commit).
        let seeds_here = |node: u32| {
            seq >= projection.vote_seed_from
                && view
                    .balances()
                    .is_some_and(|payload| payload.iter().any(|info| info.owner() == node))
        };
        let header = self
            .vote_engine
            .check_header(view, projection.complete, |node| {
                self.vote_seeded(node, projection) || seeds_here(node)
            });
        if header != Ok(true) {
            self.invert_transactions(view, idx, applied);
            return Err(match header {
                Err(e) => ProcessingError::Vote(e),
                _ => invalid(ValidationReason::VoteHeaderMismatch),
            });
        }

        // FR36 creator credit, checked here so the commit tail cannot fail.
        if !is_genesis && self.node_info.is_seeded(view.creator()) {
            let fits = (view.mined_amount() as u64)
                .checked_add(derivation.total_fees)
                .and_then(|credit| {
                    self.node_info
                        .balance_of(view.creator())
                        .checked_add(credit)
                });
            if fits.is_none() {
                self.invert_transactions(view, idx, applied);
                return Err(invalid(ValidationReason::BalanceOverflow));
            }
        }
        Ok(derivation)
    }

    /// The second half of the per-block step: the FR37 vote apply — the last
    /// fallible operation, and atomic — then the commit tail (D1 precondition
    /// 5), the effects no later check of the block reads: the FR36 creator
    /// credit (`mined_amount` + fees; FR36(c) is Epic 9), the D9 seed-source
    /// moves and the block's own available-UTXO bits. On a vote failure the
    /// effects of [`Self::derive_block`] are inverted.
    pub(super) fn commit_block(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        derivation: BlockDerivation,
    ) -> Result<(), ProcessingError> {
        if let Ok(v) = BlockView::from_bytes(view.serialized_bytes())
            && let Err(e) = self.vote_engine.apply_block(v)
        {
            self.invert_transactions(view, idx, usize::MAX);
            return Err(ProcessingError::Vote(e));
        }
        let seq = view.sequence();
        if seq > 1 && self.node_info.is_seeded(view.creator()) {
            self.node_info.credit(
                view.creator(),
                view.mined_amount() as u64 + derivation.total_fees,
            );
        }
        if let Some(payload) = view.balances() {
            for info in payload.iter() {
                self.node_info.move_seed_source(info.owner(), idx);
            }
        }
        // A block never spends its own outputs (Tier-1 causality), so its
        // bits become spendable only by descendants.
        for bit in 0..derivation.utxo_outputs {
            self.blocks.set_utxo_available(idx, bit, true);
        }
        // Story 6.7: the block's Tier-3 signature checks are final (D2), and
        // the open deviation run moves with the head (D4).
        self.blocks.mark_signatures_accepted(idx);
        self.active_open_run = run_after(self.active_open_run, view);
        Ok(())
    }

    /// Checks one transaction and applies its effects, atomically: on `Err`
    /// nothing of this transaction remains applied.
    fn apply_transaction(
        &mut self,
        tx: &TransactionView<'_>,
        idx: u32,
        seq: u32,
        projection: &Projection,
        derivation: &mut BlockDerivation,
    ) -> Result<(), ProcessingError> {
        let is_genesis_zero = seq == 0;
        let complete = projection.complete;
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };
        let vote = tx.vote();
        if let Some(nt) = tx.as_node_transfer() {
            let init = nt.initializer();
            let receiver = nt.receiver();
            // [A] Complete projection: an unseeded initializer transacts
            // before it exists (D3). Non-complete: trusted pre-window history.
            if complete && !is_genesis_zero && !self.node_info.is_seeded(init) {
                return Err(invalid(ValidationReason::UnseededActor));
            }
            // FR6 node-existence bound: the initializer (input) and the
            // receiver (output) must name nodes that can exist
            // (`id <= max_known_node_id`) — checkable even when unseeded.
            if projection.roster_bounded && !is_genesis_zero {
                self.check_node_id_in_range(init).map_err(&invalid)?;
                self.check_node_id_in_range(receiver).map_err(&invalid)?;
            }
            // State-dependent FR6 checks apply once the initializer is
            // derivable. The intrinsic invariants (no-self-vote,
            // anchor-before-block) are owned by the Tier-1 gate.
            if !is_genesis_zero && self.node_info.is_seeded(init) {
                self.check_vote_target(vote).map_err(&invalid)?;
                if !self.signatures_accepted(idx) && !self.verify_tx_signature(tx.as_bytes(), init)
                {
                    return Err(invalid(ValidationReason::TransactionSignatureInvalid));
                }
            }
            let fee = nt.fee() as u64;
            let debit = nt
                .amount()
                .checked_add(fee)
                .ok_or(invalid(ValidationReason::ValueOverflow))?;
            // FR54(d): the genesis self-transfer *creates* currency — no debit.
            let debits = !is_genesis_zero && self.node_info.is_seeded(init);
            let credits = self.node_info.is_seeded(receiver);
            if debits && self.node_info.balance_of(init) < debit {
                return Err(invalid(ValidationReason::InsufficientBalance));
            }
            // A self-transfer credits back less than it debited.
            if credits
                && !(debits && receiver == init)
                && self
                    .node_info
                    .balance_of(receiver)
                    .checked_add(nt.amount())
                    .is_none()
            {
                return Err(invalid(ValidationReason::BalanceOverflow));
            }
            let total_fees = derivation
                .total_fees
                .checked_add(fee)
                .ok_or(invalid(ValidationReason::ValueOverflow))?;
            if debits {
                self.node_info.debit(init, debit);
            }
            if credits {
                self.node_info.credit(receiver, nt.amount());
            }
            derivation.total_fees = total_fees;
        } else if let Some(reg) = tx.as_registration() {
            let node_id = reg.new_node_id();
            let init = reg.initializer();
            // [A] Complete projection: the registering initializer must be an
            // existing (seeded) node (block #0's node-#0 self-registration is
            // the FR54 bootstrap exception).
            if complete && !is_genesis_zero && !self.node_info.is_seeded(init) {
                return Err(invalid(ValidationReason::UnseededActor));
            }
            // FR6 node-existence bound on the initializer. (`new_node_id` is
            // bounded by the monotonicity check, not this range check.)
            if projection.roster_bounded && !is_genesis_zero {
                self.check_node_id_in_range(init).map_err(&invalid)?;
            }
            let debits = !is_genesis_zero && self.node_info.is_seeded(init);
            let debit = reg
                .registration_price()
                .checked_add(reg.fee())
                .ok_or(invalid(ValidationReason::ValueOverflow))?;
            // FR6 node cap (DEC-228): every registered id is below the chain's
            // `max_node_count`, judged from the transaction and the held
            // configuration alone, so in every projection and on every build.
            if !is_genesis_zero && node_id >= self.max_node_count() {
                return Err(invalid(ValidationReason::NodeCountExceeded));
            }
            if !is_genesis_zero {
                // FR6 registration monotonicity: `new_node_id == running
                // watermark + 1`, authoritative once the watermark is
                // established (a complete projection, or after the first
                // balance block of a window-anchored one).
                if complete || projection.saw_balance_block {
                    let expected = self.node_info.max_known_node_id().wrapping_add(1);
                    if node_id != expected {
                        return Err(invalid(ValidationReason::RegistrationWatermark));
                    }
                }
                if debits {
                    self.check_vote_target(vote).map_err(&invalid)?;
                    if !self.signatures_accepted(idx)
                        && !self.verify_tx_signature(tx.as_bytes(), init)
                    {
                        return Err(invalid(ValidationReason::TransactionSignatureInvalid));
                    }
                    if self.node_info.balance_of(init) < debit {
                        return Err(invalid(ValidationReason::InsufficientBalance));
                    }
                }
            }
            // [E] FR6 registration uniqueness, against the seeded roster —
            // earlier registrations of this block included.
            if self.node_info.key_is_registered(reg.new_public_key()) {
                return Err(invalid(ValidationReason::DuplicatePublicKey));
            }
            // The fee goes to the creator whether or not the initializer is
            // derivable yet, as for every other transaction kind: a seeded
            // creator's balance must stay exact, or a later balance block
            // listing it fails the D9 equality.
            let total_fees = if is_genesis_zero {
                derivation.total_fees
            } else {
                derivation
                    .total_fees
                    .checked_add(reg.fee())
                    .ok_or(invalid(ValidationReason::ValueOverflow))?
            };
            // Effects, after every check. `registration_price` is absorbed
            // (debited, credited to no node); the fee goes to the creator.
            if debits {
                self.node_info.debit(init, debit);
            }
            // Genesis #0 does not advance the watermark (FR54(h)). The id is
            // below `max_node_count ≤ MAX_NODES` (DEC-228), so it has a slot.
            if !is_genesis_zero {
                let advanced = self.node_info.max_known_node_id().max(node_id);
                self.node_info.set_max_known_node_id(advanced);
            }
            self.node_info
                .register_node(node_id, reg.new_public_key(), idx);
            derivation.total_fees = total_fees;
        } else if let Some(cx) = tx.as_complex() {
            // How many inputs and outputs applied, for the partial inversion.
            let mut applied = (0usize, 0usize);
            let result = self.apply_complex(tx, idx, seq, projection, derivation, &mut applied);
            if result.is_err() {
                self.invert_complex(&cx, idx, applied.0, applied.1, is_genesis_zero);
            }
            result?;
        } else {
            return Err(invalid(ValidationReason::MalformedPayload));
        }
        Ok(())
    }

    /// The complex-transaction arm of [`Self::apply_transaction`]: FR6 value
    /// accounting over every input and output (Story 6.8). Effects apply in
    /// order — a later input of the same initializer sees the earlier debit —
    /// and `applied` counts how many inputs and outputs applied, for the
    /// caller's partial inversion.
    fn apply_complex(
        &mut self,
        tx: &TransactionView<'_>,
        idx: u32,
        seq: u32,
        projection: &Projection,
        derivation: &mut BlockDerivation,
        applied: &mut (usize, usize),
    ) -> Result<(), ProcessingError> {
        let is_genesis_zero = seq == 0;
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };
        let vote = tx.vote();
        let cx = tx
            .as_complex()
            .ok_or(invalid(ValidationReason::MalformedPayload))?;
        // Every input declares its amount (DEC-131) and Tier 1 has checked
        // both sums against `u64` and `Σ inputs ≥ Σ outputs` (DEC-011).
        let mut in_sum: u64 = 0;
        let mut out_sum: u64 = 0;
        for input in cx.inputs() {
            if let Some(bi) = input.as_balance() {
                let binit = bi.initializer();
                if projection.complete && !is_genesis_zero && !self.node_info.is_seeded(binit) {
                    return Err(invalid(ValidationReason::UnseededActor));
                }
                if projection.roster_bounded && !is_genesis_zero {
                    self.check_node_id_in_range(binit).map_err(&invalid)?;
                }
                if !is_genesis_zero && self.node_info.is_seeded(binit) {
                    self.check_vote_target(vote).map_err(&invalid)?;
                    if self.node_info.balance_of(binit) < bi.amount() {
                        return Err(invalid(ValidationReason::InsufficientBalance));
                    }
                    self.node_info.debit(binit, bi.amount());
                }
                in_sum = in_sum.saturating_add(bi.amount());
            } else if let Some(ui) = input.as_utxo() {
                // [H] ADR-016: resolve along this block's own ancestry and
                // spend. A non-complete candidate trusts a reference below its
                // anchor (DEC-129), declared amount included. The input's
                // signature is Story 7.1 (I-21).
                let parent = self
                    .blocks
                    .get(idx)
                    .ok_or(ProcessingError::MissingBlock)?
                    .parent_ref();
                self.resolve_and_spend_utxo(
                    parent,
                    seq,
                    ui.block_sequence(),
                    ui.output_index(),
                    ui.amount(),
                    !projection.complete,
                )
                .map_err(|e| match e {
                    UtxoSpendError::Invalid(reason) => invalid(reason),
                    UtxoSpendError::StorageRead => ProcessingError::StorageRead,
                    UtxoSpendError::MissingBlock => ProcessingError::MissingBlock,
                })?;
                in_sum = in_sum.saturating_add(ui.amount());
            }
            applied.0 += 1;
        }
        // Outputs after the inputs. A UTXO output's bit is set in the commit
        // tail; here it only takes its stream position, held within the
        // configuration's cap (I-07, DEC-133).
        let max_utxo_outputs = self.held_max_utxo_outputs() as usize;
        for output in cx.outputs() {
            if let Some(uo) = output.as_utxo() {
                if derivation.utxo_outputs >= max_utxo_outputs {
                    return Err(invalid(ValidationReason::TooManyUtxoOutputs));
                }
                derivation.utxo_outputs += 1;
                out_sum = out_sum.saturating_add(uo.amount());
            } else if let Some(bo) = output.as_balance() {
                if projection.roster_bounded && !is_genesis_zero {
                    self.check_node_id_in_range(bo.receiver())
                        .map_err(&invalid)?;
                }
                if self.node_info.is_seeded(bo.receiver()) {
                    if self
                        .node_info
                        .balance_of(bo.receiver())
                        .checked_add(bo.amount())
                        .is_none()
                    {
                        return Err(invalid(ValidationReason::BalanceOverflow));
                    }
                    self.node_info.credit(bo.receiver(), bo.amount());
                }
                out_sum = out_sum.saturating_add(bo.amount());
            }
            applied.1 += 1;
        }
        // [D] The fee is the surplus over all inputs and outputs; a zero-input
        // carry-forward pays none (FR6).
        if cx.input_count() > 0 {
            let fee = in_sum.saturating_sub(out_sum);
            derivation.total_fees = derivation
                .total_fees
                .checked_add(fee)
                .ok_or(invalid(ValidationReason::ValueOverflow))?;
        }
        Ok(())
    }

    /// Inverts the effects of the first `count` transactions of `view` (all of
    /// them for `usize::MAX`), newest first — the D1 prefix inversion of
    /// [`Self::derive_block`]'s transaction effects. Undoing a *committed*
    /// block also needs the inverse of [`Self::commit_block`]'s effects, which
    /// [`Self::undo_committed_block`] adds around this call (Story 6.3):
    /// `VoteEngine::undo_block`, the block's own output bits, the seed-source
    /// restore by backward scan, and the creator credit. Each inverse is computed
    /// from the transaction bytes plus the current state, which, in reverse
    /// order, is the state right after that transaction applied. O(`count`²)
    /// transaction parses, on failure paths only.
    pub(super) fn invert_transactions(&mut self, view: &BlockView<'_>, idx: u32, count: usize) {
        let Some(txs) = view.transactions() else {
            return;
        };
        let is_genesis_zero = view.sequence() == 0;
        let count = count.min(txs.iter().count());
        for k in (0..count).rev() {
            let Some(tx) = txs.iter().nth(k) else {
                continue;
            };
            if let Some(nt) = tx.as_node_transfer() {
                if self.node_info.is_seeded(nt.receiver()) {
                    self.node_info.debit(nt.receiver(), nt.amount());
                }
                if !is_genesis_zero && self.node_info.is_seeded(nt.initializer()) {
                    let debit = nt.amount().wrapping_add(nt.fee() as u64);
                    self.node_info.credit(nt.initializer(), debit);
                }
            } else if let Some(reg) = tx.as_registration() {
                // Stride-1 on a bounded roster: the slot was empty and the
                // watermark one below the new id (D1 precondition 2).
                let node_id = reg.new_node_id();
                self.node_info.clear_node(node_id);
                if !is_genesis_zero {
                    self.node_info
                        .set_max_known_node_id(node_id.saturating_sub(1));
                }
                if !is_genesis_zero && self.node_info.is_seeded(reg.initializer()) {
                    let debit = reg.registration_price().wrapping_add(reg.fee());
                    self.node_info.credit(reg.initializer(), debit);
                }
            } else if let Some(cx) = tx.as_complex() {
                self.invert_complex(&cx, idx, usize::MAX, usize::MAX, is_genesis_zero);
            }
        }
    }

    /// Inverts the first `inputs` inputs and `outputs` outputs of a complex
    /// transaction. The balance inverses wrap, so they are exact in any order,
    /// and every spent UTXO bit is a distinct bit; a spend is re-resolved by
    /// the same ancestor walk, and a trusted below-anchor input (nothing was
    /// spent) re-resolves to nothing.
    fn invert_complex(
        &mut self,
        cx: &ComplexTransactionView<'_>,
        idx: u32,
        inputs: usize,
        outputs: usize,
        is_genesis_zero: bool,
    ) {
        for output in cx.outputs().take(outputs) {
            if let Some(bo) = output.as_balance()
                && self.node_info.is_seeded(bo.receiver())
            {
                self.node_info.debit(bo.receiver(), bo.amount());
            }
        }
        let parent = self
            .blocks
            .get(idx)
            .map_or(NONE_REF, |entry| entry.parent_ref());
        for input in cx.inputs().take(inputs) {
            if let Some(bi) = input.as_balance() {
                if !is_genesis_zero && self.node_info.is_seeded(bi.initializer()) {
                    self.node_info.credit(bi.initializer(), bi.amount());
                }
            } else if let Some(ui) = input.as_utxo()
                && let Ok(Some(slot)) = self.ancestor_at(parent, ui.block_sequence())
            {
                self.blocks
                    .set_utxo_available(slot, ui.output_index() as usize, true);
            }
        }
    }

    /// FR6 vote-target existence (AC5): the `vote` node id must name a node that
    /// exists on the candidate. Node ids are contiguous — registration is stride-1
    /// (`new_node_id == max_known_node_id + 1`) and ids are never renumbered — so a
    /// node exists iff its id is within `[0, max_known_node_id]`. This is a **range
    /// check against the watermark**, not a per-node `is_seeded` lookup, and that
    /// distinction is what keeps a **window-anchored** candidate correct: the
    /// watermark is set to the full node count (including pre-window nodes) by the
    /// window's first balance block (`max_node_id`, the `saw_balance_block`
    /// branch), whereas a *specific* pre-window node's in-window balance-block
    /// coverage (`is_seeded`) can fall later in the window than a transaction that
    /// legitimately votes for it (FR50 seed-source replays are emitted head-ward),
    /// which would produce a spurious `VoteTargetUnknown`. `vote == 0` is subsumed
    /// (`0 <= max`), kept explicit as the permanent FR37/FR54 node-#0 target that is
    /// valid even for a window-anchored candidate not containing block #0.
    ///
    /// The residual edge — a transaction validated *before* the window's first
    /// balance block, when the watermark is still 0 — is the same ordering
    /// assumption the FR6 registration-monotonicity check already relies on (it too
    /// reads `max_known_node_id`), so this introduces no new dependency.
    fn check_vote_target(&self, vote: u32) -> Result<(), ValidationReason> {
        if vote == 0 || vote <= self.node_info.max_known_node_id() {
            Ok(())
        } else {
            Err(ValidationReason::VoteTargetUnknown)
        }
    }

    /// FR6 node-existence bound (AC5) for a transaction-referenced node id (an
    /// initializer/spender on the input side, or a receiver on the output side).
    /// Contiguous ids ⇒ a node exists iff `id <= max_known_node_id`; an id beyond
    /// the watermark cannot name any node. Unlike the balance/signature checks this
    /// needs no per-node derived state, so it applies **even to a not-yet-seeded
    /// (pre-window) node** — the existence of an unseeded actor/receiver is still
    /// range-checkable. Callers gate it on the watermark being authoritative
    /// (`roster_bounded`): a window-anchored candidate with no balance block in the
    /// segment has no reliable bound and trusts the reference (AC4).
    fn check_node_id_in_range(&self, node_id: u32) -> Result<(), ValidationReason> {
        if node_id <= self.node_info.max_known_node_id() {
            Ok(())
        } else {
            Err(ValidationReason::NodeIdOutOfRange)
        }
    }

    /// Verifies the FR6 block-creator signature (AC2b) over the canonical signing
    /// preimage (the full block bytes with the header signature field
    /// zero-filled — exactly what `BlockBuilder::build_signed` signs; the
    /// signature is the last `SIGNATURE_SIZE` bytes of the `HEADER_SIZE` header). Returns
    /// `Some(valid)`, or `None` when the creator's public key is not yet derivable
    /// (pre-seed zone → the block is trusted, not re-proved). Node #0 resolves to
    /// the FR69 trust anchor (`node_zero_public_key`), available from construction.
    // Its own frame (stack budget, DEC-136): the 2 KB preimage is live only
    // here, never alongside the UTXO resolver's read buffer.
    #[inline(never)]
    pub(super) fn verify_block_creator_signature(&self, view: &BlockView) -> Option<bool> {
        let creator = view.creator();
        let key: [u8; PUBLIC_KEY_SIZE] = if creator == 0 {
            self.node_zero_public_key
        } else {
            *self.node_info.public_key_of(creator)?
        };
        let sig_off = HEADER_SIZE - SIGNATURE_SIZE;
        let bytes = view.serialized_bytes();
        let len = bytes.len();
        let mut preimage = [0u8; MAX_BLOCK_SIZE];
        preimage[..len].copy_from_slice(bytes);
        for b in preimage[sig_off..HEADER_SIZE].iter_mut() {
            *b = 0;
        }
        Some(verify_signature_bytes(
            &self.crypto,
            &preimage[..len],
            view.signature(),
            &key,
        ))
    }

    /// Whether `creator`'s key is the same on every branch that forks at or
    /// above the block at sequence `bound` (FR9 Tier 1 case (2); Story 6.2 D6,
    /// DEC-157; Story 6.3 D5, DEC-170): node #0 (the FR69 trust anchor), or a
    /// node seeded at or below `bound`, or whose seed source was released. Its
    /// registration then lies on the shared chain, and a key never changes
    /// after registration. Intake passes `S_tail` — every branch that can
    /// connect forks at or above `S_head − H ≥ S_tail` (DEC-207, DEC-208) — or,
    /// for a block whose parent is a flagged active-chain block, the parent's
    /// sequence (Story 6.4 D3); the chain-switch pre-pass passes the common
    /// ancestor. RAM only.
    pub(super) fn key_is_branch_independent(&self, creator: u32, bound: u32) -> bool {
        if creator == 0 {
            return true;
        }
        match self.node_info.seed_source_of(creator) {
            None => false,
            Some(SEED_SOURCE_RELEASED) => true,
            Some(source) => self
                .blocks
                .get(source)
                .is_some_and(|source| source.sequence() <= bound),
        }
    }

    /// Story 6.7 D2: whether the block at `idx` carries `BlockEntry` bit 6
    /// (its Tier-3 signature checks are final), so the per-block step does not
    /// verify its transaction signatures or its evidence again (a restore, a
    /// later walk).
    pub(super) fn signatures_accepted(&self, idx: u32) -> bool {
        self.blocks
            .get(idx)
            .is_some_and(|entry| entry.is_signatures_accepted())
    }

    /// Verifies a node-transfer / registration transaction signature (AC3): the
    /// signer (the `signer_node_id`, resolved to its derived key) signs the full
    /// transaction bytes with the trailing signature field zero-filled (the
    /// `*::new_signed` convention — the signature is the last `SIGNATURE_SIZE`
    /// bytes of the fixed-size transaction). Returns `false` on an unresolvable signer key or a
    /// bad signature. Only node-transfer / registration transactions have this
    /// fixed trailing-signature layout; balance/UTXO input signatures (embedded, no
    /// `new_signed` convention) are a deferred seam.
    fn verify_tx_signature(&self, tx_bytes: &[u8], signer_node_id: u32) -> bool {
        #[cfg(test)]
        crate::approval::test_seams::count(
            &crate::approval::test_seams::TX_SIGNATURE_VERIFICATIONS,
        );
        let Some(key) = self.node_info.public_key_of(signer_node_id) else {
            return false;
        };
        let key = *key;
        let len = tx_bytes.len();
        if !(SIGNATURE_SIZE..=REGISTRATION_SIZE).contains(&len) {
            return false;
        }
        let mut preimage = [0u8; REGISTRATION_SIZE];
        preimage[..len].copy_from_slice(tx_bytes);
        for b in preimage[len - SIGNATURE_SIZE..len].iter_mut() {
            *b = 0;
        }
        verify_signature_bytes(
            &self.crypto,
            &preimage[..len],
            &tx_bytes[len - SIGNATURE_SIZE..len],
            &key,
        )
    }

    /// ADR-016 UTXO-input resolver (Story 6.8; Story 6.0 reuses it in Ready).
    ///
    /// Resolves `(block_sequence, output_index)` for a block at
    /// `consuming_seq` whose parent is `parent_idx`, checks the input's
    /// `declared_amount`, spends the output and returns its address (the key
    /// the input's signature verifies against, Story 7.1):
    /// 1. causality: `block_sequence` must be below `consuming_seq` (Tier 1
    ///    owns this check; here it is a guard);
    /// 2. distance: `consuming_seq - block_sequence` must not exceed the
    ///    window `W` (FR14 freshness: the output was at or above `S_tail` when
    ///    the consuming block was made);
    /// 3. a RAM-only walk up `parent_ref` to the ancestor at `block_sequence`.
    ///    Only ancestors are visited, so a block on a side branch is never
    ///    found (FR39). Reaching `NONE_REF` first means the output lies below
    ///    the anchor: with `trust_below_anchor` (a window-anchored FR3
    ///    candidate) that is trusted pre-window history and returns `Ok(None)`,
    ///    with no bit to clear and the declared amount trusted (DEC-129);
    ///    otherwise (a genesis-anchored candidate, or the released tail in
    ///    Ready) it is `UtxoUnresolvable`;
    /// 4. the available-UTXO bit, before any read: a bit that is not 1 (the
    ///    output is spent, or lies beyond the block's outputs or the bitfield)
    ///    is `UtxoUnavailable` (DEC-132);
    /// 5. exactly one storage read of the referenced block, for the amount and
    ///    the address. A failed read is a local fault (`StorageRead`), never
    ///    `Invalid`, and so is a set bit whose output the bytes do not hold
    ///    (storage and RAM disagree); a `declared_amount` other than the
    ///    output's is `UtxoAmountMismatch`;
    /// 6. the bit is cleared.
    pub(crate) fn resolve_and_spend_utxo(
        &mut self,
        parent_idx: u32,
        consuming_seq: u32,
        block_sequence: u32,
        output_index: u16,
        declared_amount: u64,
        trust_below_anchor: bool,
    ) -> Result<Option<[u8; PUBLIC_KEY_SIZE]>, UtxoSpendError> {
        let ref_idx = match self.locate_utxo_source(parent_idx, consuming_seq, block_sequence)? {
            Some(ref_idx) => ref_idx,
            None if trust_below_anchor => return Ok(None),
            None => {
                return Err(UtxoSpendError::Invalid(ValidationReason::UtxoUnresolvable));
            }
        };
        let bit = output_index as usize;
        if self.blocks.utxo_available(ref_idx, bit) != Some(true) {
            return Err(UtxoSpendError::Invalid(ValidationReason::UtxoUnavailable));
        }

        // The bit said the output exists; bytes that lack it are the node's own
        // fault, not evidence against the spending block.
        let (address, amount) = self
            .utxo_output_of(ref_idx, output_index)?
            .ok_or(UtxoSpendError::StorageRead)?;
        if amount != declared_amount {
            return Err(UtxoSpendError::Invalid(
                ValidationReason::UtxoAmountMismatch,
            ));
        }

        self.blocks.set_utxo_available(ref_idx, bit, false);
        Ok(Some(address))
    }

    /// Steps 1–3 of [`Self::resolve_and_spend_utxo`], shared with the Tier 2
    /// structural check (Story 6.1 D6): causality, the `W` distance bound and
    /// the ancestor walk. `Ok(None)` when the walk reaches the anchor first —
    /// the output lies below it; each caller decides whether that is trusted.
    pub(super) fn locate_utxo_source(
        &self,
        parent_idx: u32,
        consuming_seq: u32,
        block_sequence: u32,
    ) -> Result<Option<u32>, UtxoSpendError> {
        let unresolvable = UtxoSpendError::Invalid(ValidationReason::UtxoUnresolvable);
        if block_sequence >= consuming_seq {
            return Err(unresolvable);
        }
        // The held configuration's `W`. In the FR3 pass the preload has already
        // made it the candidate's own, tentative or durable (DEC-129).
        if self
            .active_chain_length()
            .is_some_and(|w| consuming_seq - block_sequence > w)
        {
            return Err(unresolvable);
        }
        self.ancestor_at(parent_idx, block_sequence)
    }

    /// Reads the referenced block once for the output at `output_index`:
    /// `Ok(None)` when its bytes hold no such output, `StorageRead` on a
    /// failed read. Its own frame (stack budget, DEC-136): the read buffer
    /// must not merge into the per-block step's frame with the signature
    /// preimage.
    #[inline(never)]
    pub(super) fn utxo_output_of(
        &self,
        ref_idx: u32,
        output_index: u16,
    ) -> Result<Option<([u8; PUBLIC_KEY_SIZE], u64)>, UtxoSpendError> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self
            .view_retained(ref_idx, &mut buf)
            .ok_or(UtxoSpendError::StorageRead)?;
        Ok(utxo_output_at(&view, output_index))
    }
}
