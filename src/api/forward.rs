//! Ready forward extension of the active head, side branches and their Tier 2
//! (Stories 6.0, 6.1).

use super::*;

/// What [`Blockchain::walk_side_branch`] found on one side branch (Story 6.1
/// AC6): the FR21 sums it read and the lowest block whose Tier 2 failed.
struct SideWalk {
    /// The values of the active-chain blocks strictly above the connection
    /// point.
    active: u64,
    /// The values of the side blocks from the connection point (exclusive)
    /// up to the head.
    branch: u64,
    /// The lowest-sequence block whose Tier 2 failed, and the sum of the
    /// values from the head down to it, inclusive.
    failing: Option<(u32, u64)>,
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
    >
{
    /// FR9 Tier 2 of a side block in Ready (Story 6.1 D6): the UTXO-input
    /// structural completion of every complex transaction, along the block's
    /// own ancestry from `parent_idx`. A reference within `W` (`≥ s − W`) resolves to its
    /// block — in the window or the verification horizon — whose bytes must
    /// hold the output with the declared amount; one below the retained root
    /// is trusted pre-window history, as in the FR3 pass (DEC-129, DEC-131),
    /// which a side block inside FR58's bound never reaches once the horizon
    /// is full (Story 6.14). No available-UTXO bit is read: the bits follow the
    /// active chain, so whether the output is unspent on this branch is Tier 3.
    ///
    /// The other FR9 Tier 2 items join here and in the shared head step
    /// together: `mined_amount`, fee and price rules (7.2 / 7.3), the approval
    /// threshold (6.7), the structural `snake_chain` checks (9.2 / 9.3 / 9.5 /
    /// 6.6). Registration-key uniqueness is Tier 3 on a side branch (D6).
    pub(super) fn tier2_check(
        &self,
        view: &BlockView<'_>,
        idx: u32,
        parent_idx: u32,
    ) -> Result<(), ProcessingError> {
        // Story 6.7 AC4 (D4): the FR27 run rules and the FR48 clean slot for a
        // block off the active head, from its own ancestry (a header walk);
        // the configuration is locked in Ready. An unreadable ancestry judges
        // only the slot rule, which reads the block alone, and is then a local
        // fault: the block stays Stored and the driver judges it again.
        let h = self.verification_horizon();
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };
        match self.deviation_run_at(parent_idx) {
            Ok(run) => run_rules(view, run, h).map_err(invalid)?,
            Err(()) => {
                slot_rule(view, h).map_err(invalid)?;
                return Err(ProcessingError::StorageRead);
            }
        }
        let Some(txs) = view.transactions() else {
            return Ok(());
        };
        for tx in txs.iter() {
            let Some(cx) = tx.as_complex() else {
                continue;
            };
            for input in cx.inputs() {
                let Some(ui) = input.as_utxo() else {
                    continue;
                };
                let reason =
                    match self.locate_utxo_source(parent_idx, view.sequence(), ui.block_sequence())
                    {
                        Ok(None) => continue,
                        Ok(Some(ref_idx)) => {
                            match self.utxo_output_of(ref_idx, ui.output_index()) {
                                Ok(Some((_, amount))) if amount == ui.amount() => continue,
                                Ok(Some(_)) => ValidationReason::UtxoAmountMismatch,
                                Ok(None) => ValidationReason::UtxoUnresolvable,
                                Err(_) => return Err(ProcessingError::StorageRead),
                            }
                        }
                        Err(UtxoSpendError::Invalid(reason)) => reason,
                        Err(_) => return Err(ProcessingError::MissingBlock),
                    };
                return Err(ProcessingError::Invalid {
                    block_idx: idx,
                    reason,
                });
            }
        }
        Ok(())
    }

    /// Judges a prospective extension of the active head — a direct one at
    /// intake (AC3, before it is stored) or a stored child (AC4) — in the
    /// complete context (D3): first the FR48 window gate, then the fallible
    /// half of the per-block step. On `Valid` its invertible effects are
    /// applied; otherwise the derived state is as it was (D1). `idx` is the
    /// block's slot, already holding its entry.
    pub(super) fn judge_head_extension(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        tail: u32,
    ) -> Extension {
        let head = self.active_chain_head_idx;
        let Some(head_hash) = self.blocks.get(head).map(|entry| *entry.hash()) else {
            return Extension::Local;
        };
        // FR48 window gate (9.1): an extension that would make the active
        // chain longer than `W`, measured from `tail`, drops `tail`, which its
        // binding must allow. `tail` is the physical tail, or a chain-switch
        // replay's virtual one (Story 6.3 D3). `W` is read now (FR56), never
        // the capacity.
        let mut advance = None;
        if let Some(w) = self.active_chain_length() {
            let (Some(tail_entry), Some(head_entry)) =
                (self.blocks.get(tail), self.blocks.get(head))
            else {
                return Extension::Local;
            };
            // New length `S_head + 1 − S_tail + 1` exceeds `W`.
            let full = (head_entry.sequence() + 1).saturating_sub(tail_entry.sequence()) >= w;
            // DEC-204: the block the extension drops, if any, is evaluated
            // against its binding. A dropped block that is not retained cannot
            // be evaluated: a local failure, never trust.
            match self.dropped_by_extension(head, tail, w) {
                Ok(Some(dropped)) => {
                    let Ok(obligation) = classify_tail_drop(&self.blocks, &self.node_info, dropped)
                    else {
                        return Extension::Local;
                    };
                    if tail_drop_binding(obligation, view) == TailBinding::Invalid {
                        return Extension::Invalid;
                    }
                }
                Ok(None) => {}
                Err(()) => return Extension::Local,
            }
            if full {
                // FR21 (iii): the block that becomes `S_tail` leaves every
                // sum; its value is read now, before anything is mutated, so
                // a failed read is a local failure (Story 6.1 D1).
                let Some(step) = self.new_tail_step(tail) else {
                    return Extension::Local;
                };
                advance = Some(step);
            }
        }
        // The counter's tail: without it the evidence check has no `A'`.
        let Some(counter_tail) = self.blocks.get(tail).map(|e| e.sequence()) else {
            return Extension::Local;
        };
        let mut projection = Projection {
            counter_tail,
            ..Projection::COMPLETE
        };
        match self
            .derive_block(view, idx, Some(head_hash), &mut projection)
            .and_then(|derivation| {
                self.judge_evidence_step(view, idx, &projection)
                    .map(|()| derivation)
            }) {
            Ok(derivation) => Extension::Valid {
                advance,
                derivation,
            },
            Err(err) if is_evidence(&err) => Extension::Invalid,
            Err(_) => Extension::Local,
        }
    }

    /// DEC-204 — the block an extension of `head` at `S_head + 1` drops: block
    /// `S_head + 1 − W`, wherever the walk stands — the tail when the window is
    /// full, a block below a window a chain-switch backward walk shortened
    /// otherwise (Story 6.14's horizon). `Ok(None)` while `S_head + 1 < W` (the
    /// growth phase drops nothing); `Err` when either end or the dropped block
    /// is not retained, a local failure. RAM only. Shared by the extension's
    /// FR48 gate and the FR12 replay-completion check (Story 6.4 AC5.4).
    fn dropped_by_extension(&self, head: u32, tail: u32, w: u32) -> Result<Option<u32>, ()> {
        let (Some(tail_entry), Some(head_entry)) = (self.blocks.get(tail), self.blocks.get(head))
        else {
            return Err(());
        };
        let sequence = head_entry.sequence() + 1;
        if sequence < w {
            return Ok(None);
        }
        if sequence.saturating_sub(tail_entry.sequence()) >= w {
            return Ok(Some(tail));
        }
        match self.ancestor_at(head, sequence - w) {
            Ok(Some(dropped)) => Ok(Some(dropped)),
            _ => Err(()),
        }
    }

    /// Promotes a block that passed the whole per-block step to the active
    /// head (AC3/AC4, D7: Stored → Active directly), refreshes its
    /// `chain_heads` entry (AC7), adds its FR21 `value` to the active value
    /// (event (i)) and, when the window gate said so, advances the tail (9.1)
    /// and subtracts the new `S_tail` block's value from every value (event
    /// (iii), Story 6.1 D1). The active set follows both window events
    /// (Story 6.4 D2): `creator` enters, the old tail's creator leaves.
    pub(super) fn promote_head_extension(
        &mut self,
        idx: u32,
        value: u64,
        creator: u32,
        advance: Option<TailStep>,
    ) {
        self.blocks.set_status(idx, BlockStatus::Active);
        self.blocks.set_on_active_chain(idx, true);
        self.active_chain_head_idx = idx;
        self.chain_heads.refresh_head(&self.blocks, idx);
        self.active_branch_value += value;
        self.active_set.add(creator);
        // FR64 (Epic 11 `LogSink`): emit the head-extension event carrying the
        // promoted block's hash and sequence. Deferred — see deferred-work.md.
        if let Some(step) = advance
            && self.advance_snake_chain_tail()
        {
            self.active_branch_value = self.active_branch_value.saturating_sub(step.value);
            self.chain_heads
                .subtract_branch_value(&self.blocks, step.value);
            self.active_set.advance_tail(step.creator);
        }
        // FR58 reclamation (DEC-208): the active block at `S_head − H − 1` has
        // just left the switch bound, and its forks with it.
        if let (Some(entry), Some(h)) = (self.blocks.get(idx), self.verification_horizon()) {
            self.reclaim_out_of_bound(entry.sequence().saturating_sub(h + 1));
        }
    }

    /// Story 6.0 AC4 — continues the active head over children that are
    /// already stored: orphans that became children of the head when their
    /// parent arrived and was promoted, and an earlier local-failure retry.
    /// Runs after every Ready admission and after every direct extension.
    ///
    /// Each pass picks one Stored child of the head by the FR21 rank (Story
    /// 6.1 D9, [`Self::best_stored_child`]), judges it, and either promotes it,
    /// deletes it with its descendants (its verdict is final, D2), or stops on
    /// a local failure, leaving it Stored. At most `MAX_BLOCKS` passes. Each
    /// costs O(`MAX_BLOCKS`) child scans (there is no child index), one read of
    /// the chosen child, one read per sibling when there are several (their
    /// rank), and one read of the new tail when the window advances.
    pub(super) fn drive_forward_extension(&mut self) {
        for _ in 0..MAX_BLOCKS {
            // Story 6.7 AC8: after a failed restore the engine is not the
            // head's; no further step runs before the root re-enters.
            if self.reentry_due {
                return;
            }
            let Some(child) = self.best_stored_child() else {
                return;
            };
            // The child's read copy lives in its own frame, gone before any
            // deletion or tail advance, whose delete-set buffer (2.4 KB) must
            // not share the stack with it (D4, DEC-136).
            match self.apply_stored_child(child, self.snake_chain_tail_idx) {
                ChildStep::Applied {
                    advance,
                    value,
                    creator,
                } => {
                    self.promote_head_extension(child, value, creator, advance);
                }
                // A local failure: the child stays Stored for a later retry.
                ChildStep::Local => return,
                // AC5: no derived state was touched (D1), the head stays, and
                // the node stays Ready — never the FR5 recovery.
                //
                // FR64 (Epic 11 `LogSink`): emit the deletion event carrying
                // the child's hash. Deferred — see deferred-work.md.
                ChildStep::Invalid => {
                    self.delete_subtree_with_followup(child);
                }
            }
        }
    }

    /// Story 6.1 AC6 — Tier 2 and Stored → Connected for side blocks in
    /// Ready, and their FR21 values. Runs after every Ready admission (after
    /// the continuation, whose promotion turns a sibling into a side block)
    /// and at every Ready entry.
    ///
    /// It handles the blocks stored before their Tier 2 could run — orphans
    /// connected later, blocks retained while Collecting, local-failure
    /// retries; a new block with a Connected or Active parent was judged before
    /// its write (D4). Each pending side head ([`Self::is_pending_side_head`])
    /// is walked once ([`Self::walk_side_branch`]):
    /// - every Stored block passes: they become Connected and the head's value
    ///   is `active − Σ_active + Σ_branch` (FR21 (ii));
    /// - exact evidence: the lowest failing block goes with its descendants;
    ///   the passed blocks below it become Connected, and the entry the
    ///   deletion retargets onto its parent takes the value the same walk
    ///   gives it (FR21 (v) in Ready, D8). The table changed, so the scan
    ///   restarts;
    /// - a local failure leaves the head pending for the next admission.
    ///
    /// Bounded: each round connects a head or deletes a block, or ends.
    ///
    /// Returns the highest-ranked admissible head it valued (FR22 (ii) and the
    /// FR21 (v) retarget; Story 6.2 D1): filtered by admissibility before the
    /// choice, so an inadmissible top cannot hide an admissible runner-up.
    /// The continuation ran before, so the window is final here.
    pub(super) fn connect_side_branches(&mut self) -> Option<u32> {
        let mut best = None;
        if self.snake_chain_tail_idx == NONE_REF {
            return None;
        }
        for _ in 0..MAX_BRANCH_COUNT + MAX_BLOCKS {
            let mut progressed = false;
            for slot in 0..MAX_BRANCH_COUNT {
                let Some(head) = self.chain_heads.connected_head_at(slot) else {
                    continue;
                };
                if !self.is_pending_side_head(head) {
                    continue;
                }
                let Ok(walk) = self.walk_side_branch(head) else {
                    continue;
                };
                progressed = true;
                match walk.failing {
                    None => {
                        // FR64 (Epic 11 `LogSink`): emit the connect event.
                        // Deferred — see deferred-work.md.
                        self.mark_connected(head);
                        let value = self.side_value(walk.active, walk.branch);
                        self.chain_heads.set_branch_value(head, value);
                        self.consider(&mut best, head);
                    }
                    Some((failing, through)) => {
                        let parent = self
                            .blocks
                            .get(failing)
                            .map_or(NONE_REF, |entry| entry.parent_ref());
                        self.mark_connected(parent);
                        // FR64 (Epic 11 `LogSink`): emit the deletion event
                        // carrying the block's hash. Deferred — see
                        // deferred-work.md.
                        self.delete_subtree_with_followup(failing);
                        if self
                            .blocks
                            .get(parent)
                            .is_some_and(|entry| entry.status() == BlockStatus::Connected)
                        {
                            let value = self.side_value(walk.active, walk.branch - through);
                            self.chain_heads.set_branch_value(parent, value);
                            self.consider(&mut best, parent);
                        }
                        break;
                    }
                }
            }
            if !progressed {
                return best.map(|(head, _)| head);
            }
        }
        best.map(|(head, _)| head)
    }

    /// A pending side head: Stored, and the lowest Stored block of its branch
    /// is not a child of the active head — those stay with the Story 6.0
    /// continuation (Tier 2 + 3 in one step), which only extends into Stored
    /// children. The caller has checked the `connected` cache.
    fn is_pending_side_head(&self, head: u32) -> bool {
        let mut lowest = NONE_REF;
        let mut cur = head;
        for _ in 0..MAX_BLOCKS {
            match self.blocks.get(cur) {
                Some(entry) if entry.status() == BlockStatus::Stored => {
                    lowest = cur;
                    cur = entry.parent_ref();
                }
                _ => break,
            }
        }
        lowest != NONE_REF && cur != NONE_REF && cur != self.active_chain_head_idx
    }

    /// Walks the side branch of `head` down to its connection point (the first
    /// block on the active chain), reading each block once, then the active
    /// chain from the head down to the same point: the FR21 sums of FR21 (ii).
    /// Every Stored block runs the Tier 2 check; the lowest failing one is
    /// reported. `Err` on a local failure — nothing is changed. The read copy lives only in this
    /// frame (DEC-136), gone before the caller deletes anything.
    #[inline(never)]
    fn walk_side_branch(&self, head: u32) -> Result<SideWalk, ()> {
        // Every FR21 sum adds at most `MAX_BLOCKS` values, each at most
        // `value_cap` (an evidence block's clamp, Story 6.7 D7, DEC-264; any
        // other block's `u32` header value is below it), so plain `u64`
        // additions cannot overflow. It bounds the build: `MAX_BLOCKS ·
        // MAX_NODES` stays below about 8.6 · 10⁷.
        const { assert!((MAX_BLOCKS as u128) * (value_cap::<MAX_NODES>() as u128) <= u64::MAX as u128) };
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let mut branch = 0u64;
        let mut failing = None;
        let mut cur = head;
        let mut connection = NONE_REF;
        for _ in 0..MAX_BLOCKS {
            let entry = self.blocks.get(cur).ok_or(())?;
            if entry.is_on_active_chain() {
                connection = cur;
                break;
            }
            let (stored, parent) = (entry.status() == BlockStatus::Stored, entry.parent_ref());
            let view = self.view_retained(cur, &mut buf).ok_or(())?;
            branch += block_value::<MAX_NODES>(&view);
            if stored {
                match self.tier2_check(&view, cur, parent) {
                    Ok(()) => {}
                    // Walking down, a later failure is a lower one.
                    Err(err) if is_evidence(&err) => failing = Some((cur, branch)),
                    Err(_) => return Err(()),
                }
            }
            cur = parent;
        }
        if connection == NONE_REF {
            return Err(());
        }
        let mut active = 0u64;
        let mut cur = self.active_chain_head_idx;
        for _ in 0..MAX_BLOCKS {
            if cur == connection {
                return Ok(SideWalk {
                    active,
                    branch,
                    failing,
                });
            }
            let parent = self.blocks.get(cur).ok_or(())?.parent_ref();
            active += block_value::<MAX_NODES>(&self.view_retained(cur, &mut buf).ok_or(())?);
            cur = parent;
        }
        Err(())
    }

    /// FR21 (ii): a side head's value from the walk's sums. Exact: the active
    /// blocks above the connection point are part of the active value.
    fn side_value(&self, active: u64, branch: u64) -> u64 {
        self.active_branch_value.saturating_sub(active) + branch
    }

    /// Stored → Connected for `from` and every Stored ancestor below it — the
    /// blocks a side walk found passing Tier 2.
    fn mark_connected(&mut self, from: u32) {
        let mut cur = from;
        for _ in 0..MAX_BLOCKS {
            match self.blocks.get(cur) {
                Some(entry) if entry.status() == BlockStatus::Stored => {
                    let parent = entry.parent_ref();
                    self.blocks.set_status(cur, BlockStatus::Connected);
                    cur = parent;
                }
                _ => return,
            }
        }
    }

    /// Story 6.1 D4 — connects a side block judged at Tier 2 before its write,
    /// once `chain_heads` has seen it: interior after a merge (the surviving
    /// orphan head is the driver's); the extension of a Connected side head,
    /// valued incrementally from the parent's value read before the admission
    /// (FR21 (i)); otherwise a fork, valued by the walk from its Connected or
    /// Active `parent` plus its own `value` in hand — the block itself is never
    /// read back. A local failure there leaves it Stored, and the driver judges
    /// it again.
    pub(super) fn connect_judged_side_block(
        &mut self,
        idx: u32,
        parent: u32,
        value: u64,
        parent_value: Option<u64>,
    ) {
        if self.chain_heads.branch_value_of(idx).is_none() {
            self.blocks.set_status(idx, BlockStatus::Connected);
            return;
        }
        let value = match parent_value {
            Some(parent_value) => parent_value + value,
            None => match self.walk_side_branch(parent) {
                Ok(walk) => self.side_value(walk.active, walk.branch + value),
                Err(()) => return,
            },
        };
        self.blocks.set_status(idx, BlockStatus::Connected);
        self.chain_heads.set_branch_value(idx, value);
    }

    /// The Stored child of the active head the continuation takes next: the
    /// only one without a read, else the FR21 rank winner at the child level
    /// (Story 6.1 D9). All siblings share the active value, so each one's own
    /// value decides. `None` when there is no child, or when any candidate
    /// cannot be read — a local failure, never a choice: the continuation stops
    /// and retries at a later admission (code review 2026-10-20). Greedy per
    /// level: a heavier deeper subtree is reached by the FR22 comparison at the
    /// end of the admission (Story 6.2) and the FR23 switch (6.3).
    fn best_stored_child(&self) -> Option<u32> {
        let head = self.active_chain_head_idx;
        let is_candidate = |idx: u32| {
            self.blocks.get(idx).is_some_and(|entry| {
                entry.parent_ref() == head && entry.status() == BlockStatus::Stored
            })
        };
        let mut candidates = (0..MAX_BLOCKS as u32).filter(|idx| is_candidate(*idx));
        let first = candidates.next()?;
        if candidates.next().is_none() {
            return Some(first);
        }
        let mut best: Option<(u32, Rank)> = None;
        for idx in (0..MAX_BLOCKS as u32).filter(|idx| is_candidate(*idx)) {
            let rank = self.child_rank(idx)?;
            if best.as_ref().is_none_or(|(_, top)| rank.outranks(top)) {
                best = Some((idx, rank));
            }
        }
        best.map(|(idx, _)| idx)
    }

    /// The FR21 rank of a stored child of the head: its value from one read,
    /// its size and hash from RAM. The read copy lives only in this frame
    /// (DEC-136).
    #[inline(never)]
    fn child_rank(&self, idx: u32) -> Option<Rank> {
        let entry = self.blocks.get(idx)?;
        let (len, hash) = (entry.len(), *entry.hash());
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf)?;
        Some(Rank {
            value: block_value::<MAX_NODES>(&view),
            len,
            hash,
        })
    }

    /// Reads a child of the head and runs the whole per-block step on it, the
    /// window gate measured from `tail` (the physical tail, or a chain-switch
    /// replay's virtual one, Story 6.3 D3).
    #[inline(never)]
    pub(super) fn apply_stored_child(&mut self, child: u32, tail: u32) -> ChildStep {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let Some(view) = self.view_retained(child, &mut buf) else {
            return ChildStep::Local;
        };
        match self.judge_head_extension(&view, child, tail) {
            Extension::Valid {
                advance,
                derivation,
            } => match self.commit_block(&view, child, derivation) {
                Ok(()) => ChildStep::Applied {
                    advance,
                    value: block_value::<MAX_NODES>(&view),
                    creator: view.creator(),
                },
                Err(err) if is_evidence(&err) => ChildStep::Invalid,
                Err(_) => ChildStep::Local,
            },
            Extension::Invalid => ChildStep::Invalid,
            Extension::Local => ChildStep::Local,
        }
    }
}
