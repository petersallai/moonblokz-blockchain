//! FR48 / FR58 snake-chain window: tail advance, horizon, active-set build
//! (Stories 9.1, 6.14).

use super::*;

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
    /// FR48 / FR51 classification of the block about to drop off the tail
    /// (DEC-330): [`classify_tail_drop`]'s RAM decision, except that a block
    /// whose available-UTXO bitfield has a set bit owes a carry-forward only
    /// when one of those unspent outputs exceeds the custodian fee — otherwise
    /// its exact carry-forward would have no output, which DEC-308 refuses, and
    /// the block could never drop. No set bit, no read; a set bit costs one
    /// read of the dropping block, in its own frame. The one decision for the
    /// Ready extension, the FR3 pass and FR12 eligibility (Stories 8.3 / 9.5
    /// reuse it on the creator side).
    ///
    /// The fee is read from the held configuration. Story 7.2 binds the
    /// per-block chain-info source (DEC-305); until then a computed custodian
    /// fee's chain-info reads decline and fall through. A configuration not
    /// held, an empty slot or a failed read is the node's own failure
    /// ([`TailUnreadable`]), never "no obligation".
    pub(super) fn tail_obligation(&self, dropped: u32) -> Result<TailObligation, TailUnreadable> {
        let obligation = classify_tail_drop(&self.blocks, &self.node_info, dropped)?;
        if obligation != TailObligation::Utxo {
            return Ok(obligation);
        }
        let fee = self
            .chain_config
            .active_configuration()
            .ok_or(TailUnreadable)?
            .custodian_fee();
        if self.dropping_block_carries_output_above(dropped, fee)? {
            Ok(TailObligation::Utxo)
        } else {
            Ok(TailObligation::None)
        }
    }

    /// The read half of [`Self::tail_obligation`]: one read of the dropping
    /// block into its own buffer (DEC-136). A failed read is local. An
    /// `IntegrityFailure` is matched apart from `BackendIo` here, because a
    /// slot that fails its own hash is permanently unusable and is DEC-320's to
    /// release and re-fetch (Epic 9); until then both are local failures.
    #[inline(never)]
    fn dropping_block_carries_output_above(
        &self,
        idx: u32,
        fee: u64,
    ) -> Result<bool, TailUnreadable> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        match self.storage.read_block_into(idx, &mut buf) {
            Ok(()) => {}
            Err(StorageError::IntegrityFailure) => return Err(TailUnreadable),
            Err(_) => return Err(TailUnreadable),
        }
        let n = match self.blocks.get(idx).map(|entry| entry.len() as usize) {
            Some(len) if len > 0 && len <= MAX_BLOCK_SIZE => len,
            _ => MAX_BLOCK_SIZE,
        };
        let view = BlockView::from_bytes(&buf[..n])
            .ok()
            .ok_or(TailUnreadable)?;
        Ok(carries_output_above(
            &view,
            |bit| self.blocks.utxo_available(idx, bit) == Some(true),
            fee,
        ))
    }

    /// The [`TailStep`] of the block that becomes `S_tail` when the window
    /// advances past `tail`: its active-chain child. `None` on a failed read —
    /// a local failure. The tail is never the head here: that needs `W = 1`,
    /// where FR60 refuses every extension (`s_new ≥ s_head + W`).
    pub(super) fn new_tail_step(&self, tail: u32) -> Option<TailStep> {
        self.tail_step_at(self.tail_successor(tail)?)
    }

    /// The active-chain child of `tail`: the block that becomes `S_tail`
    /// when the window advances past it. RAM only, O(`MAX_BLOCKS`).
    pub(super) fn tail_successor(&self, tail: u32) -> Option<u32> {
        (0..MAX_BLOCKS as u32).find(|idx| {
            self.blocks
                .get(*idx)
                .is_some_and(|entry| entry.parent_ref() == tail && entry.is_on_active_chain())
        })
    }

    /// Reads a retained block and returns its FR21 value and creator; `None`
    /// on a failed read. The read copy lives only in this frame (DEC-136).
    #[inline(never)]
    fn tail_step_at(&self, idx: u32) -> Option<TailStep> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        self.view_retained(idx, &mut buf).map(|view| TailStep {
            value: block_value::<MAX_NODES>(&view),
            creator: view.creator(),
        })
    }

    /// FR4 / FR9 Tier-3 Active-promotion driver (AC9): on a clean FR6 pass, walk
    /// the validated candidate tip → anchor and atomically flip every block
    /// `Stored → Active` with `is_on_active_chain = true`, then establish
    /// `active_chain_head_idx = tip` (overwriting any Story-5.2 bootstrap
    /// placeholder) and the FR48 window over it. A pure `parent_ref` walk (no
    /// storage reads), bounded by `MAX_BLOCKS`.
    pub(super) fn promote_candidate_active(&mut self, candidate_tip_idx: u32, window_value: u64) {
        // Only the candidate is the active chain. A Collecting genesis anchor
        // that the candidate does not contain (FR2 adopted a window-anchored
        // segment, or a restart re-flagged it) would otherwise keep its flag
        // and leave its branch looking Connected for good (review r2).
        for idx in 0..MAX_BLOCKS as u32 {
            self.blocks.set_on_active_chain(idx, false);
        }
        let mut cur = candidate_tip_idx;
        for _ in 0..MAX_BLOCKS {
            self.blocks.set_status(cur, BlockStatus::Active);
            self.blocks.set_on_active_chain(cur, true);
            match self.blocks.get(cur) {
                Some(entry) => {
                    let parent = entry.parent_ref();
                    if parent == NONE_REF {
                        break;
                    }
                    cur = parent;
                }
                None => break,
            }
        }
        self.active_chain_head_idx = candidate_tip_idx;
        self.establish_snake_chain_window();
        // The FR3 walk summed exactly the window just established (D5).
        self.active_branch_value = window_value;
    }

    /// The sequence of the tail the window over a chain from `root_seq` to
    /// `head_seq` lands on: `max(root_seq, head_seq + 1 − W)`, the whole chain
    /// when no `W` is held. One function for the Ready-entry trim and the FR3
    /// walk's window value (Story 6.1 D5), so the two cannot disagree. `W` is
    /// read now (FR56), never the capacity.
    pub(super) fn window_tail_sequence(&self, root_seq: u32, head_seq: u32) -> u32 {
        match self.active_chain_length() {
            Some(w) => root_seq.max((head_seq + 1).saturating_sub(w)),
            None => root_seq,
        }
    }

    /// FR48 — establishes the snake-chain window over the active head, at every
    /// point the node enters Ready with one (genesis, the Processing→Ready
    /// promotion).
    ///
    /// The tail starts at the active chain's root (a pure `parent_ref` walk, no
    /// storage reads) and is then advanced by the ordinary window step until
    /// the window is `W` long, which lands it on `max(anchor_seq, S_head − W +
    /// 1)`. A chain shorter than `W` advances nothing — the bootstrap growth
    /// phase, where a genesis-anchored tail stays at block #0 (Story 9.1 AC2).
    ///
    /// The blocks the tail passes enter the FR58 verification horizon, and only
    /// those beyond `H` below the tail are released (Story 6.14 AC6): a
    /// segment longer than `W + H` (a restart can hold more) enters Ready
    /// holding `W + H` blocks. The released blocks go even when they carry an
    /// FR49/FR50/FR51 obligation (Ratified Decision 4, 2026-10-10): the segment
    /// passed FR3/FR6 as a whole, the state they seed is in the derived
    /// projections, and the FR3 pass has already evaluated the FR48 binding of
    /// every block whose dropped block lay in the segment (DEC-204). Each block
    /// the window passes is still classified, so the record is uniform with a
    /// steady-state advance — the result feeds only the AR16 log (Epic 11), so
    /// neither an obligation nor an unreadable block stops the trim (Project
    /// Lead, 2026-10-13).
    ///
    /// `W` is read now (FR56). A Ready node is durably locked, so it is always
    /// there; were it not, the window is the whole active chain and nothing is
    /// released — never the `SNAKE_CHAIN_LENGTH_MAX` capacity in its place
    /// (Story 5.11 Ratified Decision 2).
    ///
    /// Before the trim every `chain_heads` entry is recomputed against the new
    /// marking (O-024 ruling): without it the adopted chain's own head stays
    /// Stored and keeps requesting the anchor's parent. Then the FR58
    /// reclamation runs over the whole adopted chain (DEC-208): every branch
    /// forked below `S_head − H` and every Stored fragment that can never
    /// connect, including a genesis island the adopted chain does not contain
    /// (DEC-127).
    ///
    /// **Cost.** The tail is found by walking to the root and then advancing,
    /// not by a `W − 1`-step walk, so the trim is literally the steady-state
    /// step. Each block the window passes costs one storage read (transaction
    /// blocks only) and one O(`MAX_BLOCKS`) child scan; each release another
    /// scan. The reclamation costs one `delete_subtree_with_followup` per fork
    /// and per fragment, each O(`MAX_BLOCKS`²) through `mark_subtree`. The
    /// common case — a live join of exactly `W + H` blocks — releases nothing
    /// and deletes nothing.
    pub(super) fn establish_snake_chain_window(&mut self) {
        let mut root = self.active_chain_head_idx;
        for _ in 0..MAX_BLOCKS {
            match self.blocks.get(root) {
                Some(entry) if entry.parent_ref() != NONE_REF => root = entry.parent_ref(),
                _ => break,
            }
        }
        self.snake_chain_tail_idx = root;
        // Before any reclamation or release: the promotion re-marked the active
        // chain without touching `chain_heads`. Current caches keep the adopted
        // chain's own head from looking like a Stored fragment, and make a
        // stale genesis island (now unflagged) look like one — it is reclaimed
        // here, at once (DEC-127).
        self.chain_heads.recompute_all_caches(&self.blocks);
        // FR58 reclamation over the whole adopted chain (DEC-208), before the
        // trim: the releases below then meet only the active path.
        if let Some(root_seq) = self.blocks.get(root).map(|entry| entry.sequence()) {
            self.reclaim_out_of_bound(root_seq);
        }

        let (Some(root_seq), Some(head_seq)) = (
            self.blocks.get(root).map(|entry| entry.sequence()),
            self.blocks
                .get(self.active_chain_head_idx)
                .map(|entry| entry.sequence()),
        ) else {
            self.active_set.invalidate();
            return;
        };
        let target = self.window_tail_sequence(root_seq, head_seq);
        for _ in 0..MAX_BLOCKS {
            if self
                .blocks
                .get(self.snake_chain_tail_idx)
                .is_none_or(|tail| tail.sequence() >= target)
            {
                break;
            }
            let _ = classify_tail_drop(&self.blocks, &self.node_info, self.snake_chain_tail_idx);
            if !self.advance_snake_chain_tail() {
                break;
            }
        }
        // Story 6.4: the FR12 state of a ready entry — the support floor
        // reaches the head (D8: DEC-198's restart floor, also for the DEC-205
        // re-entry, whose ring survives), and the active set is built over the
        // window just established (D2).
        self.non_conflict.raise_floor(head_seq);
        self.build_active_set();
    }

    /// Story 6.4 D2: builds the active set by one walk over the window, head
    /// to tail (at most `W` reads, one buffer in this frame, DEC-136). A failed
    /// read leaves it invalid: no support until the next ready entry.
    fn build_active_set(&mut self) {
        match self.blocks.get(self.snake_chain_tail_idx) {
            Some(tail) => {
                let bottom = tail.sequence();
                self.build_active_set_over(self.active_chain_head_idx, bottom);
            }
            None => self.active_set.invalidate(),
        }
    }

    /// The active set over the window `[bottom, top]`, walked from `top` down
    /// by `parent_ref` (at most `W` reads, one buffer in this frame, DEC-136):
    /// the ready entry's window, or the FR3 pass's window at an evidence
    /// block's `p − 1` (Story 6.7 AC7). A failed read leaves it invalid.
    #[inline(never)]
    pub(super) fn build_active_set_over(&mut self, top: u32, bottom: u32) {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        self.active_set.start_build(0);
        let mut cur = top;
        for _ in 0..MAX_BLOCKS {
            let Some(view) = self.view_retained(cur, &mut buf) else {
                break;
            };
            let creator = view.creator();
            self.active_set.add(creator);
            if view.sequence() <= bottom {
                self.active_set.set_tail_creator(creator);
                return;
            }
            match self.blocks.get(cur) {
                Some(entry) if entry.parent_ref() != NONE_REF => cur = entry.parent_ref(),
                _ => break,
            }
        }
        self.active_set.invalidate();
    }

    /// FR58 reclamation (DEC-159, DEC-208): deletes, whole, everything whose
    /// divergence from the active chain lies at `D ≤ S_head − H` and so can
    /// never become active:
    /// - every branch forked at an active block at sequence `from ..= S_head −
    ///   H − 1` — the blocks that left the bound since the previous sweep;
    /// - every Stored fragment whose missing parent lies at `q ≤ S_head − H`
    ///   (DEC-161 as tightened by DEC-208): the retained active block at `q`
    ///   would have linked it at admission, so the missing parent is off the
    ///   active chain and the fragment diverges at or below `q`; and, on a
    ///   young chain where that bound is below #0, one whose missing parent
    ///   is at or below the tail, which can never arrive.
    ///
    /// Runs at every Ready head extension (`from = S_head − H − 1`), at a chain
    /// switch's commit (from the old head's bound) and at Ready entry (from the
    /// root). It needs current `chain_heads` caches — a Stored head's
    /// tail-point is then never an active block — and walks the active chain by
    /// `parent_ref`, with no storage read. Without a configuration (never in
    /// Ready) it does nothing. Cost: one O(`MAX_BLOCKS`) child scan per block
    /// that crossed the bound, one O(`MAX_BRANCH_COUNT`) fragment pass, and one
    /// `delete_subtree_with_followup` per deletion, one at a time.
    pub(super) fn reclaim_out_of_bound(&mut self, from: u32) {
        let (Some(head), Some(h)) = (
            self.blocks
                .get(self.active_chain_head_idx)
                .map(|entry| entry.sequence()),
            self.verification_horizon(),
        ) else {
            return;
        };
        if let Some(top) = head.checked_sub(h + 1)
            && from <= top
            && let Ok(Some(mut cur)) = self.ancestor_at(self.active_chain_head_idx, top)
        {
            for _ in 0..MAX_BLOCKS {
                let Some(entry) = self.blocks.get(cur) else {
                    break;
                };
                if entry.sequence() < from {
                    break;
                }
                let parent = entry.parent_ref();
                self.delete_forks_at(cur);
                cur = parent;
            }
        }
        // A missing parent at or below the tail can never arrive either: FR60
        // refuses it below the tail, and at the tail itself it would be the
        // tail's sibling — out of the bound once the chain has matured, a
        // second genesis before (the young chain's tail is #0). So a young
        // chain still reclaims what Story 9.1 did.
        let tail = self
            .blocks
            .get(self.snake_chain_tail_idx)
            .map_or(0, |entry| entry.sequence());
        let limit = head
            .saturating_add(1)
            .saturating_sub(h)
            .max(tail.saturating_add(1));
        for slot in 0..MAX_BRANCH_COUNT {
            let Some(tail_point) = self.chain_heads.stored_head_tail(slot) else {
                continue;
            };
            if self
                .blocks
                .get(tail_point)
                .is_some_and(|entry| entry.sequence() <= limit)
            {
                self.delete_subtree_with_followup(tail_point);
            }
        }
    }

    /// Deletes, whole, every branch forked at the active block `block`: each
    /// child that is not on the active path.
    fn delete_forks_at(&mut self, block: u32) {
        for idx in 0..MAX_BLOCKS as u32 {
            if self
                .blocks
                .get(idx)
                .is_some_and(|child| child.parent_ref() == block && !child.is_on_active_chain())
            {
                self.delete_subtree_with_followup(idx);
            }
        }
    }

    /// The lowest retained active-chain block, below the tail by at most `H`:
    /// the root, whose `parent_ref` is `NONE_REF` (D1, DEC-206). Derived by a
    /// RAM walk, so no index names it.
    pub(super) fn horizon_root(&self) -> u32 {
        let mut root = self.snake_chain_tail_idx;
        for _ in 0..MAX_BLOCKS {
            match self.blocks.get(root) {
                Some(entry) if entry.parent_ref() != NONE_REF => root = entry.parent_ref(),
                _ => break,
            }
        }
        root
    }

    /// FR48 window advance (Story 9.1 AC5; Story 6.14 AC3): moves the tail one
    /// block up the active chain. Returns `false`, changing nothing, when there
    /// is nothing to advance over — no tail, or the tail is the head.
    ///
    /// The block the tail leaves enters the FR58 verification horizon: it
    /// keeps its entry, `parent_ref`, `Active` status, `is_on_active_chain`
    /// flag, available-UTXO bits and every seed-source pointer that names it
    /// (D1, DEC-206). Horizon blocks contribute nothing to the derived state
    /// or the FR21 value — the window is the two indices — but a chain switch
    /// resolves the dropped and referenced blocks below `S_tail` against them
    /// (DEC-204). The block that leaves the horizon is then released
    /// ([`Self::release_beyond_horizon`]).
    ///
    /// The caller decides *whether* to advance: the Ready-entry trim
    /// ([`Self::establish_snake_chain_window`]), Story 6.0's forward
    /// extension, which advances once per head extension past length `W` after
    /// [`crate::snake_chain::tail_drop_binding`] allows it, and a chain
    /// switch's commit. No fork is deleted here: under DEC-207 the dropped
    /// block lies below `S_head − H − 1`, so its forks left FR58's bound
    /// earlier and were reclaimed then ([`Self::reclaim_out_of_bound`],
    /// DEC-208). The FR21 subtraction of event (iii) is the caller's.
    ///
    /// **Cost.** One O(`MAX_BLOCKS`) child scan, plus the release's.
    pub(crate) fn advance_snake_chain_tail(&mut self) -> bool {
        let dropped = self.snake_chain_tail_idx;
        // Runtime, not debug-only: advancing over a block off the active path
        // would move the window onto a branch.
        if dropped == self.active_chain_head_idx
            || !self
                .blocks
                .get(dropped)
                .is_some_and(|entry| entry.is_on_active_chain())
        {
            return false;
        }
        let Some(new_tail) = self.tail_successor(dropped) else {
            return false;
        };
        self.snake_chain_tail_idx = new_tail;
        self.release_beyond_horizon();
        true
    }

    /// The FR58 horizon release (D1, DEC-206): while more than `H` blocks lie
    /// below the tail, the root — the block that leaves the horizon — is
    /// released as Story 9.1 released the dropped tail:
    /// 1. its `is_on_active_chain` is cleared and its slot freed with the lazy
    ///    [`BlockTable::delete`] — the durable bytes stay until the slot is
    ///    reused (Ratified Decision 3);
    /// 2. index hygiene: nodes seeded from it stay seeded but stop naming the
    ///    slot (`SEED_SOURCE_RELEASED`), and a tentative provenance naming it is
    ///    dropped (never in practice: a Ready node is durably locked);
    /// 3. its one flagged child is unlinked (`parent_ref = NONE_REF`) and
    ///    becomes the new root.
    ///
    /// No fork is deleted: nothing but the active path lies at or below
    /// `S_head − H` (DEC-208), so the root's only child is its successor.
    /// Without a configuration `H` counts as 0. Cost: one root walk and one
    /// O(`MAX_BLOCKS`) child scan per release.
    fn release_beyond_horizon(&mut self) {
        let Some(tail_seq) = self
            .blocks
            .get(self.snake_chain_tail_idx)
            .map(|entry| entry.sequence())
        else {
            return;
        };
        let h = self.verification_horizon().unwrap_or(0);
        let mut root = self.horizon_root();
        for _ in 0..MAX_BLOCKS {
            let Some(root_seq) = self.blocks.get(root).map(|entry| entry.sequence()) else {
                return;
            };
            if tail_seq.saturating_sub(root_seq) <= h {
                return;
            }
            let Some(successor) = self.tail_successor(root) else {
                return;
            };
            self.blocks.set_on_active_chain(root, false);
            self.blocks.delete(root);
            self.node_info.release_seed_source(root);
            if self.tentative_config_block_idx == root {
                self.tentative_config_block_idx = NONE_REF;
                self.chain_config.discard_tentative();
            }
            self.blocks.set_parent_ref(successor, NONE_REF);
            root = successor;
        }
    }
}
