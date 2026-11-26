//! FR22 branch comparison and the FR23 reversible chain switch (Stories 6.2,
//! 6.3; DEC-171).

use super::*;

/// An upper bound on a balance block's entries (the payload also carries
/// its header): the owner list a committed-block undo copies before its
/// seed-source scan (Story 6.3 AC2).
const MAX_BALANCE_ENTRIES: usize = MAX_PAYLOAD_SIZE / NODE_INFO_SIZE;

/// What an FR70 twin check found (Story 6.12 AC2, DEC-273).
#[cfg_attr(test, derive(Debug, PartialEq))]
pub(super) enum Twin {
    /// Another creator: an honest fork.
    No,
    /// The candidate block claims the active block's creator but its creator
    /// signature is invalid under that creator's key, which every branch
    /// through the parent shares: exact evidence against it.
    Forged,
    /// A twin; `verified_now` when this check verified the candidate block's
    /// signature, for a caller that may mark it (DEC-157).
    Yes { verified_now: bool },
    /// A read failed, or the key was not derivable (only under pre-seed
    /// trust, DEC-157): not evidence either way. A same-creator candidate is
    /// never switched to in any case, so the caller holds.
    Unknown,
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
    /// The FR21 rank of a valued side head — Connected, and named by a
    /// `chain_heads` entry with its value (DEC-144) — from RAM only (D4).
    fn head_rank(&self, head: u32) -> Option<Rank> {
        let entry = self.blocks.get(head)?;
        if entry.status() != BlockStatus::Connected {
            return None;
        }
        Some(Rank {
            value: self.chain_heads.branch_value_of(head)?,
            len: entry.len(),
            hash: *entry.hash(),
        })
    }

    /// The FR21 rank of the active branch: `active_branch_value` (never an
    /// entry, DEC-144) with the active tip's size and hash.
    fn active_rank(&self) -> Option<Rank> {
        let entry = self.blocks.get(self.active_chain_head_idx)?;
        Some(Rank {
            value: self.active_branch_value,
            len: entry.len(),
            hash: *entry.hash(),
        })
    }

    /// FR21 operational admissibility of a side head on the current window
    /// (Story 6.2 D3, DEC-154; [`crate::branch_value::is_admissible`]).
    fn is_admissible_head(&self, head: u32) -> bool {
        let (Some(tail), Some(top), Some(tip), Some(w)) = (
            self.blocks.get(self.snake_chain_tail_idx),
            self.blocks.get(self.active_chain_head_idx),
            self.blocks.get(head),
            self.active_chain_length(),
        ) else {
            return false;
        };
        crate::branch_value::is_admissible(tail.sequence(), top.sequence(), tip.sequence(), w)
    }

    /// Keeps the higher-ranked admissible valued side head in `best`.
    pub(super) fn consider(&self, best: &mut Option<(u32, Rank)>, head: u32) {
        if head == self.active_chain_head_idx || !self.is_admissible_head(head) {
            return;
        }
        let Some(rank) = self.head_rank(head) else {
            return;
        };
        if best.as_ref().is_none_or(|(_, top)| rank.outranks(top)) {
            *best = Some((head, rank));
        }
    }

    /// FR22 (Story 6.2 D1, DEC-152): the head an FR23 switch should go to,
    /// if any. `candidates` are the heads this admission valued — the block
    /// judged at intake and the side-branch driver's best; anything no longer
    /// a valued Connected head (the active extension, a Stored block, a block
    /// an orphan merged away, a fork the tail advance released) drops out.
    /// The higher-ranked admissible one wins iff it outranks the active
    /// branch. RAM only; with no candidate, nothing is read.
    pub(super) fn switch_target(&self, candidates: [Option<u32>; 2]) -> Option<u32> {
        let mut best = None;
        for head in candidates.into_iter().flatten() {
            self.consider(&mut best, head);
        }
        let (head, rank) = best?;
        rank.outranks(&self.active_rank()?).then_some(head)
    }

    /// FR70 (Story 6.12 AC2, DEC-273): whether `x` is a twin of the active
    /// block `y`, two children of one retained parent. Two entries at one
    /// sequence never share a hash (FR11), so they are twins when they have one
    /// creator and `x`'s creator signature is valid (`y` is committed). `y`'s
    /// creator is seeded on the prefix both blocks share, so the key the check
    /// uses is the one every branch through the parent uses. The signature is
    /// verified only when the creators match and bit 5 is unset; `&self`, so a
    /// read-only query can use it (Story 10.1) and the caller marks the bit.
    /// No state is kept: the check reads both blocks each time, one after the
    /// other into its one read buffer (DEC-136).
    #[inline(never)]
    pub(super) fn twin_of(&self, x: u32, y: u32) -> Twin {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let Some(creator) = self.view_retained(y, &mut buf).map(|view| view.creator()) else {
            return Twin::Unknown;
        };
        let Some(verified) = self
            .blocks
            .get(x)
            .map(|entry| entry.is_signature_verified())
        else {
            return Twin::Unknown;
        };
        let Some(view) = self.view_retained(x, &mut buf) else {
            return Twin::Unknown;
        };
        if view.creator() != creator {
            return Twin::No;
        }
        if verified {
            return Twin::Yes {
                verified_now: false,
            };
        }
        match self.verify_block_creator_signature(&view) {
            Some(true) => Twin::Yes { verified_now: true },
            Some(false) => Twin::Forged,
            None => Twin::Unknown,
        }
    }

    /// FR70's hold (Story 6.12 AC3, D3, DEC-273): whether the switch toward
    /// `head` would cross a same-parent twin of the active block. The RAM
    /// checks come first: a candidate the FR58 bound refuses is not held here
    /// (`switch_toward` refuses it, reading nothing), and one without an active
    /// block above the common ancestor crosses no twin. A check that could not
    /// complete (a read, the block index, an underivable key) holds, deleting
    /// nothing. A forged candidate block is deleted with its descendants as
    /// exact evidence (FR16), as the switch's pre-pass would, and the candidate
    /// drops out without a second verification or a walk. Story 6.13 lifts
    /// the hold for a candidate whose side holds an approved twin round
    /// against the active twin (`approved_against`).
    pub(super) fn twin_held(&mut self, head: u32) -> bool {
        let Some(ancestor) = self.common_ancestor(head) else {
            return false;
        };
        if !self.in_place_switch_allowed(ancestor) {
            return false;
        }
        let Some(first) = self.blocks.get(ancestor).map(|entry| entry.sequence() + 1) else {
            return false;
        };
        let (x, y) = match (
            self.ancestor_at(head, first),
            self.ancestor_at(self.active_chain_head_idx, first),
        ) {
            (Ok(Some(x)), Ok(Some(y))) => (x, y),
            // A local index fault: no evidence, so hold.
            (Err(_), _) | (_, Err(_)) => return true,
            // No active block above the ancestor: no twin to cross.
            _ => return false,
        };
        match self.twin_of(x, y) {
            Twin::No => false,
            Twin::Unknown => true,
            Twin::Forged => {
                // FR64 (Epic 11 `LogSink`): the deletion event, as for the
                // pre-pass. Deferred — see deferred-work.md.
                self.delete_offender(x, None);
                true
            }
            Twin::Yes { verified_now } => {
                if verified_now {
                    self.blocks.mark_signature_verified(x);
                }
                // Story 6.13 AC7 (FR70, FR71; DEC-276): an approved twin round
                // on the candidate's segment, against the active twin `y`,
                // lifts the hold; FR21 then decides. The claim is verified on
                // the switch's replay (DEC-259).
                !self.approved_against(head, first, y)
            }
        }
    }

    /// FR22 with the FR70 hold (Story 6.12 AC3, D3, DEC-273): the head
    /// [`Self::switch_target`] names, unless FR70 holds it; a held head drops
    /// out of `candidates` and the next-ranked one is compared. Each round
    /// removes a candidate, so there are at most two.
    fn unheld_switch_target(&mut self, candidates: &mut [Option<u32>; 2]) -> Option<u32> {
        while let Some(head) = self.switch_target(*candidates) {
            if !self.twin_held(head) {
                return Some(head);
            }
            // FR64 (Epic 11 `LogSink`): the FR70 hold, with the candidate head
            // and the twin's `(c, s, P)`. Deferred — see deferred-work.md.
            for candidate in candidates.iter_mut() {
                if *candidate == Some(head) {
                    *candidate = None;
                }
            }
        }
        None
    }

    /// FR22's one comparison and the FR23 switch it may run. A switch whose
    /// restore failed leaves a chain shorter than the window and horizon that
    /// every ready-state rule assumes, so the node re-enters collecting
    /// (DEC-205); a re-entry that reaches `Ready` again runs the restart's one
    /// comparison, and a second restore failure re-enters without a further
    /// one (the next FR22 trigger compares). At most two switches per call.
    pub(super) fn compare_and_switch(&mut self, candidates: [Option<u32>; 2], now: u64) {
        let mut candidates = candidates;
        for comparisons_left in [true, false] {
            let Some(head) = self.unheld_switch_target(&mut candidates) else {
                return;
            };
            // Story 6.7 AC8: an evidence check on the walk whose projection
            // could not restore the engine asks for the same re-entry.
            if !matches!(self.switch_toward(head), SwitchOutcome::RestoreFailed)
                && !self.reentry_due
            {
                return;
            }
            let Some(driver_best) = self.reenter_collecting(now) else {
                return;
            };
            if !comparisons_left {
                return;
            }
            candidates = [None, driver_best];
        }
    }

    /// DEC-205: `Ready → Collecting` over the retained tree, then the
    /// acquisition spine a restart drives (FR59 steps 2–5). Nothing durable
    /// changed — a switch writes no block bytes and defers its releases — so
    /// the tree is the node's durable footprint, and the FR2 stopping
    /// condition applies unchanged: a window-anchored segment qualifies at
    /// `W + H` (DEC-177). The derived state is discarded as the FR5 recovery
    /// discards it, the marking and statuses go back to collecting's (every
    /// block Stored, block #0 the root if retained), and `chain_heads` is
    /// rebuilt from the tree. The FR8 lock is irrevocable and stays. Returns
    /// the side-branch driver's best when the spine reached `Ready`.
    pub(super) fn reenter_collecting(&mut self, now: u64) -> Option<Option<u32>> {
        // Story 6.6 AC4: the accumulator is Ready-state work.
        self.approval.clear();
        self.active_open_run = NO_OPEN_RUN;
        // Story 6.7 AC8: this re-entry is the one a failed restore asked for.
        self.reentry_due = false;
        self.node_info.reset();
        self.reset_vote_engine();
        for idx in 0..MAX_BLOCKS as u32 {
            self.blocks.clear_available_utxo(idx);
            self.blocks.set_on_active_chain(idx, false);
            self.blocks.set_status(idx, BlockStatus::Stored);
        }
        self.active_chain_head_idx = NONE_REF;
        self.snake_chain_tail_idx = NONE_REF;
        self.active_branch_value = 0;
        for idx in 0..MAX_BLOCKS as u32 {
            if self
                .blocks
                .get(idx)
                .is_some_and(|entry| entry.sequence() == 0)
            {
                self.blocks.set_on_active_chain(idx, true);
                self.active_chain_head_idx = idx;
                break; // the single-genesis guard admits at most one block #0
            }
        }
        self.chain_heads.clear();
        self.chain_heads
            .rebuild_from_blocks(&mut self.blocks, now, self.active_chain_head_idx);
        self.seed_missing_parent_hashes();
        self.set_lifecycle_phase(LifecyclePhase::Collecting);
        if self.chain_config.active_configuration().is_some() {
            self.drive_dominant_chain_acquisition();
        }
        // Story 6.1 AC3: side branches are valued after the Ready entry.
        self.is_ready().then(|| self.connect_side_branches())
    }

    /// The FR23 chain switch toward `head` (FR22; Story 6.3, DEC-166..171,
    /// DEC-204): an atomic, in-place walk — back from the active head to the
    /// common ancestor by exact per-block inverses, then forward to `head`
    /// through the shared Tier-3 step — that completes, or restores the
    /// original chain exactly, or, after a second fault while restoring, stops
    /// for [`Self::compare_and_switch`] to re-enter collecting (AC6, DEC-205).
    /// It runs inside this call, so no
    /// query or event surface sees a blend of the two branches (FR24), and it
    /// writes no block bytes. The walk is these `Blockchain` methods, not
    /// `reconciliation.rs` (D6, DEC-171): the fields are private to `api`.
    ///
    /// Story 7.4 wires the mempool into the walk's three FR32 points: the
    /// re-add of each undone block's transactions, the removal of each
    /// applied block's, and the window expiry after the commit — the restore
    /// carries the same hooks.
    ///
    /// FR64 (Epic 11 `LogSink`): emit the active-branch change per FR22 with
    /// the old head, the new head and the common ancestor, and the walk's
    /// step counts. Deferred — see deferred-work.md.
    pub(super) fn switch_toward(&mut self, head: u32) -> SwitchOutcome {
        let Some(ancestor) = self.common_ancestor(head) else {
            return SwitchOutcome::NotAdmitted;
        };
        if !self.in_place_switch_allowed(ancestor) {
            // FR64: the switch-bound / completeness / evaluability refusal.
            // Deferred — see deferred-work.md.
            return SwitchOutcome::NotAdmitted;
        }
        match self.switch_signature_prepass(head, ancestor) {
            PrePass::Clean => {}
            PrePass::Local => return SwitchOutcome::Kept,
            PrePass::Invalid { block, through } => {
                // No projection was mutated (the pre-pass only marked the
                // signatures it verified): delete the forgery, and give the
                // entry retargeted onto its parent the value below it.
                let value = self
                    .chain_heads
                    .branch_value_of(head)
                    .map(|value| value.saturating_sub(through));
                self.delete_offender(block, value);
                return SwitchOutcome::Deleted;
            }
        }
        let old_head = self.active_chain_head_idx;
        let old_value = self.active_branch_value;

        // AC3 — the backward walk. Story 7.4: re-add each undone block's
        // transactions to the mempool here (FR32 (1)).
        while self.active_chain_head_idx != ancestor {
            if self.undo_active_head().is_err() {
                return self.restore_original(ancestor, old_head, old_value, None);
            }
        }

        // AC4 — the forward replay, with the tail advances against a virtual
        // tail and released only at the commit (D3, DEC-168). Story 7.4:
        // remove each applied block's transactions from the mempool here
        // (FR32 (2)).
        //
        // Story 6.4 D2: the active set follows the virtual window — each
        // replayed block enters it, and each virtual advance removes the block
        // that leaves it, whose creator the previous advance read (the
        // physical tail's is kept). A failure unwinds those removals before the
        // restore ([`Self::abort_switch`]).
        let mut virtual_tail = self.snake_chain_tail_idx;
        let mut virtual_tail_creator = self.active_set.tail_creator();
        let mut advances = 0usize;
        let mut released_value = 0u64;
        while self.active_chain_head_idx != head {
            let Some(next) = self.next_toward(head) else {
                return self.abort_switch(ancestor, old_head, old_value, None, advances);
            };
            match self.apply_stored_child(next, virtual_tail) {
                ChildStep::Applied {
                    advance,
                    value,
                    creator,
                } => {
                    self.promote_replayed(next, value, creator);
                    if let Some(step) = advance {
                        let Some(successor) = self.tail_successor(virtual_tail) else {
                            return self
                                .abort_switch(ancestor, old_head, old_value, None, advances);
                        };
                        virtual_tail = successor;
                        advances += 1;
                        released_value = released_value.saturating_add(step.value);
                        self.active_set.remove(virtual_tail_creator);
                        virtual_tail_creator = step.creator;
                    }
                }
                ChildStep::Invalid => {
                    // `next`'s parent is the current head: its value is the
                    // active value now, before anything is undone.
                    let parent_value = self.active_branch_value;
                    return self.abort_switch(
                        ancestor,
                        old_head,
                        old_value,
                        Some((next, parent_value)),
                        advances,
                    );
                }
                ChildStep::Local => {
                    return self.abort_switch(ancestor, old_head, old_value, None, advances);
                }
            }
        }
        // The walk must land on the value the comparison ranked (FR21): a
        // mismatch means an inconsistent table — a local failure.
        if self.chain_heads.branch_value_of(head) != Some(self.active_branch_value) {
            return self.abort_switch(ancestor, old_head, old_value, None, advances);
        }
        // Every deferred release must succeed, so the commit's summed FR21
        // (iii) subtraction is exact (AC5): the physical tail is the flagged
        // root and the virtual tail lies on the new head's ancestry, the chain
        // `advance_snake_chain_tail` walks. A breach is a local failure,
        // before anything is committed.
        if advances > 0 && !self.releases_will_succeed(head, virtual_tail) {
            return self.abort_switch(ancestor, old_head, old_value, None, advances);
        }
        self.commit_switch(head, old_head, old_value, advances, released_value);
        if advances > 0 {
            self.active_set.set_tail_creator(virtual_tail_creator);
        }
        SwitchOutcome::Switched
    }

    /// A failed replay: unwinds the active set's virtual-advance removals,
    /// then restores the original chain (Story 6.4 D2).
    fn abort_switch(
        &mut self,
        ancestor: u32,
        old_head: u32,
        old_value: u64,
        offender: Option<(u32, u64)>,
        advances: usize,
    ) -> SwitchOutcome {
        self.unwind_virtual_advances(advances);
        self.restore_original(ancestor, old_head, old_value, offender)
    }

    /// Puts back the creators the replay's `advances` virtual advances removed
    /// from the active set: the physical tail's, then its successors' along
    /// the flagged chain, read again — the failure path's only reads for the
    /// active set. A failed read invalidates it (no support until the next
    /// ready entry).
    fn unwind_virtual_advances(&mut self, advances: usize) {
        if advances == 0 || !self.active_set.is_valid() {
            return;
        }
        let mut released = self.snake_chain_tail_idx;
        self.active_set.add(self.active_set.tail_creator());
        for _ in 1..advances {
            let Some((next, creator)) = self
                .tail_successor(released)
                .and_then(|next| Some((next, self.header_at(next)?.0)))
            else {
                self.active_set.invalidate();
                return;
            };
            self.active_set.add(creator);
            released = next;
        }
    }

    /// Whether the commit's deferred advances, from the physical tail up to
    /// `virtual_tail`, will all succeed: the tail is flagged and
    /// `virtual_tail` is a proper ancestor of `head`, so every block the
    /// window advances over has a flagged child on the way to `head`. The
    /// horizon releases they trigger take roots below the tail, which the walk
    /// never touched (`A ≥ S_tail`, DEC-207), so they succeed whenever the
    /// advances do. RAM only.
    fn releases_will_succeed(&self, head: u32, virtual_tail: u32) -> bool {
        let tail = self.snake_chain_tail_idx;
        let tail_is_flagged = self
            .blocks
            .get(tail)
            .is_some_and(|entry| entry.is_on_active_chain());
        tail_is_flagged
            && virtual_tail != head
            && self.blocks.get(virtual_tail).is_some_and(|entry| {
                matches!(self.ancestor_at(head, entry.sequence()), Ok(Some(idx)) if idx == virtual_tail)
            })
    }

    /// The common ancestor of the active chain and `head`'s branch: the first
    /// block on the active chain below `head` (the connection point). RAM only.
    fn common_ancestor(&self, head: u32) -> Option<u32> {
        let mut cur = head;
        for _ in 0..MAX_BLOCKS {
            let entry = self.blocks.get(cur)?;
            if entry.is_on_active_chain() {
                return Some(cur);
            }
            cur = entry.parent_ref();
        }
        None
    }

    /// Whether a switch with common ancestor `ancestor` may run in place
    /// (Story 6.3 AC1; [`crate::reconciliation::switch_admitted`]).
    fn in_place_switch_allowed(&self, ancestor: u32) -> bool {
        let (Some(ancestor), Some(tail), Some(root), Some(top), Some(w), Some(h)) = (
            self.blocks.get(ancestor),
            self.blocks.get(self.snake_chain_tail_idx),
            self.blocks.get(self.horizon_root()),
            self.blocks.get(self.active_chain_head_idx),
            self.active_chain_length(),
            self.verification_horizon(),
        ) else {
            return false;
        };
        crate::reconciliation::switch_admitted(
            ancestor.sequence(),
            tail.sequence(),
            root.sequence(),
            top.sequence(),
            w,
            h,
        )
    }

    /// The next block toward `target` above the active head: `target`'s
    /// ancestor one sequence higher. RAM only.
    fn next_toward(&self, target: u32) -> Option<u32> {
        let sequence = self.blocks.get(self.active_chain_head_idx)?.sequence() + 1;
        self.ancestor_at(target, sequence).ok().flatten()
    }

    /// Story 6.3 D5 (DEC-170): verifies, before anything is mutated, the
    /// creator signature of every unmarked new-branch block above `ancestor`
    /// whose creator is fork-independent; a verified block is marked, so the
    /// replay does not verify it again (DEC-157). Top-down from `head`, so the
    /// lowest bad block is the one reported. Every block is read once for its
    /// FR21 value, so a deletion can value the retargeted entry. One read
    /// buffer in this frame (DEC-136).
    #[inline(never)]
    fn switch_signature_prepass(&mut self, head: u32, ancestor: u32) -> PrePass {
        let Some(bound) = self.blocks.get(ancestor).map(|entry| entry.sequence()) else {
            return PrePass::Local;
        };
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let mut through = 0u64;
        let mut lowest = None;
        let mut cur = head;
        for _ in 0..MAX_BLOCKS {
            if cur == ancestor {
                return match lowest {
                    Some((block, through)) => PrePass::Invalid { block, through },
                    None => PrePass::Clean,
                };
            }
            let Some((parent, verified)) = self
                .blocks
                .get(cur)
                .map(|entry| (entry.parent_ref(), entry.is_signature_verified()))
            else {
                return PrePass::Local;
            };
            let Some(view) = self.view_retained(cur, &mut buf) else {
                return PrePass::Local;
            };
            through = through.saturating_add(block_value::<MAX_NODES>(&view));
            if !verified && self.key_is_branch_independent(view.creator(), bound) {
                match self.verify_block_creator_signature(&view) {
                    Some(true) => {
                        self.blocks.mark_signature_verified(cur);
                    }
                    Some(false) => lowest = Some((cur, through)),
                    None => {}
                }
            }
            cur = parent;
        }
        PrePass::Local
    }

    /// AC2 + AC3: undoes the active head block — the exact inverse of
    /// [`Self::validate_and_derive_block`] — demotes it Active → Connected
    /// and moves the head to its parent. `Err` is a local failure with nothing
    /// changed: a failed read, an inconsistent seed source or value, or a
    /// vote-engine refusal — never evidence (AC2 step 2).
    pub(super) fn undo_active_head(&mut self) -> Result<(), ()> {
        let idx = self.active_chain_head_idx;
        let entry = self.blocks.get(idx).ok_or(())?;
        let (parent, payload_type) = (entry.parent_ref(), entry.payload_type());
        let mut owners = [NONE_REF; MAX_BALANCE_ENTRIES];
        let mut sources = [NONE_REF; MAX_BALANCE_ENTRIES];
        let mut count = 0;
        if payload_type == PAYLOAD_TYPE_BALANCE {
            count = self.balance_owners(idx, &mut owners).ok_or(())?;
            // Undone top-down, so every later block listing an owner is
            // undone already: its seed source is this block (D9).
            if owners[..count]
                .iter()
                .any(|owner| self.node_info.seed_source_of(*owner) != Some(idx))
            {
                return Err(());
            }
            self.previous_seed_sources(parent, &owners[..count], &mut sources[..count])?;
        }
        let creator = self.undo_committed_block(idx, &owners[..count], &sources[..count])?;
        self.active_set.remove(creator);
        self.blocks.set_status(idx, BlockStatus::Connected);
        self.blocks.set_on_active_chain(idx, false);
        self.active_chain_head_idx = parent;
        Ok(())
    }

    /// The owner ids of the balance block at `idx`, copied out so the
    /// seed-source scan's read buffer never lives beside this one (AC12).
    #[inline(never)]
    fn balance_owners(&self, idx: u32, owners: &mut [u32; MAX_BALANCE_ENTRIES]) -> Option<usize> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf)?;
        let mut count = 0;
        for info in view.balances()?.iter() {
            *owners.get_mut(count)? = info.owner();
            count += 1;
        }
        Some(count)
    }

    /// Story 6.3 D4 (DEC-169): each owner's previous FR50 seed source — the
    /// nearest block at or below `from` that lists it in a balance block or
    /// registers it, walking down to the root (the lowest retained block);
    /// `SEED_SOURCE_RELEASED` when the root misses too. One scan for every
    /// owner; FR50 coverage puts each previous source within `W` of `from`,
    /// and the walk stops once every owner is found. A block that can hold
    /// neither is skipped unread. Its own read buffer (DEC-136). `Err` on a
    /// failed read or a walk that does not reach the root (a corrupt
    /// `parent_ref` cycle): a local failure.
    #[inline(never)]
    pub(super) fn previous_seed_sources(
        &self,
        from: u32,
        owners: &[u32],
        out: &mut [u32],
    ) -> Result<(), ()> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let mut remaining = owners.len();
        let mut cur = from;
        let mut ended = false;
        for _ in 0..=MAX_BLOCKS {
            if remaining == 0 || cur == NONE_REF {
                ended = true;
                break;
            }
            let entry = self.blocks.get(cur).ok_or(())?;
            let (parent, payload_type) = (entry.parent_ref(), entry.payload_type());
            if payload_type == PAYLOAD_TYPE_BALANCE || payload_type == PAYLOAD_TYPE_TRANSACTION {
                let view = self.view_retained(cur, &mut buf).ok_or(())?;
                let mut found = |node: u32| {
                    for (owner, source) in owners.iter().zip(out.iter_mut()) {
                        if *owner == node && *source == NONE_REF {
                            *source = cur;
                            remaining -= 1;
                        }
                    }
                };
                if let Some(payload) = view.balances() {
                    for info in payload.iter() {
                        found(info.owner());
                    }
                } else if let Some(txs) = view.transactions() {
                    for tx in txs.iter() {
                        if let Some(reg) = tx.as_registration() {
                            found(reg.new_node_id());
                        }
                    }
                }
            }
            cur = parent;
        }
        if !ended {
            return Err(());
        }
        for source in out.iter_mut() {
            if *source == NONE_REF {
                *source = SEED_SOURCE_RELEASED;
            }
        }
        Ok(())
    }

    /// Story 6.3 AC2: the exact inverse of the per-block step on the
    /// committed block at `idx` — fallible preparation first, then infallible
    /// effects, so `Err` leaves everything unchanged (Story 6.0 D1):
    /// the vote undo (atomic), the block's own available-UTXO bits, the
    /// seed-source restore (`owners` → `sources`), the FR36 creator credit,
    /// and [`Self::invert_transactions`]; its FR21 value leaves the active
    /// value. A balance block seeds nothing in Ready (D9), so its seeding
    /// inverse is the identity (O-009, DEC-025). Its own read buffer. Returns
    /// the block's creator, which leaves the active set (Story 6.4 D2).
    #[inline(never)]
    fn undo_committed_block(
        &mut self,
        idx: u32,
        owners: &[u32],
        sources: &[u32],
    ) -> Result<u32, ()> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf).ok_or(())?;
        let value = block_value::<MAX_NODES>(&view);
        let remaining_value = self.active_branch_value.checked_sub(value).ok_or(())?;
        // AC2 precondition, a real check: undone top-down, the block's bits are
        // exactly its own outputs, all set (every later spend of them is undone
        // already).
        let (fees, outputs) = fees_and_utxo_outputs(&view);
        if (0..Self::UTXO_BITFIELD_WIDTH as usize)
            .any(|bit| self.blocks.utxo_available(idx, bit) != Some(bit < outputs))
        {
            return Err(());
        }
        // The vote engine refuses atomically; its errors are the node's own
        // state, never evidence against the block (AC2 step 2).
        if let Ok(v) = BlockView::from_bytes(view.serialized_bytes()) {
            // FR72: the credit drop the apply made (Story 6.13 AC6).
            let drop = fact::credit_drop::<_, MAX_BLOCKS, MAX_NODES, AVAILABLE_UTXO_BYTES>(
                &self.blocks,
                &self.storage,
                self.verification_horizon(),
                idx,
            );
            if !drop.reads_hold(&v) {
                return Err(());
            }
            let undone = self.vote_engine.undo_block(v, |node| drop.excluded(node));
            if drop.faulted() {
                // The engine's result is not trusted: escalate (DEC-205),
                // as the commit and the vote step do; the FR3 pass has no
                // re-entry of its own (code review P7).
                self.reentry_due |= self.is_ready();
                return Err(());
            }
            undone.map_err(|_| ())?;
        }
        // Undone top-down: every descendant spend of this block's outputs is
        // undone already and side branches never touch bits, so its bits are
        // exactly its own outputs.
        self.blocks.clear_available_utxo(idx);
        for (owner, source) in owners.iter().zip(sources) {
            self.node_info.move_seed_source(*owner, *source);
        }
        if !is_fr36_exempt(&view) && self.node_info.is_seeded(view.creator()) {
            self.node_info
                .debit(view.creator(), view.mined_amount() as u64 + fees);
        }
        self.invert_transactions(&view, idx, usize::MAX);
        self.active_branch_value = remaining_value;
        self.active_open_run = run_before(self.active_open_run, &view);
        Ok(view.creator())
    }

    /// Promotes a block the replay (or the restore) just applied: Connected →
    /// Active (FR9), on the active chain, the new head; its FR21 value joins
    /// the active value and its `creator` the active set (Story 6.4 D2). The
    /// tail is left to the commit (D3).
    pub(super) fn promote_replayed(&mut self, idx: u32, value: u64, creator: u32) {
        self.blocks.set_status(idx, BlockStatus::Active);
        self.blocks.set_on_active_chain(idx, true);
        self.active_chain_head_idx = idx;
        self.active_branch_value += value;
        self.active_set.add(creator);
    }

    /// AC5 — the commit, after which nothing fails: FR19 event (iii) first
    /// (the release step's fragment reclamation reads current caches), the
    /// FR21 (iv) value hand-over before any release (a release may delete the
    /// old head), then the deferred tail advances and their FR21 (iii)
    /// subtraction, and last the FR58 reclamation of every block that left the
    /// switch bound between the old head and the new one — the demoted branch
    /// included once its common ancestor did (DEC-208). No comparison follows
    /// (FR22 (d)). Story 7.4 adds the mempool window expiry (FR32 (3)).
    fn commit_switch(
        &mut self,
        head: u32,
        old_head: u32,
        old_value: u64,
        advances: usize,
        released_value: u64,
    ) {
        let old_head_seq = self.blocks.get(old_head).map(|entry| entry.sequence());
        self.chain_heads.recompute_all_caches(&self.blocks);
        // The active value is never an entry (DEC-144); the old head, if an
        // entry still names it, carries the old active value.
        self.chain_heads.set_branch_value(head, 0);
        self.chain_heads.set_branch_value(old_head, old_value);
        for _ in 0..advances {
            if !self.advance_snake_chain_tail() {
                // Unreachable by construction — the replay advanced the
                // virtual tail along the same flagged chain. FR64: log the
                // invariant breach. Deferred — see deferred-work.md. The
                // active set no longer matches the window (Story 6.4 D2).
                self.active_set.invalidate();
                return;
            }
        }
        self.active_branch_value = self.active_branch_value.saturating_sub(released_value);
        self.chain_heads
            .subtract_branch_value(&self.blocks, released_value);
        // The old head's bound was `S_head_old − H`: everything from there up to
        // the new bound crossed it with this switch.
        if let (Some(seq), Some(h)) = (old_head_seq, self.verification_horizon()) {
            self.reclaim_out_of_bound(seq.saturating_sub(h));
        }
    }

    /// AC6 — restores the original chain after a failed walk: undoes every
    /// block above the original chain's path (never below `ancestor`),
    /// re-applies the original branch up to `old_head` by the same step (its
    /// blocks are marked, so no signature is verified again), and, for exact
    /// evidence at `offender`, deletes it with its descendants. Any error
    /// while restoring stops it where it is (a restore failure), whatever its
    /// kind.
    fn restore_original(
        &mut self,
        ancestor: u32,
        old_head: u32,
        old_value: u64,
        offender: Option<(u32, u64)>,
    ) -> SwitchOutcome {
        while !self.on_path_to(old_head) {
            if self.active_chain_head_idx == ancestor || self.undo_active_head().is_err() {
                return self.stop_restore(offender);
            }
        }
        let tail = self.snake_chain_tail_idx;
        while self.active_chain_head_idx != old_head {
            let Some(next) = self.next_toward(old_head) else {
                return self.stop_restore(offender);
            };
            match self.apply_stored_child(next, tail) {
                ChildStep::Applied {
                    advance,
                    value,
                    creator,
                } => {
                    // Its effects are committed: promote it either way. The
                    // original chain fit the window, so an advance means an
                    // inconsistent window — stop (the caller re-enters collecting,
                    // DEC-205).
                    self.promote_replayed(next, value, creator);
                    if advance.is_some() {
                        return self.stop_restore(offender);
                    }
                }
                _ => return self.stop_restore(offender),
            }
        }
        // FR64: a recomputed value differing from the recorded one is an
        // invariant breach to log; the recorded value stands. Deferred — see
        // deferred-work.md.
        self.active_branch_value = old_value;
        self.chain_heads.recompute_all_caches(&self.blocks);
        match offender {
            Some((block, parent_value)) => {
                self.delete_offender(block, Some(parent_value));
                SwitchOutcome::Deleted
            }
            None => SwitchOutcome::Kept,
        }
    }

    /// Whether the active head lies on the path from the root to `target`.
    fn on_path_to(&self, target: u32) -> bool {
        let head = self.active_chain_head_idx;
        self.blocks.get(head).is_some_and(|entry| {
            matches!(self.ancestor_at(target, entry.sequence()), Ok(Some(idx)) if idx == head)
        })
    }

    /// AC6 restore failure: the walk stops where the restore reached — on
    /// the original chain, or on a prefix of the new one when an undo failed.
    /// Every step is atomic, so nothing is half-applied, but the chain is
    /// shorter than the window and horizon the ready-state rules assume: the
    /// caller re-enters collecting (DEC-205), which rebuilds every derived
    /// structure from the tree. Nothing of the original chain is deleted; the
    /// offender, if any, is still exact evidence and goes first.
    fn stop_restore(&mut self, offender: Option<(u32, u64)>) -> SwitchOutcome {
        if let Some((block, parent_value)) = offender {
            self.delete_offender(block, Some(parent_value));
        }
        SwitchOutcome::RestoreFailed
    }

    /// Deletes an offending new-branch block with its descendants (exact
    /// evidence, FR9; no FR5 in Ready, DEC-019) and gives the entry the
    /// deletion retargets onto its parent that parent's value, when the
    /// parent is a Connected side block.
    ///
    /// FR64 (Epic 11 `LogSink`): emit the deletion event carrying the block's
    /// hash. Deferred — see deferred-work.md.
    fn delete_offender(&mut self, block: u32, parent_value: Option<u64>) {
        let parent = self
            .blocks
            .get(block)
            .map_or(NONE_REF, |entry| entry.parent_ref());
        self.delete_subtree_with_followup(block);
        if let Some(value) = parent_value
            && self
                .blocks
                .get(parent)
                .is_some_and(|entry| entry.status() == BlockStatus::Connected)
        {
            self.chain_heads.set_branch_value(parent, value);
        }
    }
}
