//! `chain_heads.rs` — FR19 / FR20.
//!
//! Owns the `ChainHeadsTable { heads: [ChainHeadEntry; MAX_BRANCH_COUNT] }`
//! (~2.8 KB at the default `MAX_BRANCH_COUNT = 40`) — the tip set of the
//! bounded block-tree, with per-head parent-recovery scheduling and the
//! bounded-eviction deletion path.
//!
//! Story 4.4 scope (Epic 4): the tip table + **driven** mutation events
//! (i) new-block admission and (ii) tail-pointing parent admission, the FR19/FR46
//! parent-recovery scheduler (deterministic selection + tie-breaks), and the
//! FR19 bounded eviction (the block-tree's first authorized deletion path).
//! Events (iii) FR23 chain-switch and (iv) FR5 deletion are **specified**
//! (documented on the relevant helpers) but **driven** by Epic 6 / Epic 5.
//! `branch_value` (FR21) is present but unpopulated (Epic 6).
//!
//! ## head_ref_count is a branch-count, not a path-count (KEY DECISION)
//!
//! FR19's safety-critical eviction rule — "walking back from the evicted head
//! …for each block visited, `head_ref_count` is decremented by 1; …if the
//! resulting count remains > 0 …the walk terminates" — is only correct if
//! `head_ref_count[b]` is the number of **distinct head-bearing branches that
//! pass through `b`** (its out-degree toward heads), NOT the number of heads in
//! `b`'s subtree. Under the branch-count model the eviction walk decrements the
//! evicted head's branch and stops at the first block still shared by another
//! branch — exactly FR19's "stop at count > 0." Maintenance:
//!
//! - **new isolated tip / extend**: the new block gets `head_ref_count = 1`; the
//!   parent (on extend) is unchanged — the same single branch continues.
//! - **fork** (parent already in the tree, not a head): the new block gets 1 and
//!   the **fork-point parent gains +1** (a genuinely new branch now passes
//!   through it). *This +1 is required for eviction safety* — FR19's literal
//!   "the fork-point block and its ancestors retain their existing ref-counts"
//!   is eviction-unsafe as written (evicting one fork arm would delete the
//!   shared fork-point); the ancestors *above* the fork-point correctly retain.
//! - **event (ii) connect**: the junction block that gains the reconnected
//!   child gets +1.
//! - **eviction**: decrement along the evicted branch, delete at 0, stop at > 0.
//!
//! This reconciliation of FR19's per-event wording to its own eviction rule was
//! **ratified 2026-07-12**: PRD FR19 + the `moonblokz-info` KB (prd / algorithm)
//! were corrected to define `head_ref_count` as this branch-count and to
//! increment the fork-point on a fork (the original "fork-point … retain"
//! wording was eviction-unsafe). This module is the reference implementation.

use crate::api::ParentRecoveryRequest;
use crate::blocks::{BlockTable, NONE_REF};

/// `flags` bit 0: the FR19 `connected` cache — the head's ancestry resolves to
/// the current active chain. `0` = Stored (parent-recovery scheduled), `1` =
/// Connected. Active membership is derived globally (`head_idx ==
/// active_chain_head_idx`), so there is no per-head Active flag (FR19).
const FLAG_CONNECTED: u8 = 0b0000_0001;

/// One tracked block-tree tip (architecture §6.3 + the Story 4.4 additions —
/// `arrival_timestamp` (FR18 head-scoped) and `missing_parent_hash` (a Stored-only
/// cache of the tail-point's `previous_hash`, so the scheduler and event (ii)
/// need no durable-storage read)).
///
/// Empty-slot sentinel: `head_idx == u32::MAX` ([`NONE_REF`]).
#[allow(dead_code)] // `arrival_timestamp`/`branch_value` are Epic-8/Epic-6 consumers.
pub(crate) struct ChainHeadEntry {
    /// Index into `blocks` of the head (tip) block. `head_sequence` /
    /// `head_block_id` (the FR63 tie-break keys) are read from `blocks[head_idx]`
    /// — no cached copies (architecture §6.3).
    head_idx: u32,
    /// Stored → tail-point index (lowest-sequence block on the branch whose
    /// parent is unresolved); Connected → connection-point index (highest-sequence
    /// block on the branch that lies on the active chain). Overlaid per §6.3.
    tail_or_connection_idx: u32,
    /// Stored-only cache: the tail-point block's `previous_hash` — the missing
    /// parent the FR19 request targets. Recomputable from the block-tree; cached
    /// here so neither the scheduler nor event (ii) reads durable storage.
    missing_parent_hash: [u8; 32],
    /// FR19 parent-recovery scheduling: local wall-clock time of this head's last
    /// emitted request (`0` = never → immediately eligible). Stored-only.
    last_request_timestamp: u64,
    /// FR18 head-scoped arrival timestamp (local wall-clock time the head block
    /// was admitted/advanced). Populated but **unread in Epic 4** — the FR9 Tier 3
    /// block-creation pacing rule (Epic 8) reads the parent-to-current
    /// arrival-time difference. **Never** a selection/eviction tie-break input
    /// (FR19/FR63 — wall-clock is non-deterministic across nodes).
    arrival_timestamp: u64,
    /// FR21 relative branch value (Connected/Active only). Present but
    /// **unpopulated** in Epic 4 — computed by Epic 6.
    branch_value: u64,
    /// State flags (bit 0 = `connected`).
    flags: u8,
}

impl ChainHeadEntry {
    const fn new_empty() -> Self {
        Self {
            head_idx: NONE_REF,
            tail_or_connection_idx: NONE_REF,
            missing_parent_hash: [0; 32],
            last_request_timestamp: 0,
            arrival_timestamp: 0,
            branch_value: 0,
            flags: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.head_idx == NONE_REF
    }

    fn is_connected(&self) -> bool {
        self.flags & FLAG_CONNECTED != 0
    }

    #[cfg(test)]
    fn is_stored(&self) -> bool {
        !self.is_empty() && !self.is_connected()
    }
}

/// FR19 bounded tip table over a fixed-capacity `MAX_BRANCH_COUNT` array
/// (architecture §6.3). `chain_heads_max_capacity == MAX_BRANCH_COUNT`.
#[allow(dead_code)] // methods are consumed by `api.rs` wiring; tests exercise each directly.
pub(crate) struct ChainHeadsTable<const MAX_BRANCH_COUNT: usize> {
    heads: [ChainHeadEntry; MAX_BRANCH_COUNT],
}

/// Where a downward parent-walk from a block bottoms out (head classification).
enum Anchor {
    /// The branch reaches the active chain at this block index — Connected head;
    /// this index is the connection-point.
    Connection(u32),
    /// The branch bottoms out at this block whose parent is unresolved — Stored
    /// head; this index is the tail-point.
    Tail(u32),
}

impl<const MAX_BRANCH_COUNT: usize> ChainHeadsTable<MAX_BRANCH_COUNT> {
    /// In-place construction for embedded/task use (mirrors
    /// [`BlockTable::init_in_place`]), and this type's only constructor: each
    /// `ChainHeadEntry` is written directly to its final address, so no
    /// whole-array temporary is materialized. An earlier by-value `new()`
    /// (backed by a compile-time `const EMPTY`, same rationale as
    /// `BlockTable::EMPTY` used to have) was removed once every caller was
    /// confirmed able to use this constructor instead — see
    /// `Blockchain::init_in_place`'s doc comment for why.
    ///
    /// # Safety
    /// `dst` must be valid for writes of `Self` and non-overlapping with any
    /// other live reference. Writes over possibly-uninitialized memory without
    /// reading or dropping the old value, correct only because `dst` is not yet
    /// initialized.
    pub(crate) unsafe fn init_in_place(dst: *mut Self) {
        let heads_ptr = unsafe { core::ptr::addr_of_mut!((*dst).heads) } as *mut ChainHeadEntry;
        for i in 0..MAX_BRANCH_COUNT {
            unsafe {
                heads_ptr.add(i).write(ChainHeadEntry::new_empty());
            }
        }
    }

    /// Number of occupied tip entries.
    pub(crate) fn count(&self) -> usize {
        self.heads.iter().filter(|h| !h.is_empty()).count()
    }

    /// `true` iff at least one Stored head exists. The scheduler's `NextCall`
    /// derivation uses [`Self::earliest_recovery_deadline`] (which returns `None`
    /// on the same condition) instead; this predicate is kept for the Epic 5
    /// collecting-state lifecycle gating (a node stays a pure receiver while any
    /// Stored head still awaits its parent) and is exercised by the tests.
    #[allow(dead_code)] // consumed by the Epic 5 lifecycle gating; tests use it now.
    pub(crate) fn has_stored_head(&self) -> bool {
        self.heads
            .iter()
            .any(|h| !h.is_empty() && !h.is_connected())
    }

    /// Slot of the entry whose head block is `head_idx`, if any.
    fn slot_of_head(&self, head_idx: u32) -> Option<usize> {
        self.heads
            .iter()
            .position(|h| !h.is_empty() && h.head_idx == head_idx)
    }

    fn first_empty(&self) -> Option<usize> {
        self.heads.iter().position(|h| h.is_empty())
    }

    /// Walk down `parent_ref` from `start_idx` to the branch anchor: the first
    /// active-chain block (Connection) or the deepest unresolved-parent block
    /// (Tail). Bounded by `MAX_BLOCKS` (same rationale as
    /// `BlockTable::walks_to_active_chain`).
    fn locate_anchor<const MAX_BLOCKS: usize>(
        blocks: &BlockTable<MAX_BLOCKS>,
        start_idx: u32,
    ) -> Anchor {
        let mut current = start_idx;
        let mut last_valid = start_idx;
        for _ in 0..MAX_BLOCKS {
            let Some(entry) = blocks.get(current) else {
                return Anchor::Tail(last_valid);
            };
            if entry.is_on_active_chain() {
                return Anchor::Connection(current);
            }
            if entry.parent_ref() == NONE_REF {
                return Anchor::Tail(current);
            }
            last_valid = current;
            current = entry.parent_ref();
        }
        Anchor::Tail(current)
    }

    /// The cached missing-parent hash for a Stored head whose tail-point is
    /// `tail_idx` (copied when a new head shares an existing branch's tail).
    fn cached_missing_hash_for_tail(&self, tail_idx: u32) -> Option<[u8; 32]> {
        self.heads
            .iter()
            .find(|h| !h.is_empty() && !h.is_connected() && h.tail_or_connection_idx == tail_idx)
            .map(|h| h.missing_parent_hash)
    }

    /// Populate a head entry's cache fields (`connected` flag, tail/connection
    /// index, `missing_parent_hash`) from the current block-tree structure — the
    /// FR19 "caches are recomputable / invalidated-and-recomputed" rule.
    /// `new_block_prev_hash` is a just-processed block's `previous_hash`, used
    /// when this head's tail-point *is* that block (so the hash is in hand
    /// without a storage read).
    fn recompute_caches<const MAX_BLOCKS: usize>(
        &mut self,
        slot: usize,
        blocks: &BlockTable<MAX_BLOCKS>,
        anchor_block_idx: u32,
        anchor_block_prev_hash: &[u8; 32],
    ) {
        let head_idx = self.heads[slot].head_idx;
        match Self::locate_anchor(blocks, head_idx) {
            Anchor::Connection(conn_idx) => {
                self.heads[slot].flags |= FLAG_CONNECTED;
                self.heads[slot].tail_or_connection_idx = conn_idx;
                self.heads[slot].last_request_timestamp = 0; // scheduling removed
                self.heads[slot].missing_parent_hash = [0; 32];
            }
            Anchor::Tail(tail_idx) => {
                self.heads[slot].flags &= !FLAG_CONNECTED;
                self.heads[slot].tail_or_connection_idx = tail_idx;
                let hash = if tail_idx == anchor_block_idx {
                    *anchor_block_prev_hash
                } else {
                    self.cached_missing_hash_for_tail(tail_idx)
                        .unwrap_or(*anchor_block_prev_hash)
                };
                self.heads[slot].missing_parent_hash = hash;
            }
        }
    }

    // -- FR19 mutation events (i) + (ii): block admission ---------------------

    /// Update the tip table for a just-admitted block (already inserted at
    /// `Stored` in `blocks`).
    ///
    /// `new_idx` is the block's index in `blocks`; `parent` is `Some(idx)` if its
    /// `previous_hash` resolved in the tree, else `None`; `prev_hash` is its
    /// `previous_hash` (in hand — no storage read); `active_head_idx` is the
    /// global `active_chain_head_idx` (`NONE_REF` = none).
    pub(crate) fn on_block_admitted<const MAX_BLOCKS: usize>(
        &mut self,
        blocks: &mut BlockTable<MAX_BLOCKS>,
        new_idx: u32,
        parent: Option<u32>,
        prev_hash: [u8; 32],
        arrival_now: u64,
        active_head_idx: u32,
    ) {
        // The new block is a fresh tip → its own branch contributes 1.
        blocks.adjust_head_ref_count(new_idx, 1);

        match parent {
            Some(parent_idx) => {
                if let Some(slot) = self.slot_of_head(parent_idx) {
                    // Event (i) EXTEND — parent was a head; advance it. The single
                    // branch continues, so the parent's ref-count is unchanged.
                    self.heads[slot].head_idx = new_idx;
                    self.heads[slot].arrival_timestamp = arrival_now;
                    self.recompute_caches(slot, blocks, new_idx, &prev_hash);
                } else {
                    // Event (i) FORK — parent is interior; a new branch now passes
                    // through it → fork-point +1 (eviction safety). New head entry.
                    blocks.adjust_head_ref_count(parent_idx, 1);
                    self.insert_head(blocks, new_idx, arrival_now, &prev_hash, active_head_idx);
                }
            }
            None => {
                // Event (i) NEW STORED HEAD — parent unresolved. Head == tail-point;
                // `last_request_timestamp = 0` so the next tick schedules the first
                // parent-recovery request.
                self.insert_head(blocks, new_idx, arrival_now, &prev_hash, active_head_idx);
            }
        }

        // Event (ii): does the just-admitted block resolve any *other* Stored
        // head's missing tail-point parent?
        self.resolve_pending_tails(blocks, new_idx, &prev_hash);
    }

    /// Insert a brand-new head entry (fork / new-stored / bootstrap), evicting
    /// first if the table is at capacity (FR19 bounded eviction). Cache fields
    /// are computed from the tree: genesis/active-anchored heads come out
    /// Connected, missing-parent heads come out Stored.
    fn insert_head<const MAX_BLOCKS: usize>(
        &mut self,
        blocks: &mut BlockTable<MAX_BLOCKS>,
        head_idx: u32,
        arrival_now: u64,
        prev_hash: &[u8; 32],
        active_head_idx: u32,
    ) {
        if self.count() >= MAX_BRANCH_COUNT {
            self.evict_one(blocks, active_head_idx);
        }
        let Some(slot) = self.first_empty() else {
            // Only reachable if every entry is the active head (cannot evict) —
            // then the new tip is simply not tracked (bounded resources, FR20).
            return;
        };
        self.heads[slot] = ChainHeadEntry {
            head_idx,
            tail_or_connection_idx: head_idx,
            missing_parent_hash: [0; 32],
            last_request_timestamp: 0,
            arrival_timestamp: arrival_now,
            branch_value: 0,
            flags: 0,
        };
        self.recompute_caches(slot, blocks, head_idx, prev_hash);
    }

    /// Event (ii): the just-admitted block `x_idx` may be the missing parent a
    /// Stored head `H` has been waiting for. For each such head, link its
    /// tail-point `T` to X and recompute `H`'s caches (Stored→Connected when the
    /// branch now reaches the active chain, else a deeper tail-point).
    ///
    /// **Reverse-arrival merge (the parent-recovery common case — child `T`
    /// arrived before parent `X`).** When X was admitted, event (i) already made
    /// X a tip (`head_idx == x_idx` in some slot). Attaching `T` as X's child
    /// makes X interior, so:
    /// - the **first** tail to attach to X *merges*: X's own head entry is
    ///   removed (X is no longer a tip; `H`'s head is the surviving tip) and X's
    ///   ref-count is **unchanged** (its single tip attachment becomes its single
    ///   child attachment — the branch-count out-degree is still 1);
    /// - a **subsequent** tail attaching to X (a fork *below* X) genuinely adds a
    ///   new child branch, so X's ref-count is bumped +1 (fork-point semantics).
    ///
    /// Getting this wrong would leave a stale head pointing at an interior block
    /// and double-count X (breaking eviction). See the module's branch-count note.
    ///
    /// **Two phases** so that *several heads sharing one tail-point* `T` (a fork
    /// *above* `T`) are all handled: phase 1 resolves each distinct unresolved
    /// tail that names X as parent (exactly once per tail) and does the X
    /// merge/fork accounting; phase 2 recomputes **every** Stored head that was
    /// waiting for X — including the shared-tail siblings that phase 1's
    /// resolve-once left with an already-linked tail — so none is stranded as a
    /// zombie still emitting recovery requests for a block now in the tree.
    fn resolve_pending_tails<const MAX_BLOCKS: usize>(
        &mut self,
        blocks: &mut BlockTable<MAX_BLOCKS>,
        x_idx: u32,
        x_prev_hash: &[u8; 32],
    ) {
        let Some(x_entry) = blocks.get(x_idx) else {
            return;
        };
        let x_hash = *x_entry.hash();
        let x_seq = x_entry.sequence();

        // Phase 1 — resolve each *distinct* unresolved tail that names X as its
        // parent (a tail with `parent_ref == NONE_REF`, sequence `x_seq + 1`, and
        // a head whose cached `missing_parent_hash == x_hash`). A tail shared by
        // several heads is resolved on the first head that reaches it; the shared
        // siblings then fail the `parent_ref == NONE_REF` test and are handled in
        // phase 2.
        for slot in 0..MAX_BRANCH_COUNT {
            let (is_empty, is_conn, tail_idx, mph) = {
                let h = &self.heads[slot];
                (
                    h.is_empty(),
                    h.is_connected(),
                    h.tail_or_connection_idx,
                    h.missing_parent_hash,
                )
            };
            if is_empty || is_conn || tail_idx == x_idx || mph != x_hash {
                continue;
            }
            let unresolved_child = blocks
                .get(tail_idx)
                .is_some_and(|t| t.parent_ref() == NONE_REF && t.sequence() == x_seq + 1);
            if !unresolved_child {
                continue;
            }
            blocks.resolve_parent_ref(tail_idx, x_idx);
            // Merge vs. fork-below-X accounting (see the doc above): the first
            // child attaching to X merges away X's transient own-head (ref-count
            // unchanged); each further distinct child is a genuine fork at X (+1).
            if let Some(x_own_slot) = self.slot_of_head(x_idx) {
                self.heads[x_own_slot] = ChainHeadEntry::new_empty();
            } else {
                blocks.adjust_head_ref_count(x_idx, 1);
            }
        }

        // Phase 2 — recompute every Stored head that was waiting for X. After
        // phase 1 each such head's tail resolves through X, so `recompute_caches`
        // migrates it to the new (deeper) tail-point or reclassifies it Connected.
        for slot in 0..MAX_BRANCH_COUNT {
            let (is_empty, is_conn, mph) = {
                let h = &self.heads[slot];
                (h.is_empty(), h.is_connected(), h.missing_parent_hash)
            };
            if is_empty || is_conn || mph != x_hash {
                continue;
            }
            self.recompute_caches(slot, blocks, x_idx, x_prev_hash);
        }
    }

    // -- FR19 bounded eviction ------------------------------------------------

    /// Evict the non-active head with the smallest `head_sequence` (tie →
    /// smallest `head_block_id` big-endian, FR63). Back-walk decrementing
    /// `head_ref_count`; a block reaching 0 is deleted from the tree (its durable
    /// slot released for reuse), a block staying > 0 is shared and terminates the
    /// walk. Removes the entry.
    fn evict_one<const MAX_BLOCKS: usize>(
        &mut self,
        blocks: &mut BlockTable<MAX_BLOCKS>,
        active_head_idx: u32,
    ) {
        let Some(victim_slot) = self.select_eviction_victim(blocks, active_head_idx) else {
            return;
        };
        let mut current = self.heads[victim_slot].head_idx;
        for _ in 0..MAX_BLOCKS {
            let (parent, on_active) = match blocks.get(current) {
                Some(entry) => (entry.parent_ref(), entry.is_on_active_chain()),
                None => break,
            };
            if on_active {
                // The active chain (and, contiguously, everything below it) is
                // **never** deleted by eviction — even when this head's branch
                // telescopes an active block's ref-count to 0. Drop this head's
                // edge but keep the block and stop the walk. This is the robust
                // guard: victim exclusion only protects the exact `active_head_idx`,
                // but a Connected head that *extends* the active root leaves the
                // root without a matching head entry (its head advanced), so the
                // root must be protected structurally here, not by exclusion alone.
                blocks.adjust_head_ref_count(current, -1);
                break;
            }
            match blocks.adjust_head_ref_count(current, -1) {
                Some(0) => {
                    blocks.delete(current); // releases storage_index == current
                }
                _ => break, // shared with another branch — stop
            }
            if parent == NONE_REF {
                break;
            }
            current = parent;
        }
        self.heads[victim_slot] = ChainHeadEntry::new_empty();
    }

    /// FR19 eviction victim selection: smallest `head_sequence` among non-active
    /// heads, tie broken by smallest `head_block_id` (big-endian). Pure `&self`.
    fn select_eviction_victim<const MAX_BLOCKS: usize>(
        &self,
        blocks: &BlockTable<MAX_BLOCKS>,
        active_head_idx: u32,
    ) -> Option<usize> {
        let mut best: Option<(usize, u32, [u8; 32])> = None;
        for (slot, head) in self.heads.iter().enumerate() {
            if head.is_empty() || head.head_idx == active_head_idx {
                continue;
            }
            let Some(entry) = blocks.get(head.head_idx) else {
                continue;
            };
            let seq = entry.sequence();
            let hash = *entry.hash();
            let take = match &best {
                None => true,
                Some((_, best_seq, best_hash)) => {
                    seq < *best_seq || (seq == *best_seq && hash < *best_hash)
                }
            };
            if take {
                best = Some((slot, seq, hash));
            }
        }
        best.map(|(slot, _, _)| slot)
    }

    // -- FR19 / FR46 parent-recovery scheduler --------------------------------

    /// Deterministic FR19/FR46 selection: among Stored heads whose per-head retry
    /// window has elapsed (`last_request_timestamp + per_head_retry ≤ now`), pick
    /// the smallest `last_request_timestamp`, ties broken by smallest
    /// `head_sequence`, then smallest `head_block_id` (big-endian). Pure `&self`
    /// — the caller applies the timestamp writes on the winner via
    /// [`Self::mark_requested`]. Returns the winning slot and the request
    /// (missing-parent hash + `tail.sequence − 1`).
    pub(crate) fn select_parent_recovery<const MAX_BLOCKS: usize>(
        &self,
        blocks: &BlockTable<MAX_BLOCKS>,
        now: u64,
        per_head_retry: u64,
    ) -> Option<(usize, ParentRecoveryRequest)> {
        let mut best: Option<(usize, u64, u32, [u8; 32])> = None;
        for (slot, head) in self.heads.iter().enumerate() {
            if head.is_empty() || head.is_connected() {
                continue;
            }
            if Self::head_eligible_at(head.last_request_timestamp, per_head_retry) > now {
                continue;
            }
            let Some(entry) = blocks.get(head.head_idx) else {
                continue;
            };
            let head_seq = entry.sequence();
            let head_hash = *entry.hash();
            let lrt = head.last_request_timestamp;
            let take = match &best {
                None => true,
                Some((_, b_lrt, b_seq, b_hash)) => {
                    lrt < *b_lrt
                        || (lrt == *b_lrt
                            && (head_seq < *b_seq || (head_seq == *b_seq && head_hash < *b_hash)))
                }
            };
            if take {
                best = Some((slot, lrt, head_seq, head_hash));
            }
        }
        let (slot, _, _, _) = best?;
        let tail_idx = self.heads[slot].tail_or_connection_idx;
        let tail_seq = blocks.get(tail_idx).map(|e| e.sequence())?;
        // `claimed_parent_sequence = tail.sequence − 1` (FR19). A Stored head's
        // tail-point never has sequence 0 (genesis has no missing parent), so the
        // saturating sub is defensive only.
        let claimed = tail_seq.saturating_sub(1);
        let req = ParentRecoveryRequest::new(self.heads[slot].missing_parent_hash, claimed);
        Some((slot, req))
    }

    /// The per-head eligibility instant: a never-requested head
    /// (`last_request_timestamp == 0`) is eligible from time 0 (FR46 "immediately
    /// eligible"); otherwise it is eligible at `last_request_timestamp +
    /// per_head_retry`. Used both by selection and by the exact-deadline
    /// computation so the two never disagree.
    fn head_eligible_at(last_request_timestamp: u64, per_head_retry: u64) -> u64 {
        if last_request_timestamp == 0 {
            0
        } else {
            last_request_timestamp.saturating_add(per_head_retry)
        }
    }

    /// The earliest instant at which *some* Stored head becomes per-head eligible
    /// for a parent-recovery request, or `None` when no Stored head exists. The
    /// caller combines this with the FR46 global emit cooldown to compute the
    /// exact next `NextCall::At` — so the bridge wakes precisely when a request
    /// can fire, never on a fixed periodic tick (there is no
    /// `parent_recovery_global_tick_interval` in the AR4 scheduling-pull model).
    pub(crate) fn earliest_recovery_deadline(&self, per_head_retry: u64) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        for head in self.heads.iter() {
            if head.is_empty() || head.is_connected() {
                continue;
            }
            let eligible_at = Self::head_eligible_at(head.last_request_timestamp, per_head_retry);
            earliest = Some(earliest.map_or(eligible_at, |e| e.min(eligible_at)));
        }
        earliest
    }

    /// Mark the winning head as requested at `now` (the only scheduler mutation).
    pub(crate) fn mark_requested(&mut self, slot: usize, now: u64) {
        if let Some(head) = self.heads.get_mut(slot) {
            head.last_request_timestamp = now;
        }
    }

    // -- Events (iii)/(iv): specified, not driven (AC8) -----------------------
    //
    // (iii) FR23 chain-switch reconciliation (Epic 6): on an active-chain switch
    //       every Connected/Active head's `connected` flag + connection-point are
    //       recomputed (`recompute_caches`), a head that no longer reaches the
    //       active chain demotes to Stored (tail-point populated,
    //       `last_request_timestamp` reset to 0, `branch_value` cleared), and
    //       `head_ref_count` is unaffected (structural). Driver owned by Epic 6.
    // (iv)  FR5 atomic recovery deletion (Epic 5): a chain_heads entry whose head
    //       is deleted is removed; survivors whose ancestry passed through a
    //       deleted block have caches recomputed; a Connected head that loses its
    //       connection demotes to Stored. Driver owned by Epic 5.

    #[cfg(test)]
    fn head_at(&self, slot: usize) -> &ChainHeadEntry {
        &self.heads[slot]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::BlockEntry;

    fn hash_of(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    // Insert a metadata-only block, returning its index. The chain_heads logic is
    // over the block-tree metadata graph, so we build exact ancestry shapes with
    // `BlockEntry::new(hash, parent_ref, sequence)` without signed blocks.
    fn put<const N: usize>(t: &mut BlockTable<N>, byte: u8, parent: u32, seq: u32) -> u32 {
        t.insert(BlockEntry::new(hash_of(byte), parent, seq))
            .unwrap()
    }

    /// Test-only stand-in for the deleted by-value `BlockTable::new()`: wraps
    /// the `MaybeUninit` + `init_in_place` + `assume_init()` calling
    /// convention once so individual tests don't each repeat `unsafe` code.
    fn empty_blocks<const N: usize>() -> BlockTable<N> {
        let mut table = core::mem::MaybeUninit::<BlockTable<N>>::uninit();
        unsafe {
            BlockTable::init_in_place(table.as_mut_ptr());
            table.assume_init()
        }
    }

    /// Test-only stand-in for the deleted by-value `ChainHeadsTable::new()`:
    /// same rationale as [`empty_blocks`].
    fn empty_chain_heads<const N: usize>() -> ChainHeadsTable<N> {
        let mut table = core::mem::MaybeUninit::<ChainHeadsTable<N>>::uninit();
        unsafe {
            ChainHeadsTable::init_in_place(table.as_mut_ptr());
            table.assume_init()
        }
    }

    #[test]
    fn empty_table_has_no_heads() {
        let ch = empty_chain_heads::<4>();
        assert_eq!(ch.count(), 0);
        assert!(!ch.has_stored_head());
    }

    #[test]
    fn new_stored_head_on_unresolved_parent() {
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let b = put(&mut blocks, 5, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, b, None, hash_of(9), 1_000, NONE_REF);
        assert_eq!(ch.count(), 1);
        assert!(ch.has_stored_head());
        assert!(ch.head_at(0).is_stored());
        assert_eq!(ch.head_at(0).tail_or_connection_idx, b);
        assert_eq!(ch.head_at(0).missing_parent_hash, hash_of(9));
        assert_eq!(ch.head_at(0).last_request_timestamp, 0);
        assert_eq!(blocks.head_ref_count(b), Some(1));
    }

    #[test]
    fn extend_advances_single_head() {
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let a = put(&mut blocks, 1, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, a, None, hash_of(9), 1, NONE_REF);
        let b = put(&mut blocks, 2, a, 6);
        ch.on_block_admitted(&mut blocks, b, Some(a), hash_of(1), 2, NONE_REF);
        assert_eq!(ch.count(), 1, "extend does not create a new head");
        assert_eq!(ch.head_at(0).head_idx, b);
        assert_eq!(
            blocks.head_ref_count(a),
            Some(1),
            "extend leaves parent unchanged"
        );
        assert_eq!(blocks.head_ref_count(b), Some(1));
    }

    #[test]
    fn fork_creates_second_head_and_bumps_fork_point() {
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let a = put(&mut blocks, 1, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, a, None, hash_of(9), 1, NONE_REF);
        let b = put(&mut blocks, 2, a, 6);
        ch.on_block_admitted(&mut blocks, b, Some(a), hash_of(1), 2, NONE_REF);
        let bp = put(&mut blocks, 3, a, 6);
        ch.on_block_admitted(&mut blocks, bp, Some(a), hash_of(1), 3, NONE_REF);
        assert_eq!(ch.count(), 2, "fork creates a second head");
        assert_eq!(
            blocks.head_ref_count(a),
            Some(2),
            "fork-point gains a branch (+1) for eviction safety"
        );
        assert_eq!(blocks.head_ref_count(b), Some(1));
        assert_eq!(blocks.head_ref_count(bp), Some(1));
    }

    #[test]
    fn eviction_deletes_exclusive_blocks_and_protects_shared() {
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let a = put(&mut blocks, 1, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, a, None, hash_of(9), 1, NONE_REF);
        let b = put(&mut blocks, 2, a, 6);
        ch.on_block_admitted(&mut blocks, b, Some(a), hash_of(1), 2, NONE_REF);
        let bp = put(&mut blocks, 3, a, 6);
        ch.on_block_admitted(&mut blocks, bp, Some(a), hash_of(1), 3, NONE_REF);
        // Evict the smaller-hash fork head (B hash 2 < B' hash 3, same seq 6).
        ch.evict_one(&mut blocks, NONE_REF);
        assert_eq!(ch.count(), 1);
        assert!(blocks.get(b).is_none(), "exclusive block B deleted");
        assert!(blocks.get(a).is_some(), "shared fork-point A protected");
        assert_eq!(
            blocks.head_ref_count(a),
            Some(1),
            "A decremented to B'-only"
        );
        assert!(blocks.get(bp).is_some(), "surviving head B' intact");
    }

    #[test]
    fn eviction_full_branch_when_unshared() {
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let a = put(&mut blocks, 1, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, a, None, hash_of(9), 1, NONE_REF);
        let b = put(&mut blocks, 2, a, 6);
        ch.on_block_admitted(&mut blocks, b, Some(a), hash_of(1), 2, NONE_REF);
        ch.evict_one(&mut blocks, NONE_REF);
        assert_eq!(ch.count(), 0);
        assert!(blocks.get(a).is_none());
        assert!(blocks.get(b).is_none(), "whole unshared branch deleted");
    }

    #[test]
    fn eviction_never_evicts_active_head() {
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let a = put(&mut blocks, 1, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, a, None, hash_of(9), 1, NONE_REF);
        let b = put(&mut blocks, 2, NONE_REF, 4);
        ch.on_block_admitted(&mut blocks, b, None, hash_of(8), 2, NONE_REF);
        ch.evict_one(&mut blocks, a); // A's head marked active → excluded
        assert!(blocks.get(a).is_some(), "active head never evicted");
        assert!(
            blocks.get(b).is_none(),
            "non-active smaller-seq head evicted"
        );
    }

    #[test]
    fn scheduler_selects_most_overdue_then_tie_breaks() {
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let lo = put(&mut blocks, 20, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, lo, None, hash_of(20), 1, NONE_REF);
        let hi = put(&mut blocks, 30, NONE_REF, 9);
        ch.on_block_admitted(&mut blocks, hi, None, hash_of(30), 1, NONE_REF);
        let (slot, req) = ch
            .select_parent_recovery(&blocks, 1_000_000, 100)
            .expect("an eligible head");
        assert_eq!(
            ch.head_at(slot).head_idx,
            lo,
            "smaller head_sequence wins the lrt=0 tie"
        );
        assert_eq!(req.missing_parent_hash(), &hash_of(20));
        assert_eq!(req.claimed_parent_sequence(), 4, "tail.sequence - 1");
    }

    #[test]
    fn scheduler_per_head_retry_window_gates() {
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let h = put(&mut blocks, 20, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, h, None, hash_of(20), 1, NONE_REF);
        let (slot, _) = ch.select_parent_recovery(&blocks, 1_000, 500).unwrap();
        ch.mark_requested(slot, 1_000);
        assert!(
            ch.select_parent_recovery(&blocks, 1_400, 500).is_none(),
            "per-head retry window not yet elapsed"
        );
        assert!(
            ch.select_parent_recovery(&blocks, 1_500, 500).is_some(),
            "retry window elapsed at now == lrt + retry"
        );
    }

    #[test]
    fn scheduler_never_requested_head_is_immediately_eligible() {
        // FR46: a never-requested head (`last_request_timestamp == 0`) is
        // eligible immediately — even at a `now` smaller than `per_head_retry`
        // (a freshly booted node must not wait a full retry window for its first
        // request).
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let h = put(&mut blocks, 20, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, h, None, hash_of(20), 1, NONE_REF);
        assert!(
            ch.select_parent_recovery(&blocks, 5, 120_000).is_some(),
            "lrt == 0 is eligible even at now (5) << per_head_retry (120000)"
        );
        assert_eq!(ch.earliest_recovery_deadline(120_000), Some(0));
        // After a request, the head's next eligibility is lrt + per_head_retry.
        let (slot, _) = ch.select_parent_recovery(&blocks, 5, 120_000).unwrap();
        ch.mark_requested(slot, 1_000);
        assert_eq!(ch.earliest_recovery_deadline(120_000), Some(121_000));
        assert!(ch.select_parent_recovery(&blocks, 5, 120_000).is_none());
    }

    #[test]
    fn earliest_recovery_deadline_none_without_stored_heads() {
        let ch = empty_chain_heads::<4>();
        assert_eq!(ch.earliest_recovery_deadline(120_000), None);
    }

    #[test]
    fn scheduler_ignores_connected_heads() {
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        // Active genesis block (is_on_active_chain set) at seq 0.
        let mut e = BlockEntry::new(hash_of(1), NONE_REF, 0);
        e.set_on_active_chain(true);
        let g = blocks.insert(e).unwrap();
        ch.on_block_admitted(&mut blocks, g, None, [0; 32], 1, g);
        assert!(
            ch.head_at(0).is_connected(),
            "genesis/active head is Connected"
        );
        assert!(!ch.has_stored_head());
        assert!(ch.select_parent_recovery(&blocks, 1_000_000, 1).is_none());
    }

    #[test]
    fn event_ii_resolves_tail_to_new_deeper_tail() {
        // Stored head H = block T (seq 6, parent missing, waiting for hash 5).
        // Admit X (seq 5, hash 5, parent still missing) → T links to X, tail
        // migrates to X, head stays Stored with X's missing parent.
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let t = put(&mut blocks, 6, NONE_REF, 6);
        ch.on_block_admitted(&mut blocks, t, None, hash_of(5), 1, NONE_REF);
        assert_eq!(ch.head_at(0).tail_or_connection_idx, t);
        // X arrives: hash 5 (== H.missing_parent_hash), seq 5 (== tail.seq - 1),
        // its own parent (hash 4) still missing. Reverse arrival (child before
        // parent) → X merges into H's branch, X's transient own-head is dropped.
        let x = put(&mut blocks, 5, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, x, None, hash_of(4), 2, NONE_REF);
        assert_eq!(
            ch.count(),
            1,
            "X's transient head merges into H (one branch)"
        );
        // H's tail migrated to X; H still Stored, now waiting for X's parent.
        let h_slot = (0..4).find(|&s| ch.head_at(s).head_idx == t).unwrap();
        assert!(ch.head_at(h_slot).is_stored());
        assert_eq!(ch.head_at(h_slot).tail_or_connection_idx, x);
        assert_eq!(ch.head_at(h_slot).missing_parent_hash, hash_of(4));
        assert_eq!(blocks.get(t).unwrap().parent_ref(), x, "tail linked to X");
        // Branch-count: X has exactly one child (T) — out-degree 1, not 2.
        assert_eq!(blocks.head_ref_count(x), Some(1));
        // And the merged branch is evictable cleanly: evicting H deletes T then X.
        ch.evict_one(&mut blocks, NONE_REF);
        assert_eq!(ch.count(), 0);
        assert!(blocks.get(t).is_none());
        assert!(
            blocks.get(x).is_none(),
            "no leaked block after merge + eviction"
        );
    }

    #[test]
    fn eviction_never_deletes_active_chain_root_after_extend() {
        // Review Finding A: genesis G is the active root; extending it advances
        // the head (head_idx G→B) while `active_chain_head_idx` stays G, so no
        // head entry matches the exact active-head exclusion. Eviction must still
        // never delete an `is_on_active_chain` block — the walk stops at it.
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let mut ge = BlockEntry::new(hash_of(1), NONE_REF, 0);
        ge.set_on_active_chain(true);
        let g = blocks.insert(ge).unwrap();
        ch.on_block_admitted(&mut blocks, g, None, [0; 32], 1, g);
        // Extend the active root: head advances G→B; active_chain_head_idx stays G.
        let b = put(&mut blocks, 2, g, 1);
        ch.on_block_admitted(&mut blocks, b, Some(g), hash_of(1), 2, g);
        assert_eq!(ch.count(), 1);
        assert_eq!(
            ch.head_at(0).head_idx,
            b,
            "head advanced off the active root"
        );
        // Fill to capacity with higher-sequence orphan heads (seq 5,6,7).
        for (byte, seq) in [(20u8, 5u32), (30, 6), (40, 7)] {
            let o = put(&mut blocks, byte, NONE_REF, seq);
            ch.on_block_admitted(&mut blocks, o, None, hash_of(byte), 3, g);
        }
        assert_eq!(ch.count(), 4);
        // One more orphan head forces eviction; the smallest-seq victim is B
        // (seq 1), whose back-walk reaches G. G must survive.
        let extra = put(&mut blocks, 50, NONE_REF, 9);
        ch.on_block_admitted(&mut blocks, extra, None, hash_of(50), 4, g);
        assert!(
            blocks.get(g).is_some(),
            "genesis / active root is never evicted"
        );
        assert!(
            blocks.get(b).is_none(),
            "the Connected extension B was the victim"
        );
        assert_eq!(ch.count(), 4, "capacity held");
    }

    #[test]
    fn event_ii_shared_tail_resolves_all_heads_no_zombie() {
        // Review Finding B: two heads U and V share tail-point T (a fork *above*
        // T). Admitting T's missing parent X must migrate BOTH — not leave V a
        // zombie still requesting X's hash.
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let t = put(&mut blocks, 6, NONE_REF, 5);
        ch.on_block_admitted(&mut blocks, t, None, hash_of(4), 1, NONE_REF);
        let u = put(&mut blocks, 7, t, 6); // extend T
        ch.on_block_admitted(&mut blocks, u, Some(t), hash_of(6), 2, NONE_REF);
        let v = put(&mut blocks, 8, t, 6); // fork at T
        ch.on_block_admitted(&mut blocks, v, Some(t), hash_of(6), 3, NONE_REF);
        assert_eq!(ch.count(), 2, "two heads U and V share tail T");
        // Admit X = T's missing parent (hash 4, seq 4).
        let x = put(&mut blocks, 4, NONE_REF, 4);
        ch.on_block_admitted(&mut blocks, x, None, hash_of(3), 4, NONE_REF);
        // Neither head is a zombie: none still points its missing-parent cache at
        // X's hash; both migrated to X's own missing parent (hash 3).
        for slot in 0..4 {
            let h = ch.head_at(slot);
            if !h.is_empty() && !h.is_connected() {
                assert_ne!(
                    h.missing_parent_hash,
                    hash_of(4),
                    "no head still requests the now-present block X"
                );
                assert_eq!(
                    h.tail_or_connection_idx, x,
                    "both heads' tails migrated to X"
                );
                assert_eq!(h.missing_parent_hash, hash_of(3));
            }
        }
        assert_eq!(ch.count(), 2, "U and V both survive as heads");
        assert_eq!(blocks.head_ref_count(x), Some(1), "X has one child (T)");
        assert_eq!(blocks.head_ref_count(t), Some(2), "T forks to U and V");
        // The scheduler no longer selects anything for X (no zombie request).
        let (_, req) = ch.select_parent_recovery(&blocks, 1_000_000, 1).unwrap();
        assert_eq!(
            req.missing_parent_hash(),
            &hash_of(3),
            "requests X's parent, not X"
        );
    }

    #[test]
    fn event_ii_connects_to_active_chain() {
        // Active genesis G (seq 0). Stored head H = T (seq 1, waiting for G).
        let mut blocks = empty_blocks::<8>();
        let mut ch = empty_chain_heads::<4>();
        let mut ge = BlockEntry::new(hash_of(7), NONE_REF, 0);
        ge.set_on_active_chain(true);
        let g = blocks.insert(ge).unwrap();
        ch.on_block_admitted(&mut blocks, g, None, [0; 32], 1, g);
        let t = put(&mut blocks, 6, NONE_REF, 1);
        ch.on_block_admitted(&mut blocks, t, None, hash_of(7), 2, NONE_REF);
        assert!(ch.head_at(1).is_stored());
        // G was already admitted; now re-admit its relationship by resolving T's
        // parent to G directly (simulate G arriving after T). Since G is already
        // present, drive event (ii) via a fresh admission whose hash matches.
        // Here T's missing parent hash == G.hash (7): resolve directly.
        ch.resolve_pending_tails(&mut blocks, g, &[0; 32]);
        // H's branch now reaches the active chain → Connected.
        let h_slot = (0..4).find(|&s| ch.head_at(s).head_idx == t).unwrap();
        assert!(
            !ch.head_at(h_slot).is_stored(),
            "H transitions to Connected"
        );
        assert_eq!(
            ch.head_at(h_slot).tail_or_connection_idx,
            g,
            "connection-point is the active block"
        );
        assert!(!ch.has_stored_head());
    }
}
