//! FR7 / FR8 / FR17 chain-configuration handling and the configuration
//! parameter readers (Stories 5.8, 5.9, 5.12).

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
    // -----------------------------------------------------------------------
    // FR7/FR8 chain-config commitment lifecycle (Story 5.9)
    // -----------------------------------------------------------------------

    /// The configuration content this node currently holds: the durable-locked
    /// one once the FR8 lock is engaged, otherwise the tentatively-loaded one,
    /// and `None` while it holds none.
    ///
    /// The two are never both present — the module keeps one buffer and one
    /// commitment flag (Story 5.7, NFR1) — so this is a selection, not a
    /// precedence rule. Durable is read first anyway, so the expression states
    /// the invariant it relies on rather than assuming it.
    pub(super) fn held_chain_config_content(&self) -> Option<&[u8]> {
        match self.chain_config.durable_content() {
            Some(durable) => Some(durable),
            None => self.chain_config.tentative_content(),
        }
    }

    /// Walks the candidate segment `tip → anchor` over `parent_ref`, answering
    /// the two questions the FR8 lifecycle asks about it *without* a storage
    /// read: which block is its **first** (lowest-sequence) in-scope chain-config
    /// block (`NONE_REF` if it carries none), and whether `probe` lies on the
    /// segment.
    ///
    /// This repeats the mark walk `run_processing_pass` performs, deliberately.
    /// The pass's own `marked` buffer is a local of that function and its frame
    /// is released before the Ready transition and the adopt-retry read the
    /// answer; keeping the pass's signature free of an out-parameter — and the
    /// `Blockchain` free of pass scratch state that a later caller could read
    /// stale — is worth one re-walk over cached flag bits on paths that already
    /// cost a full forward derivation.
    ///
    /// Pass `NONE_REF` for `probe` when only the config block is wanted;
    /// `NONE_REF` is never a live index, so the flag is then always `false`.
    ///
    /// A walk that does not end at the segment's anchor — a `parent_ref` into a
    /// freed slot, or a cycle exhausting the `MAX_BLOCKS` bound — reports no
    /// config block, matching the pass, which refuses that same ancestry with
    /// `MissingBlock` / `MarkOverflow`. Otherwise FR2 would keep selecting a
    /// segment whose every pass fails, and FR5 would take a head each time.
    pub(super) fn scan_candidate_chain_config(&self, tip: u32, probe: u32) -> (u32, bool) {
        let mut first_config_idx = NONE_REF;
        let mut probe_on_segment = false;
        let mut reached_anchor = false;
        let mut cur = tip;
        for _ in 0..MAX_BLOCKS {
            let Some(entry) = self.blocks.get(cur) else {
                break;
            };
            if cur == probe {
                probe_on_segment = true;
            }
            if entry.payload_type() == PAYLOAD_TYPE_CHAIN_CONFIG {
                first_config_idx = cur;
            }
            let parent = entry.parent_ref();
            if parent == NONE_REF {
                reached_anchor = true;
                break;
            }
            cur = parent;
        }
        if !reached_anchor {
            first_config_idx = NONE_REF;
        }
        (first_config_idx, probe_on_segment)
    }

    /// FR9 re-evaluation, candidate side: the first block of the candidate
    /// segment that exceeds the block-size limit the node is **about to lock**,
    /// or `None` when every block fits.
    ///
    /// This is the deferred half of the FR9 rule made good. While the
    /// configuration was only tentative, the size check could not condemn a block;
    /// at the durable lock it can, and FR9 names that moment explicitly. Run
    /// *before* the commit and before `promote_candidate_active`, so a violation
    /// is still an ordinary FR5 rollback rather than damage to a chain the node
    /// has already adopted.
    ///
    /// Reads `BlockEntry::len()`, the length cached at admission, so the whole
    /// re-evaluation costs no storage reads. The limit comes from
    /// [`Self::block_size_limit`] — the *declared* value — which is correct here
    /// precisely because this runs at the commitment: the FR3 preload has already
    /// established that what the node holds is the candidate's own configuration,
    /// and it is the one about to become durable.
    pub(super) fn candidate_block_exceeding_size_limit(&self, tip: u32) -> Option<u32> {
        let limit = self.block_size_limit() as usize;
        let mut offender = None;
        let mut cur = tip;
        for _ in 0..MAX_BLOCKS {
            let entry = self.blocks.get(cur)?;
            if entry.len() as usize > limit {
                // Keep walking: the segment is traversed tip → anchor, so the
                // last violator seen is the earliest one, and FR5 wants the
                // earliest offender.
                offender = Some(cur);
            }
            let parent = entry.parent_ref();
            if parent == NONE_REF {
                break;
            }
            cur = parent;
        }
        offender
    }

    /// FR9 re-evaluation, retained-tree side: applies the now-locked
    /// configuration to every retained block that was admitted while the limit
    /// could not be enforced, deleting those that violate it along with their
    /// descendants.
    ///
    /// Runs immediately after the lock, alongside the AC5 content-mismatch
    /// cleanup, and skips on-active-chain blocks — the candidate was re-evaluated
    /// before the commit, so anything still on the active chain has already been
    /// measured against this exact limit.
    pub(super) fn reevaluate_retained_blocks_against_lock(&mut self) {
        let limit = self.enforceable_block_size_limit() as usize;
        for idx in 0..MAX_BLOCKS {
            let idx = idx as u32;
            let Some(entry) = self.blocks.get(idx) else {
                continue;
            };
            if entry.is_on_active_chain() || (entry.len() as usize) <= limit {
                continue;
            }
            self.delete_subtree_with_followup(idx);
        }
    }

    /// FR8 durable set-once lock (AC4): commits the candidate's configuration to
    /// the durable control plane and promotes the module's commitment, exactly
    /// once for the lifetime of the chain.
    ///
    /// `first_config_idx` is the candidate's first in-scope chain-config block.
    /// By the AC3 final check every in-scope config block carries identical
    /// content, so *which* one is committed cannot matter; the first is chosen
    /// because it is the one the chain named earliest and the one the AC6 adopt
    /// path takes, so the two agree by construction.
    ///
    /// **Storage first, then promote** — the same order the FR54 genesis path
    /// uses. The durable write is the step that can fail; doing it while the
    /// module is still merely tentative means a failure leaves a node that can
    /// try again, whereas promoting first would engage an *irrevocable* lock over
    /// content the control plane does not hold.
    ///
    /// Returns `Err(())` if the durable write fails or the promotion is refused.
    /// A refused promotion is not papered over: `promote_durable` refuses a
    /// second promotion by design (Story 5.7), and swallowing that would turn the
    /// set-once guarantee into a no-op.
    // Its own frame (stack budget, DEC-136): its block buffer stays out of
    // the acquisition loop's frame.
    #[inline(never)]
    pub(super) fn commit_durable_chain_config(&mut self, first_config_idx: u32) -> Result<(), ()> {
        // The control plane takes an owned `Block`, so this one-shot path holds
        // the read buffer and that copy (both in this frame, DEC-136).
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(first_config_idx, &mut buf).ok_or(())?;
        let block = Block::from_bytes(view.serialized_bytes()).map_err(|_| ())?;
        // The pass compared content from one read of this slot; this is a second
        // read, and it is the one whose bytes reach the control plane. Check it
        // still carries what the module is about to lock: a divergence between the
        // two reads would leave the control plane holding one configuration and
        // the module irrevocably locked on another, with no way back. Fail closed
        // — the caller abandons the transition and the node retries.
        let commits_what_is_locked = BlockView::from_bytes(block.serialized_bytes())
            .ok()
            .and_then(|view| view.chain_config().map(|config| config.content()))
            == self.chain_config.tentative_content();
        if !commits_what_is_locked {
            return Err(());
        }
        self.storage
            .set_chain_configuration(&block)
            .map_err(|_| ())?;
        self.chain_config.promote_durable().map_err(|_| ())?;
        // The provenance named a *tentative*; the commitment is durable now and
        // the module will never discard it. Clearing keeps the index from
        // outliving what it describes and firing the AC8 unload for a block that
        // no longer supplies anything.
        self.tentative_config_block_idx = NONE_REF;
        Ok(())
    }

    /// FR8 lock-time mismatch cleanup (AC5): deletes every chain-config block
    /// anywhere in the block-tree whose content differs from the now-locked
    /// configuration, each with its descendant subtree and the FR19
    /// `chain_heads` follow-up.
    ///
    /// Scope is the **whole tree** — the candidate's own active chain, retained
    /// side branches, and unconnected orphans alike — because FR8 words it that
    /// way and because a retained block that can never again be admitted (FR17
    /// silently discards it from now on) is pure occupancy in a bounded table.
    ///
    /// The active chain is never damaged, and that is a consequence rather than a
    /// precaution: AC3 proved every in-scope config block byte-identical to what
    /// was just locked, so no on-active-chain config block can mismatch, and the
    /// delete-set is closed under the child relation, so nothing on the active
    /// chain descends from a deleted block either. The debug assertion below
    /// states that so a future change to AC3 fails loudly instead of quietly
    /// deleting the chain the node just adopted.
    ///
    /// Deletion invalidates indices, so each subtree is discovered against the
    /// tree as it stands at that moment rather than from one up-front list.
    pub(super) fn delete_mismatching_chain_config_blocks(&mut self) {
        for idx in 0..MAX_BLOCKS {
            let idx = idx as u32;
            // Re-read per iteration: an earlier subtree deletion may have freed
            // this slot, and a freed slot is not a block.
            let Some(entry) = self.blocks.get(idx) else {
                continue;
            };
            if entry.payload_type() != PAYLOAD_TYPE_CHAIN_CONFIG {
                continue;
            }
            // A **runtime** guard, not a `debug_assert!`. AC3 proves no
            // on-active-chain config block can mismatch, so this never fires on a
            // healthy node — but the predicate below answers from a storage read,
            // and a read that fails must not be allowed to delete the chain the
            // node just went Ready on. An assertion compiled out of release builds
            // is no protection at all for that; `continue` is.
            if entry.is_on_active_chain() {
                debug_assert!(
                    self.chain_config_block_matches_lock(idx),
                    "AC3 proved every in-scope chain-config block matches the lock"
                );
                continue;
            }
            // Unreadable is not mismatching: only a block whose content was read
            // and *differs* is evidence against itself.
            if !matches!(
                self.chain_config_block_content_verdict(idx),
                ConfigPreload::Differs
            ) {
                continue;
            }
            self.delete_subtree_with_followup(idx);
        }
    }

    /// The FR3 preload verdict for the candidate's first in-scope chain-config
    /// block: does its content match what this node holds, does it differ, or
    /// could it not be read at all?
    ///
    /// Three outcomes rather than two because the two failure modes carry
    /// different evidence and must not share a consequence. A content that
    /// *differs* is exact evidence about the chain (FR16) and drives the FR8
    /// mismatch path. A block that cannot be read back, or whose envelope no
    /// longer frames, says nothing about the chain — it is local I/O trouble, and
    /// collapsing it into "differs" would route it into the adopt path and, on a
    /// second failed read there, delete the block together with its whole
    /// descendant subtree. `StorageRead` keeps the pre-5.9 consequence: the
    /// candidate head only, and no retry.
    pub(super) fn candidate_chain_config_readable_match(&self, idx: u32) -> ConfigPreload {
        let Some(held) = self.held_chain_config_content() else {
            return ConfigPreload::Matches;
        };
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let Some(view) = self.view_retained(idx, &mut buf) else {
            return ConfigPreload::Unreadable;
        };
        match view.chain_config().map(|config| config.content() == held) {
            Some(true) => ConfigPreload::Matches,
            Some(false) => ConfigPreload::Differs,
            // Framed when it was admitted, unframeable now: the bytes changed
            // under us, which is a storage fault, not chain evidence.
            None => ConfigPreload::Unreadable,
        }
    }

    /// `true` iff the block at `idx` carries chain-config content byte-identical
    /// to the durable-locked configuration.
    ///
    /// A block that cannot be read back, or whose envelope does not frame, does
    /// **not** match: it carries no content region to be identical to. Answering
    /// `false` there is the safe direction — it deletes a block this node cannot
    /// interpret, rather than retaining one it cannot check.
    ///
    /// Split out as a `&self` predicate so the comparison's borrow of
    /// `chain_config` and `storage` ends before the caller mutates the block-tree.
    fn chain_config_block_matches_lock(&self, idx: u32) -> bool {
        matches!(
            self.chain_config_block_content_verdict(idx),
            ConfigPreload::Matches
        )
    }

    /// The AC5 verdict for the block at `idx` against the durable-locked
    /// configuration: matching, differing, or unreadable.
    ///
    /// Tri-state for the same reason the preload is: only `Differs` is evidence
    /// about the block. `Unreadable` is local I/O trouble and must not cost a
    /// block its place in the tree.
    fn chain_config_block_content_verdict(&self, idx: u32) -> ConfigPreload {
        let Some(locked) = self.chain_config.durable_content() else {
            return ConfigPreload::Unreadable;
        };
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let Some(view) = self.view_retained(idx, &mut buf) else {
            return ConfigPreload::Unreadable;
        };
        match view.chain_config().map(|config| config.content() == locked) {
            Some(true) => ConfigPreload::Matches,
            Some(false) => ConfigPreload::Differs,
            None => ConfigPreload::Unreadable,
        }
    }

    /// FR8 mismatch path (AC6): adopts the candidate's first in-scope
    /// chain-config content as the new tentative configuration, so the pass can
    /// be re-run over the same candidate.
    ///
    /// **Replace, don't discard-then-load.** FR8 describes clearing the seam and
    /// then adopting; `load_tentative` performs exactly that transition as one
    /// step, and doing it as one step is strictly stronger than the two-step
    /// reading: the module runs its whole acceptance pass before it retains
    /// anything (Story 5.7), so a refusal leaves the previous tentative intact
    /// and *no* intermediate state — no partially-committed configuration, and no
    /// window in which the node holds nothing — is observable at any point. A
    /// literal `discard_tentative()` first would create precisely that window,
    /// and on a refusal would leave the node worse off than before it tried.
    ///
    /// The FR7 content signature is **re-verified** here rather than trusted from
    /// the block's admission. It is the trust anchor for content this node is
    /// about to derive its whole chain from, the block has since made a round trip
    /// through durable storage, and this path is expected-rare.
    ///
    /// The previous tentative's block is removed per FR8 — but only when it is
    /// **off-candidate**. A previous tentative that sits *on* the candidate (it
    /// can: a higher-sequence config block that arrived first loads the tentative,
    /// then a lower-sequence one arrives and becomes the candidate's first) is
    /// left in place for the retry to condemn with exact evidence. Deleting it
    /// here would take the candidate's own tip subtree with it and dissolve the
    /// very candidate this retry exists to re-run.
    ///
    /// Returns `Err(())` when the block cannot be read, its signature does not
    /// re-verify, or the module refuses its content — each exact evidence against
    /// that block (FR16), which the caller routes into the FR5 recovery.
    // Its own frame (stack budget, DEC-136): its block buffer stays out of
    // the acquisition loop's frame.
    #[inline(never)]
    pub(super) fn adopt_candidate_chain_config(
        &mut self,
        tip: u32,
        first_config_idx: u32,
    ) -> Result<(), ()> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(first_config_idx, &mut buf).ok_or(())?;
        // FR7 re-verification, over the same state-free gate the intake path uses,
        // so the two can never drift apart.
        tier1_chain_config_block(&view, &self.node_zero_public_key, &self.crypto)
            .map_err(|_| ())?;
        self.chain_config
            .load_tentative(view.payload())
            .map_err(|_| ())?;
        // The FR37 parameters just changed under the engine. The re-run's pass
        // entry would reset it anyway, but the re-evaluation can legitimately
        // select no candidate at all, and leaving the engine parameterized from a
        // configuration this node has discarded is exactly the state step 3b
        // exists to prevent elsewhere.
        self.reset_vote_engine();

        let previous = self.tentative_config_block_idx;
        self.tentative_config_block_idx = first_config_idx;
        if previous != NONE_REF && previous != first_config_idx {
            let (_, on_candidate) = self.scan_candidate_chain_config(tip, previous);
            if !on_candidate {
                self.delete_subtree_with_followup(previous);
            }
        }
        Ok(())
    }

    /// The durable-locked chain-config **content** — the FR17 comparand — or
    /// `None` until the configuration is durably locked.
    ///
    /// One accessor, not two: the module returns `Some` here exactly when
    /// `is_durable_locked()` is true, so reading both would be the same
    /// predicate twice.
    pub(crate) fn durable_chain_config_content(&self) -> Option<&[u8]> {
        self.chain_config.durable_content()
    }

    /// The active-chain window length `W` the held configuration — tentative or
    /// durable — declares, or `None` while the node holds none.
    ///
    /// Read where it is needed and never cached (FR56). There is no fallback to
    /// `SNAKE_CHAIN_LENGTH_MAX`: that is this build's capacity, and a threshold
    /// taken from it would differ between builds on the same chain — exactly the
    /// disagreement making `W` chain configuration removes.
    pub(crate) fn active_chain_length(&self) -> Option<u32> {
        self.chain_config
            .active_configuration()
            .map(|config| config.active_chain_length())
    }

    /// FR58's verification horizon `H` (DEC-160) the held configuration —
    /// tentative or durable — declares, or `None` while the node holds none.
    /// Read where it is needed and never cached (FR56); acceptance holds it
    /// to `1 ≤ H < W` and `W + 2·H ≤ MAX_BLOCKS`.
    pub(crate) fn verification_horizon(&self) -> Option<u32> {
        self.chain_config
            .active_configuration()
            .map(|config| config.verification_horizon())
    }

    /// The chain's node cap `max_node_count` (DEC-228) the held configuration
    /// declares. Never cached (FR56).
    ///
    /// The per-block step runs only with a configuration held (the FR3 pass is
    /// gated on one, Story 5.8; Ready holds the durable one). Should it ever
    /// run without one, the build's own `MAX_NODES` bounds the ids instead, so
    /// the watermark can never name a node with no slot; acceptance keeps every
    /// chain's cap at or below it.
    pub(super) fn max_node_count(&self) -> u32 {
        self.chain_config
            .active_configuration()
            .map_or(MAX_NODES as u32, |config| config.max_node_count())
    }

    /// The block UTXO-output cap `max_block_utxo_output` the held configuration
    /// — tentative or durable — declares, or the bitfield width while the node
    /// holds none (I-07).
    ///
    /// The FR6 per-block step enforces this declared value even before the
    /// durable lock (DEC-133, an exception to DEC-015 like DEC-129's `W`): the
    /// FR3 preload has made the held configuration the candidate's own, so it is
    /// exactly the value the lock commits, and a block admitted under the
    /// tentative bitfield-width bound cannot be adopted past its chain's cap.
    pub(super) fn held_max_utxo_outputs(&self) -> u16 {
        self.chain_config
            .active_configuration()
            .map_or(Self::UTXO_BITFIELD_WIDTH, |config| {
                config.max_utxo_outputs()
            })
    }

    /// The block UTXO-output cap that Tier 1 may **enforce** against an arriving
    /// block: the chain's value once the configuration is durably locked, and
    /// the available-UTXO bitfield width before that (FR9; the
    /// [`Self::enforceable_block_size_limit`] pattern, DEC-132).
    pub(super) fn enforceable_max_utxo_outputs(&self) -> u16 {
        self.chain_config
            .durable_content()
            .and_then(|_| self.chain_config.active_configuration())
            .map_or(Self::UTXO_BITFIELD_WIDTH, |config| {
                config.max_utxo_outputs()
            })
    }

    /// The block-size limit **the chain declares**, once any configuration is
    /// loaded, and this build's block capacity `MAX_BLOCK_SIZE` until then.
    ///
    /// The fallback is not a policy choice standing in for a chain value — it is
    /// this build's capacity (DEC-225, amending DEC-105): a larger block cannot be
    /// framed here at all, and `BlockView::from_bytes` refuses it before intake,
    /// so the fallback never judges a block as evidence. Two builds with
    /// different capacities never disagree on whether a block is acceptable:
    /// a block above the smaller build's capacity is refused by both — as
    /// evidence on a larger build locked to a chain whose limit it exceeds, as
    /// a local refusal on the smaller one, which cannot frame it. Acceptance
    /// refuses a chain whose limit a build cannot hold (§6 check 5).
    ///
    /// Read this where the configuration in force is known to be the one the work
    /// commits to — the FR54 genesis path, which is about to lock the very
    /// configuration it is measuring against. Anything that can **reject or
    /// delete** a block must read [`Self::enforceable_block_size_limit`] instead.
    pub(super) fn block_size_limit(&self) -> u32 {
        self.chain_config
            .active_configuration()
            .map_or(MAX_BLOCK_SIZE as u32, |config| config.block_size_limit())
    }

    /// The block-size limit that may be **enforced** against an arriving or
    /// retained block: the chain's value once the configuration is durably
    /// locked, and this build's block capacity before that (DEC-225).
    ///
    /// PRD FR9 draws this line explicitly. The block-size limit is a
    /// chain-config-derived value, and such values "produce Invalid
    /// classification (and downstream deletion) **only after** the
    /// chain-configuration is durably locked per FR8 … or per FR54 (genesis);
    /// while the chain-configuration is only tentatively loaded … a tentative-only
    /// failure of any such check shall not transition the block to Invalid, shall
    /// not be deleted from durable storage, and shall be re-evaluated whenever the
    /// tentative is replaced … or whenever the durable lock is performed."
    ///
    /// The rule was vacuous before Story 5.9 — nothing on the join path loaded a
    /// tentative, so `active_configuration()` and `durable_content()` agreed. The
    /// FR8 tentative load makes the two diverge, and with them this distinction:
    /// a stray chain-config block declaring a tight limit must not cost a joining
    /// node the legitimate blocks of the chain it is actually trying to join.
    ///
    /// The deferred enforcement is not dropped. It is re-run at the moment FR9
    /// names — the durable lock — over the candidate before the commit, and over
    /// the retained tree after it; see
    /// [`Self::reevaluate_retained_blocks_against_lock`].
    pub(super) fn enforceable_block_size_limit(&self) -> u32 {
        self.chain_config
            .durable_content()
            .and_then(|_| self.chain_config.active_configuration())
            .map_or(MAX_BLOCK_SIZE as u32, |config| config.block_size_limit())
    }

    /// The FR19/FR46 parent-recovery intervals as `(min_emit, per_head_retry)`,
    /// or `None` while no configuration is loaded.
    ///
    /// Unlike the block-size limit there is no structural value to fall back on:
    /// a cadence is chain-governed through and through, so specification §5.2
    /// applies unchanged — the step that needs the configuration does not run,
    /// and the scheduler stays idle until one is loaded.
    ///
    /// **Do not "fix" this into a pre-configuration cadence.** The consequence
    /// is understood and accepted (Project Lead, 2026-09-19): while unconfigured
    /// both [`Self::on_tick`] and [`Self::receive_block`] answer
    /// `NextCall::Idle`, so the bridge holds no deadline and recovery resumes
    /// not on a timer but at the first admission after a configuration lands —
    /// and a configuration must eventually arrive to move the node forward at
    /// all, which is the same event that tips this. Inventing a cadence here
    /// would be a per-build value standing in for a chain-governed one, which is
    /// exactly what the configuration specification §6 forbids.
    ///
    /// The scheduler runs outside any block application step, so its programs
    /// read chain-info at the active head's post-state (Story 5.12).
    pub(super) fn parent_recovery_intervals(&self) -> Option<(u64, u64)> {
        let chain_info = self.chain_info_at_head();
        self.chain_config.active_configuration().map(|config| {
            let config = config.with_chain_info(&chain_info);
            (
                config.parent_recovery_min_emit_interval_ms() as u64,
                config.parent_recovery_per_head_retry_interval_ms() as u64,
            )
        })
    }

    /// The chain-info values at the active head, for a configuration consumer
    /// that runs outside a block application step (specification §4.6).
    ///
    /// Served only in `Ready`. The head state is then a function of the last `W`
    /// blocks alone (FR48-FR51), so every Ready node **at the same head** reads
    /// the same value. While Collecting or Processing there is no active chain,
    /// and every read declines.
    ///
    /// The head extension (Story 6.0) and the chain switch (Story 6.3) keep
    /// `node_info` — the watermark included — at the active head's state;
    /// Story 7.2 completes the per-block update set (FR35).
    pub(super) fn chain_info_at_head(&self) -> ChainInfoAtHead {
        ChainInfoAtHead {
            registered_node_count: self
                .is_ready()
                .then(|| u64::from(self.node_info.max_known_node_id()) + 1),
        }
    }
}

/// The blockchain's chain-info source: values read once, at bind time, from the
/// FR34 projections. A thin read: no field, no cache, no maintenance of its own.
pub(super) struct ChainInfoAtHead {
    /// Node ids are contiguous, so the count is the node-id watermark plus one.
    registered_node_count: Option<u64>,
}

impl ChainInfoSource for ChainInfoAtHead {
    fn read(&self, id: u8, args: &[u64]) -> Option<u64> {
        match (id, args) {
            (chain_info::REGISTERED_NODE_COUNT, []) => self.registered_node_count,
            _ => None,
        }
    }
}
