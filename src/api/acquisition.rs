//! FR2 dominant-chain acquisition, the FR3 processing pass and FR5 recovery
//! (Stories 5.2, 5.3, 5.5).

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
    /// FR2 dominant-chain acquisition: evaluate the collecting-phase stopping
    /// condition over the current block-tree and return the selected candidate
    /// tip's block-table index, or `None` if no candidate yet qualifies. The
    /// returned `u32` is this node's **local** handle to the chosen tip (indices
    /// are assigned by local admission order); the cross-node-deterministic
    /// quantity is the tip's identity (hash), which the tie-break orders on.
    ///
    /// Pure and side-effect-free (reads `chain_heads`, `blocks` and the held
    /// configuration; no `now`, no PRNG, no mutation — FR63/NFR5 determinism). A
    /// candidate is an occupied `chain_heads` tip whose continuous segment is
    /// either **genesis-anchored** (earliest block has `sequence == 0`, FR54) or
    /// **active-length-satisfying** (segment length `≥ W + H`: the window and
    /// the FR58 horizon below it, DEC-177), and which carries at
    /// least one chain-config block. The last condition is the FR8 final check's
    /// precondition applied *before* the pass rather than as its failure: a
    /// segment naming no configuration stays a non-candidate, with nothing
    /// deleted, until a chain-config block on it arrives (Story 5.13).
    ///
    /// `W` and `H` are what the held configuration — tentative or durable —
    /// declares, never the build's capacity `SNAKE_CHAIN_LENGTH_MAX`, which would make the
    /// moment a node stops collecting depend on how it was built. With no
    /// configuration held the active-length condition is not evaluated: the
    /// chain's window is unknown, and such a segment could not pass the FR8 final
    /// check anyway — a chain-config block in it would have loaded a tentative
    /// configuration on admission. A held tentative may be a stray whose `W`
    /// differs from the candidate's own; the adopt retry in
    /// [`Self::drive_dominant_chain_acquisition`] already resolves that mismatch.
    ///
    /// The earliest block is the head's cached `tail_or_connection_idx` (the
    /// tail for a Stored head; the connection-point for a head Connected to the
    /// bootstrap-anchored genesis — which while collecting is the genesis,
    /// `sequence 0`), so no ancestry re-walk is needed; continuity implies
    /// consecutive sequences, so segment length is exact sequence arithmetic.
    ///
    /// Selection: highest tip sequence; a same-sequence tie is broken by the
    /// **lowest tip block hash** (big-endian) — an in-memory total order (distinct
    /// blocks have distinct hashes) that preserves FR63 determinism. This is a
    /// bootstrapping pick of which candidate to reconstruct first; the final
    /// authoritative chain is governed by branch value (FR21/FR22/FR23) once
    /// ready. The PRD's fuller size→creator→hash tie-break is a deferred
    /// optimization (ratified 2026-07-22) — it would need tip block content the
    /// in-memory tree does not retain; see `prd.md` FR2 + `deferred-work.md`.
    /// `branch_value` (FR21) is never consulted here (it is 0/unpopulated —
    /// Epic 6).
    pub(crate) fn evaluate_stopping_condition(&self) -> Option<u32> {
        // (head_idx, tip_sequence, tip_hash) of the best qualifying candidate.
        let mut best: Option<(u32, u32, [u8; 32])> = None;
        // The length a window-anchored segment needs, once for the whole
        // evaluation: the window and the horizon below it (DEC-177). With no
        // configuration held the active-length condition is not evaluated.
        // Acceptance keeps `W + 2·H` within the `u32` block-storage capacity
        // (check 16), so the sum fits a `u32`.
        let required = self
            .active_chain_length()
            .zip(self.verification_horizon())
            .map(|(w, h)| w + h);
        for (head_idx, earliest_idx) in self.chain_heads.occupied_heads() {
            let (Some(tip), Some(earliest)) =
                (self.blocks.get(head_idx), self.blocks.get(earliest_idx))
            else {
                // A head always resolves in the tree; skip defensively, never panic.
                continue;
            };
            let tip_seq = tip.sequence();
            let earliest_seq = earliest.sequence();
            // Invariant: the head's earliest block (tail-point, or connection-point
            // — in collecting the only on-active-chain block is the bootstrap
            // genesis, seq 0) is never above the tip. Surfaces tree/cache
            // corruption in debug; the saturating math fails safe in release.
            debug_assert!(earliest_seq <= tip_seq, "chain-head earliest above tip");
            let genesis_anchored = earliest_seq == 0;
            // Continuity ⇒ consecutive sequences (a resolved parent link keys on
            // `child_sequence - 1`, so a continuous segment has no gaps), making the
            // length exact. `saturating_add(1)` keeps the reserved `u32::MAX`
            // sequence sentinel (rejected at intake per FR53) from ever overflowing.
            let segment_len = tip_seq.saturating_sub(earliest_seq).saturating_add(1);
            let active_length = required.is_some_and(|len| segment_len >= len);
            if !(genesis_anchored || active_length) {
                continue;
            }
            let tip_hash = *tip.hash();
            let better = match best {
                None => true,
                Some((_, best_seq, best_hash)) => {
                    tip_seq > best_seq || (tip_seq == best_seq && tip_hash < best_hash)
                }
            };
            // A segment that names no configuration is not yet a candidate
            // (Story 5.13): the FR8 final check would refuse it, and the FR5
            // recovery would then delete its head — a valid block, since no
            // single block is at fault. A later admission re-evaluates.
            //
            // Cost: the walk reads only the in-RAM block table (cached
            // `payload_type` bits and `parent_ref`), never storage. It runs for
            // every segment that passes the length test and beats the best
            // config-bearing one so far — so while segments wait for their
            // configuration, each of them is walked on every evaluation: at
            // most `MAX_BRANCH_COUNT × MAX_BLOCKS` entry reads per admission.
            if better && self.scan_candidate_chain_config(head_idx, NONE_REF).0 != NONE_REF {
                best = Some((head_idx, tip_seq, tip_hash));
            }
        }
        best.map(|(head_idx, _, _)| head_idx)
    }

    /// The FR2→FR3→FR6→FR4 acquisition spine: while a candidate segment
    /// qualifies, reconstruct and validate it, and either transition to `Ready`
    /// or recover per FR5 and fall back to `Collecting`.
    ///
    /// Extracted from [`Self::receive_block`] so the FR59 restart
    /// ([`Self::initialize_from_storage`]) drives **the identical** loop rather
    /// than a parallel copy of it. Story 5.10's acceptance criteria require a
    /// restart to reuse "the identical acquisition / reconstruction / validation
    /// code paths as a fresh join (no separate restart-only logic)" (the wording
    /// is the epics', not FR59's); sharing the body is what makes
    /// that true by construction instead of by review discipline.
    ///
    /// The caller owns the entry gate — an admission outcome and the FR2
    /// preconditions for `receive_block`, the completed rebuild for the restart
    /// — because the two have different reasons to be here. Both must hold the
    /// same two invariants on entry: the phase is `Collecting`, and a
    /// configuration is loaded (Story 5.8 — an unconfigured pass would refuse at
    /// the first FR37 vote effect and the FR5 fallback would then delete a valid
    /// block for the node's own missing configuration).
    pub(crate) fn drive_dominant_chain_acquisition(&mut self) {
        debug_assert!(
            matches!(self.lifecycle_phase, LifecyclePhase::Collecting),
            "acquisition must be entered from Collecting"
        );
        // At most **three** full-chain passes per call, from two
        // independent single-use tokens, neither ever replenished inside the
        // loop: `retries_left` covers the Story-5.5 `Invalid` recovery
        // retry, and `adopt_retries_left` the Story-5.9 FR8 config-adopt
        // retry (ratified 2026-07-30, raising Story 5.5's ceiling of two).
        // `1 + 1 + 1 = 3` regardless of interleaving — `Invalid → adopt` and
        // `adopt → Invalid` both terminate at three.
        //
        // The adopt retry additionally cannot recur *for the same candidate*
        // by construction rather than by counter: the content it adopts **is**
        // the candidate's own first in-scope config block, so on the retry
        // that block matches. The one shape that could otherwise oscillate —
        // a candidate carrying two config blocks with differing contents —
        // is excluded by the same construction: after the adopt, the first
        // block matches and the *other* one is the offender, so `block_idx`
        // no longer equals the first config block and the adopt guard below
        // does not fire. It takes the hard FR5 rollback instead.
        let mut retries_left = 1u8;
        let mut adopt_retries_left = 1u8;
        while let Some(candidate_tip_idx) = self.evaluate_stopping_condition() {
            self.set_lifecycle_phase(LifecyclePhase::Processing);
            // Story 5.3 (FR3) + Story 5.4 (FR6/FR4): reconstruct AND validate the
            // derived projection for the FR2 candidate in one forward pass. A
            // bootstrap-anchored genesis's `active_chain_head_idx` is a placeholder
            // the Ready transition below overwrites; it does not pre-empt selection.
            match self.run_processing_pass(candidate_tip_idx) {
                Ok(window_value) => {
                    // FR8 durable set-once lock (Story 5.9, AC4). The pass has
                    // just proved the AC3 final check — the candidate carries
                    // at least one chain-config block and every one of them is
                    // byte-identical to the tentative configuration — so this
                    // is the instant FR8 names for the commitment.
                    //
                    // **Before `promote_candidate_active`, not after.** The
                    // durable write can fail, and this is the last point at
                    // which a failure costs nothing: nothing has been promoted,
                    // so abandoning the transition needs no undo of a marking
                    // the FR5 recovery explicitly cannot undo (see its step-4
                    // note on recovering after a successful promotion). A
                    // failure therefore leaves the node Collecting with its
                    // blocks intact, to try again on the next admission —
                    // Story 5.8's rule that a node's own local trouble must not
                    // be charged to a valid block.
                    if !self.chain_config.is_durable_locked() {
                        let (first_config_idx, _) =
                            self.scan_candidate_chain_config(candidate_tip_idx, NONE_REF);
                        // AC3 guarantees this: the pass fails with
                        // `MissingChainConfigBlock` when the candidate carries
                        // none, so reaching `Ok(())` means one is there.
                        debug_assert!(
                            first_config_idx != NONE_REF,
                            "AC3: a candidate that passed the pass carries a chain-config block"
                        );
                        // FR9 re-evaluation at the durable lock: the
                        // block-size limit could not condemn a block while the
                        // configuration was merely tentative, so it is applied
                        // here, before anything irrevocable happens. A
                        // violation is now exact evidence — the limit being
                        // enforced is the one this very candidate declares —
                        // and takes the ordinary FR5 rollback.
                        if let Some(offender) =
                            self.candidate_block_exceeding_size_limit(candidate_tip_idx)
                        {
                            // The pass returned `Ok`, so its abort-path clear never
                            // ran and the derived available-UTXO bits are still set;
                            // the recovery does not sweep them, and a surviving
                            // block must not advertise outputs of a chain the node
                            // did not adopt (DEC-132).
                            for idx in 0..MAX_BLOCKS {
                                self.blocks.clear_available_utxo(idx as u32);
                            }
                            self.recover_from_failed_pass(
                                ProcessingError::Invalid {
                                    block_idx: offender,
                                    reason: ValidationReason::BlockTooLarge,
                                },
                                candidate_tip_idx,
                            );
                            break;
                        }
                        if first_config_idx == NONE_REF
                            || self.commit_durable_chain_config(first_config_idx).is_err()
                        {
                            // The pass returned `Ok`, so it left a complete
                            // derived projection behind and never ran its
                            // abort-path available-UTXO rollback. Abandoning the
                            // transition has to undo all of it, or the node
                            // returns to Collecting holding the projection of
                            // a chain it did not adopt. Nothing was promoted
                            // (the commit is ordered before
                            // `promote_candidate_active` precisely so this
                            // path needs no un-promotion), so the FR5 step-1
                            // rollback is the whole of the cleanup.
                            self.node_info.reset();
                            self.reset_vote_engine();
                            for idx in 0..MAX_BLOCKS {
                                self.blocks.clear_available_utxo(idx as u32);
                            }
                            self.set_lifecycle_phase(LifecyclePhase::Collecting);
                            break;
                        }
                        // FR6 passed over the full candidate → FR4 Ready
                        // transition: atomically promote every candidate block
                        // Stored→Active (the Epic-4-deferred FR9 Tier-3
                        // driver) and establish the active head.
                        self.promote_candidate_active(candidate_tip_idx, window_value);
                        // AC5: with the lock engaged and the active chain
                        // marked, drop every chain-config block in the tree
                        // that disagrees with what was just locked. Ordered
                        // after the promotion so the marking the cleanup's
                        // safety assertion reads is the final one.
                        self.delete_mismatching_chain_config_blocks();
                        // FR9's other re-evaluation trigger, for the blocks
                        // that are not on the chain just adopted.
                        self.reevaluate_retained_blocks_against_lock();
                    } else {
                        self.promote_candidate_active(candidate_tip_idx, window_value);
                    }
                    // Processing→Ready. The FR40-series ready-only surface
                    // becomes live (its query bodies remain Epic 7/10
                    // `todo!()` — reachable, but this story wires no caller).
                    self.set_lifecycle_phase(LifecyclePhase::Ready);
                    // Side branches retained while Collecting are connected by
                    // the caller, after every cleanup (Story 6.1 AC3).
                    break;
                }
                Err(err) => {
                    // FR8 mismatch path (Story 5.9, AC6) — evaluated **before**
                    // the FR5 recovery, because it is not a recovery: the
                    // candidate is not being condemned, the node's own
                    // tentative configuration is. The guard is deliberately
                    // narrow, and each clause carries weight:
                    //
                    // - a *durable* lock is irrevocable (FR8), so a mismatch
                    //   against it is always the block's fault and never an
                    //   invitation to adopt;
                    // - the offender must be the candidate's **first** in-scope
                    //   config block, which is exactly what makes the retry
                    //   at-most-once by construction — adopting the first
                    //   block's own content cannot leave it mismatching, and a
                    //   later offender means the candidate carries two
                    //   differing contents and can never satisfy AC3 under any
                    //   adoption;
                    // - and the single-use token bounds the pass count even if
                    //   a future change breaks the reasoning above.
                    if adopt_retries_left > 0
                        && !self.chain_config.is_durable_locked()
                        && let ProcessingError::Invalid {
                            block_idx,
                            reason: ValidationReason::ChainConfigMismatch,
                        } = &err
                    {
                        let block_idx = *block_idx;
                        let (first_config_idx, _) =
                            self.scan_candidate_chain_config(candidate_tip_idx, NONE_REF);
                        if block_idx == first_config_idx
                            && self
                                .adopt_candidate_chain_config(candidate_tip_idx, first_config_idx)
                                .is_ok()
                        {
                            adopt_retries_left -= 1;
                            // Re-run over the same candidate, in the same
                            // call. Reverting to Collecting first is what
                            // makes that safe rather than merely convenient:
                            // the loop head re-enters Processing, and if the
                            // re-evaluation were ever to yield no candidate,
                            // the node is left in a phase it can act from
                            // instead of stranded in Processing.
                            //
                            // The re-evaluation returns the same tip unless the
                            // adopted content declares a larger `W + H` than the one
                            // held before, in which case the segment may no
                            // longer qualify and it yields no candidate (Story
                            // 5.11) — the reverted phase covers that. Otherwise
                            // the only tree change an adopt makes is deleting an
                            // off-candidate subtree, which can only remove a
                            // *competitor* — the candidate's own dominance
                            // cannot be reduced by it.
                            self.set_lifecycle_phase(LifecyclePhase::Collecting);
                            continue;
                        }
                        // Adoption impossible (unreadable block, signature
                        // re-verification failed, or content refused): that is
                        // exact evidence against the block, so fall through to
                        // the FR5 recovery, which deletes it.
                    }
                    // FR6 failed (or FR3 could not derive) → the FR5 atomic
                    // recovery (Story 5.5): discard the working set, delete the
                    // offending block (or the candidate head) with its
                    // descendants, follow up on `chain_heads`, and revert
                    // Processing→Collecting.
                    //
                    // **Re-evaluate immediately, but only after `Invalid`**
                    // (ratified 2026-07-30, superseding the original
                    // revert-only Decision #1). The shortened branch validates
                    // **iff** the deletion removed the *first* failing block:
                    // the anchor does not move and the forward derivation is
                    // deterministic, so the retry recomputes exactly the prefix
                    // of the run that just failed. `Invalid` carries that block
                    // by construction — `block_idx` is the earliest offender, so
                    // the surviving prefix was already proved valid by the very
                    // pass that failed, and a retry over it succeeds. FR2 admits
                    // it as a candidate: a genesis-anchored segment qualifies at
                    // any length, and a window-anchored one that was well above
                    // the configured `W` (a large piece having just connected)
                    // still clears the threshold after losing its tip — in both
                    // cases only while the surviving prefix still carries a
                    // chain-config block (Story 5.13). If the deletion took the
                    // segment's only one, FR2 yields no candidate and the node
                    // waits in Collecting rather than retrying.
                    //
                    // The other variants get **no** retry, because for them the
                    // one-block head deletion is a guess, not evidence:
                    // `MarkOverflow` means a `parent_ref` cycle (a legal ancestry
                    // cannot exceed `MAX_BLOCKS`, the table's own capacity) and
                    // `MissingBlock` a `parent_ref` into a freed slot — both
                    // always *deeper* than the tip, so dropping the tip cannot
                    // remove them and the retry is structurally certain to fail
                    // while eating a second good block off the branch.
                    // `StorageRead` and `Vote(_)` *could* succeed (the fault may
                    // sit at the tip, and a transient read may simply re-read
                    // clean), but the Project Lead ruled retry-on-`Invalid`-only:
                    // spend the second pass only where success is derivable.
                    // `MissingChainConfigBlock` (AC3) is excluded: it is not
                    // evidence against the deleted head, so the shortened
                    // branch still carries no chain-config block and the retry
                    // is structurally certain to fail — while eating a second
                    // good block off the branch. The Story-5.5 argument for
                    // retrying on `Invalid` ("the deletion removed the first
                    // failing block, so the surviving prefix was already proved
                    // valid") does not apply to a violation that no single
                    // block commits. Since Story 5.13 FR2 never selects a
                    // segment naming no configuration, so this exclusion is a
                    // defensive guard, not a path the loop takes.
                    let retryable = matches!(
                        &err,
                        ProcessingError::Invalid { reason, .. }
                            if !matches!(reason, ValidationReason::MissingChainConfigBlock)
                    );
                    self.recover_from_failed_pass(err, candidate_tip_idx);
                    // The FR2 gate above is evaluated once, on entry — but the
                    // recovery can retract the configuration underneath it
                    // (AC8 step 3b, when the delete-set contained the block
                    // that supplied the tentative). Re-check before retrying:
                    // an unconfigured pass refuses at the first FR37 vote
                    // effect with `Vote(NotParameterized)`, which carries no
                    // `block_idx`, so the FR5 fallback would delete the
                    // candidate **head** — punishing a valid block for the
                    // node's own missing configuration, which is precisely
                    // what Story 5.8 put that gate there to prevent.
                    if !retryable
                        || retries_left == 0
                        || self.chain_config.active_configuration().is_none()
                    {
                        break;
                    }
                    retries_left -= 1;
                }
            }
        }
    }

    /// Brings the vote registry into the state the current chain configuration
    /// implies: empty, and parameterized when there is a configuration to
    /// parameterize from.
    ///
    /// Emptying is the obligation every caller shares (FR3 "not resumable —
    /// clean working set on re-entry", AC5, and the FR5 recovery's rollback);
    /// supplying the FR37 values is what the genesis path additionally needs,
    /// since the engine is constructed unparameterized. Both run in place, over
    /// the live value, with no `MAX_NODES`-scaled stack temporary.
    ///
    /// Deliberately not named `init_*`: in this crate `init` means in-place
    /// construction into uninitialized memory, exactly once, while this runs
    /// repeatedly on a live engine.
    pub(super) fn reset_vote_engine(&mut self) {
        // The active set is part of the projection (Story 6.4 D2): invalid
        // until the next ready entry builds it.
        self.active_set.invalidate();
        match self.chain_config.active_configuration() {
            // FR37 parameters from the chain, and an empty working set.
            Some(config) => self
                .vote_engine
                .reset(config.vote_scale(), config.vote_interest()),
            // No configuration to parameterize with — but the working set must
            // still be clean (FR3 / FR5), and the engine stays unparameterized,
            // so a vote effect reached from here refuses rather than computing
            // on a value nobody chose.
            None => self.vote_engine.clear(),
        }
    }

    /// FR5 atomic recovery from a failed full-chain pass (Story 5.5).
    ///
    /// Runs as **one** logical step at the single failure seam in
    /// [`Self::receive_block`]: no caller can observe the working set discarded
    /// but the blocks still present, or the blocks deleted but the phase not yet
    /// reverted. `pub(crate)` and self-contained (no `now`, no PRNG, no durable
    /// I/O) so the FR59 restart (Story 5.10) and the FR23 deep-zone
    /// re-derivation (Epic 6) reuse it exactly as they reuse
    /// [`Self::run_processing_pass`].
    ///
    /// **Step 1 — working-set rollback, full and unconditional** (FR5/FR34), for
    /// every `ProcessingError` variant and before any deletion decision:
    /// - `node_info.reset()` — balances, public keys, seed sources, and the
    ///   `max_known_node_id` watermark;
    /// - `reset_vote_engine()` — accumulated vote (incl. FR37 anti-capture
    ///   interest) + the FR38 creator-order projection;
    /// - the marked segment's available-UTXO bits are **already** back at their
    ///   clean baseline: [`Self::run_processing_pass`] zeroes them at pass entry
    ///   and re-zeroes them on its abort path, which is the only place that
    ///   still holds the marked set. Recovery deliberately does not sweep them a
    ///   second time.
    ///
    /// Every FR34 projection that does not exist yet is a forward seam, not a
    /// silent gap: the six Epic-7 derived projections and the `snake_chain`
    /// bookkeeping (a stub today) MUST be reset here once they land. The FR8
    /// tentative chain-config unload, which was the outstanding one, is now
    /// **step 3b** below — it could not be done before the tentative had a
    /// provenance to test the delete-set against (Story 5.9).
    ///
    /// **Step 2 — deletion target** (FR5 exact evidence):
    /// `ProcessingError::Invalid { block_idx, .. }` is the only variant that
    /// pins a block, and the forward walk guarantees `block_idx` is the
    /// **earliest** offender. A local failure (`StorageRead`,
    /// `Vote(NotParameterized)`, DEC-037; `MarkOverflow`, `MissingBlock`,
    /// DEC-134) is no evidence at all and deletes nothing; after a
    /// `MissingBlock` the index repairs itself (step 5b). An arithmetic
    /// `Vote(_)` pins no specific block, so the target is the candidate head —
    /// FR5's explicit "delete exactly one block, the candidate chain's head"
    /// fallback. `ValidationReason` is
    /// diagnostic only (the FR64 log, Epic 11) and is never a selection input.
    ///
    /// **Step 3 — transitive deletion** (FR5): the target and every transitive
    /// descendant are freed via `BlockTable::delete`; sibling subtrees whose
    /// ancestry does not pass through the target are untouched. Boundedness is
    /// by construction — the delete-set comes from
    /// [`BlockTable::mark_subtree`], which examines at most `MAX_BLOCKS` slots
    /// and walks each one's ancestry under a `MAX_BLOCKS` step bound. That is a
    /// `MAX_BLOCKS²` worst case — on the order of 360 000 `BlockTable::get`
    /// hops at the production `MAX_BLOCKS = 600`, an order of magnitude above
    /// the ~24 k hops the `head_ref_count` recompute costs. Bounded and
    /// allocation-free, but it is the dominant per-recovery cost, and recovery
    /// is a rare path by design. Because `blocks[i] ⟷ storage_index = i`,
    /// freeing the slot *is* the durable deletion (the bytes are overwritten by
    /// the next `save_block`), so recovery performs zero storage writes and zero
    /// block reads and therefore cannot fail on I/O. The **genesis pair is not
    /// exempt**: if an `Invalid` failure pins block #0/#1 of a genesis-anchored
    /// candidate they are deleted like any other block, because FR5 deletion is
    /// forward progress — a node that cannot prove its genesis must re-acquire
    /// it, and clearing `active_chain_head_idx` below is what lets it.
    ///
    /// **Step 4 — restore the pre-acquisition active-chain marking**
    /// (ratified 2026-07-30): every block's `is_on_active_chain` bit is cleared,
    /// every block's FR9 status is reset to `Stored` (FR9: "in collecting state
    /// every retained block remains in the Stored status" — never `Connected`,
    /// which has no meaning without an active chain), **and**
    /// `active_chain_head_idx` is reset; then the FR19 genesis bootstrap
    /// is re-established if block #0 survived. The status travels with the bit
    /// because [`Self::promote_candidate_active`] writes the two together.
    /// Clearing only the anchor index
    /// (the original behaviour) left the per-block bits behind, so a caller that
    /// had promoted a chain would keep blocks claiming to be on an active chain
    /// that no longer has a head. Re-establishing the genesis matters just as
    /// much as the clearing: that marking is an *admission*-time artefact, and
    /// without it a surviving genesis-anchored head would be classified `Tail`
    /// instead of `Connection` — a demotion, whose all-zero `missing_parent_hash`
    /// `select_parent_recovery` would then request forever — while the
    /// single-genesis guard would also disarm and let a second block #0 in. See
    /// the inline comment for why the demotion stays unreachable in both
    /// directions.
    ///
    /// **Step 5 — FR19 event (iv)** on `chain_heads`
    /// ([`ChainHeadsTable::on_blocks_deleted`]) — which removes the deleted
    /// heads' entries, retargets one of them to the target's now-childless
    /// parent so the shortened branch stays selectable, recomputes the
    /// survivors' caches and restores the FR19 `head_ref_count`s. It runs after
    /// step 4 so the recompute sees the final marking, not a transient mix.
    ///
    /// **Step 6 — phase reversion.** `Processing→Collecting` (a legal edge) is
    /// this function's last step; it does **not** itself re-evaluate FR2. FR5's
    /// "re-evaluate the remaining block-tree against the FR2 stopping
    /// conditions" is the caller's, and [`Self::receive_block`] does it
    /// immediately after an `Invalid` recovery rather than waiting for the next
    /// admission (ratified 2026-07-30, superseding the original revert-only
    /// Decision #1 — see the rationale at that seam). A `receive_block` call
    /// therefore performs **at most two** full-chain passes: still bounded
    /// radio-task work under the non-blocking rule, and still a deterministic
    /// FR63 replay trace.
    ///
    /// Why the original revert-only rule was wrong: it rested on the mitigation
    /// that a node holding a qualifying-but-unvalidated branch would be poked by
    /// its Stored heads' FR19 parent-recovery requests. That mitigation is
    /// inverted. A genesis-anchored shortened branch is *Connected*, so it emits
    /// no requests at all — and it is exactly the branch that still qualifies,
    /// because FR2 accepts a genesis-anchored segment at any length (as long as
    /// it carries its chain-config block, Story 5.13). The node
    /// would sit in Collecting holding a candidate whose validity the failed pass
    /// had *already computed* (`block_idx` is the earliest offender, so every
    /// block below it passed) and then discarded with the rollback.
    ///
    /// **Reuse constraint** (inherited from [`Self::run_processing_pass`]): this
    /// rollback is self-consistent only for a re-derivation over a candidate
    /// whose blocks are **not shared** with an already-active chain (a fresh
    /// join, the Story-5.10 restart). A ready-state chain switch does not
    /// re-derive: it walks the shared chain in place by exact per-block
    /// inverses (Story 6.3, DEC-168), and ready state has no
    /// full-reconstruction path (DEC-159).
    // Its own frame: the 2.4 KB delete-set never merges with the pass's
    // buffers into the acquisition loop's frame (stack budget, DEC-136).
    #[inline(never)]
    pub(crate) fn recover_from_failed_pass(
        &mut self,
        err: ProcessingError,
        candidate_tip_idx: u32,
    ) {
        // Entry contract: the only caller today is the `Processing` seam, and
        // step 5's reversion target assumes it. A future reuse (Story 5.10, Epic
        // 6) entering from another phase would be silently downgraded to
        // Collecting, so make that loud in debug and free in release.
        debug_assert!(
            matches!(self.current_phase(), LifecyclePhase::Processing),
            "FR5 recovery reverts to Collecting and must be entered from Processing"
        );

        // Step 1 — unconditional working-set rollback (before any deletion
        // decision, and regardless of which deletion path is taken).
        self.approval.clear();
        self.active_open_run = NO_OPEN_RUN;
        self.node_info.reset();
        self.reset_vote_engine();

        // Step 2 — exact offender, else the candidate-head fallback. A local
        // failure is no evidence and deletes nothing; the node retries on a
        // later admission: a read error or an absent vote parameter (amended
        // FR5, DEC-037), and an inconsistency of the node's own index — a mark
        // overflow or a `parent_ref` into a freed slot (DEC-134). Both lie
        // deeper than the tip, so deleting the head could never cure them.
        let target = match err {
            ProcessingError::Invalid { block_idx, .. } => block_idx,
            ProcessingError::StorageRead
            | ProcessingError::MarkOverflow
            | ProcessingError::MissingBlock
            | ProcessingError::Vote(VoteEngineError::NotParameterized) => NONE_REF,
            ProcessingError::Vote(_) => candidate_tip_idx,
        };
        let repair_index = matches!(err, ProcessingError::MissingBlock);

        // Step 3 — collect the subtree first, then delete, so every ancestry
        // walk runs against the pre-deletion tree. A target naming an
        // empty/out-of-range slot yields an empty set: the rollback and the
        // phase reversion still happen, nothing is deleted, nothing panics.
        //
        // Stack: `[u32; MAX_BLOCKS]` is 2.4 KB at the default `MAX_BLOCKS = 600`
        // on the Core 1 blockchain-task stack (DEC-137, sized per scheme). It does not coexist with
        // `run_processing_pass`'s equally-sized `marked` buffer — that is a local
        // of *that* function, whose frame is already released at this seam. This
        // must be re-checked if the recovery call ever moves inside the pass.
        let mut delete_set = [NONE_REF; MAX_BLOCKS];
        let deleted_count = self.blocks.mark_subtree(target, &mut delete_set);
        // Captured before the deletion: the target's parent survives (the
        // delete-set is closed under the child relation) and becomes a childless
        // tip, which event (iv) re-tracks so the shortened branch stays visible
        // to FR2 / FR19.
        let parent_of_target = self
            .blocks
            .get(target)
            .map_or(NONE_REF, |entry| entry.parent_ref());
        for idx in delete_set.iter().take(deleted_count) {
            self.blocks.delete(*idx);
        }

        // Step 3b — FR8 tentative unload (Story 5.9, AC8). A tentative
        // configuration is justified by the block that carried it; if that block
        // is gone, so is the justification, and keeping it would let the node go
        // on deriving from a configuration it can no longer point at (and which
        // FR49 replay could not reproduce).
        //
        // A **durable-locked** configuration is never unloaded — the FR8 lock is
        // irrevocable for the lifetime of the chain — and the module enforces
        // that itself: `discard_tentative` is a no-op unless the commitment is
        // `Tentative`. So this needs no lock check of its own, and cannot become
        // one by accident.
        //
        // The vote engine is re-reset **after** the unload, not instead of step
        // 1's reset: step 1 ran while the configuration was still loaded, so it
        // parameterized the engine from FR37 values that no longer have a source.
        // Re-running it now leaves the engine unparameterized, so any later vote
        // effect refuses rather than computing on a value nobody chose. Two
        // clears on a rare path, in exchange for never deriving from a retracted
        // configuration.
        if self.tentative_config_block_idx != NONE_REF
            && delete_set[..deleted_count].contains(&self.tentative_config_block_idx)
        {
            self.tentative_config_block_idx = NONE_REF;
            self.chain_config.discard_tentative();
            self.reset_vote_engine();
        }

        // Step 4 — restore the pre-acquisition active-chain marking, so recovery
        // really returns the node to its baseline instead of only clearing the
        // anchor index (ratified 2026-07-30). Both halves of the marking are
        // reset — every block's `is_on_active_chain` bit *and*
        // `active_chain_head_idx` — and then the FR19 genesis bootstrap is
        // re-established if block #0 survived, because that marking is an
        // *admission*-time artefact (`receive_block`'s `is_genesis` arm), not
        // something the failed acquisition produced. The result is exactly the
        // state the node would be in had the blocks been admitted and no
        // acquisition attempted.
        //
        // Re-establishing the genesis is load-bearing, not cosmetic. Leaving
        // every bit cleared would make `ChainHeadsTable::locate_anchor` classify
        // a genesis-anchored head as `Tail` rather than `Connection`, i.e.
        // *demote* it — and a demoted head's `missing_parent_hash` is the
        // all-zero sentinel it was given when it became Connected, which
        // `select_parent_recovery` would then request forever. It also keeps the
        // single-genesis guard armed, so a *second* genesis cannot be admitted
        // alongside the surviving one.
        //
        // When the genesis does *not* survive, no surviving head can have been
        // Connected: the delete-set is closed under the child relation, so
        // deleting block #0 deletes everything descending from it, and in
        // collecting state block #0 is the only block that is ever marked. The
        // demotion above is therefore unreachable in both directions. A caller
        // that recovers after a *successful* promotion (the Story-5.10 restart,
        // an Epic-6 chain switch) breaks that premise — `promote_candidate_active`
        // marks a whole chain — and must re-derive the survivors' caches itself.
        // The FR9 status is the other half of the same promotion and is reset
        // with it: `promote_candidate_active` writes `Active` *and* the bit
        // together, so undoing one without the other would leave a block claiming
        // `Active` while off the active chain. FR9 settles the target value —
        // "in collecting state every retained block remains in the Stored status
        // (no Connected or Active status is assigned because no active chain
        // exists)" — so it is `Stored`, never `Connected`. This is the caller
        // `BlockTable::set_status`'s Story-5.4 doc already anticipated. Idempotent
        // today: nothing on the FR5 path is ever promoted, since the promotion
        // runs only on the success branch.
        for idx in 0..MAX_BLOCKS {
            let idx = idx as u32;
            self.blocks.set_on_active_chain(idx, false);
            self.blocks.set_status(idx, BlockStatus::Stored);
        }
        self.active_chain_head_idx = NONE_REF;
        // No window while Collecting (FR48): the tail exists only in Ready.
        self.snake_chain_tail_idx = NONE_REF;
        self.active_branch_value = 0;
        for idx in 0..MAX_BLOCKS {
            let idx = idx as u32;
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

        if deleted_count > 0 {
            // Step 5 — FR19 event (iv). Runs *after* the marking is restored so
            // `recompute_caches` classifies every survivor against the final
            // flags rather than a transient mix.
            let deleted = &delete_set[..deleted_count];
            self.chain_heads
                .on_blocks_deleted(&mut self.blocks, deleted, parent_of_target);
        }

        // Step 5b — index self-repair (DEC-134), against the final marking,
        // so the next FR2 evaluation sees a tree it can walk.
        if repair_index {
            self.unlink_dangling_parents();
        }

        // Step 6 — revert. The caller re-evaluates FR2 (see step 6 in the doc).
        self.set_lifecycle_phase(LifecyclePhase::Collecting);
    }

    /// FR3 processing-pass forward state reconstruction (Story 5.3).
    ///
    /// Backward-marks the candidate segment from `candidate_tip_idx`, then walks
    /// it strictly forward from the anchor, deriving the complete active-chain
    /// projection into `node_info` (roster, public keys, balances, seed sources,
    /// `max_known_node_id`) and `vote_engine` (accumulated vote + creator order,
    /// FR37/FR38). `pub(crate)` and self-contained so the FR59 restart (Story 5.10)
    /// reuses the same primitive; ready state has no full-reconstruction path
    /// (DEC-159). Returns the FR21 value of the window the promotion will
    /// establish.
    ///
    /// **Derive-only** (Decision #2): it does not validate FR6 invariants, promote
    /// Stored→Active, or transition to Ready (Story 5.4), nor perform the FR5
    /// atomic recovery (Story 5.5). Reads no wall-clock (`now`-independent —
    /// FR63/NFR5); the only PRNG use is whatever `VoteEngine` performs internally
    /// (none for accumulation).
    // Its own frame: see `recover_from_failed_pass` (DEC-136).
    #[inline(never)]
    pub(crate) fn run_processing_pass(
        &mut self,
        candidate_tip_idx: u32,
    ) -> Result<u64, ProcessingError> {
        // AC5: clean working set on (re-)entry — no partial projection persists.
        self.node_info.reset();
        self.reset_vote_engine();
        // Story 6.7: the pass derives the run state forward from its anchor,
        // and judges every block's signatures itself (D2: a block trusted under
        // one anchor may be exact under this one).
        self.active_open_run = NO_OPEN_RUN;
        self.blocks.clear_signatures_accepted();

        // AC1: backward mark tip → anchor along `parent_ref`, bounded by
        // MAX_BLOCKS. `marked[0] = tip … marked[count-1] = anchor`; the forward
        // traversal iterates the buffer in reverse (anchor → tip). Termination:
        // the anchor is either genesis (block #0, `parent_ref == NONE_REF`) or a
        // retained-window tail whose `previous_hash` is unresolved locally (also
        // `parent_ref == NONE_REF`, set at admission) — both stop the walk.
        let mut marked = [NONE_REF; MAX_BLOCKS];
        let mut count = 0usize;
        let mut cur = candidate_tip_idx;
        // FR3 existence-floor source: the lowest-sequence balance block in the
        // segment. The backward walk descends tip → anchor, so the *last* balance
        // block it sees is the earliest; its `max_node_id` seeds `max_known_node_id`
        // before the forward walk (below), so a vote-target range check for a block
        // that precedes the first balance block is measured against the true window
        // node count instead of 0. The payload type is read from the cached flag
        // bits (`BlockEntry::payload_type`) — no storage read during the mark.
        let mut floor_balance_idx = NONE_REF;
        // FR8 (Story 5.9, AC3): the **first** in-scope chain-config block — the
        // lowest-sequence one, which is the last the backward walk assigns, the
        // same idiom `floor_balance_idx` uses. It is both the AC3 existence
        // witness and the content the AC4 lock and the AC6 adopt-retry take, and
        // it is read from the cached `payload_type` flag bits, so establishing it
        // costs no storage read.
        let mut first_config_idx = NONE_REF;
        loop {
            if count >= MAX_BLOCKS {
                return Err(ProcessingError::MarkOverflow);
            }
            marked[count] = cur;
            count += 1;
            let entry = self.blocks.get(cur).ok_or(ProcessingError::MissingBlock)?;
            if entry.payload_type() == PAYLOAD_TYPE_BALANCE {
                floor_balance_idx = cur;
            }
            if entry.payload_type() == PAYLOAD_TYPE_CHAIN_CONFIG {
                first_config_idx = cur;
            }
            let parent = entry.parent_ref();
            if parent == NONE_REF {
                break;
            }
            cur = parent;
        }

        // FR3 **candidate chain-config preload** — before the forward traversal,
        // not during it.
        //
        // PRD FR3 requires the candidate segment's own configuration content to be
        // the basis of every chain-config-derived check performed by the forward
        // traversal. That is not a refinement of the FR8 content comparison; it is
        // a precondition for the traversal being meaningful at all. The forward
        // walk consults the held configuration for `block_size_limit` (the FR6
        // size invariant), so running it while the node holds a *different*
        // configuration than the candidate names would judge legitimate candidate
        // blocks against a limit their chain never set — and an FR6 failure
        // deletes the block. Detecting the divergence here costs one storage read
        // and forecloses that entirely: no candidate block is ever measured
        // against a configuration the candidate does not carry.
        //
        // The remedy is the caller's: `receive_block` adopts the candidate's own
        // content and re-runs this pass (FR8's mismatch path, Story 5.9 AC6). The
        // re-run then finds the preload satisfied and proceeds. Under a durable
        // lock there is no remedy and none is wanted — the lock is irrevocable, so
        // the mismatch is the block's fault and the `Err` routes to the FR5
        // recovery, which is the same outcome the forward walk would have reached,
        // only sooner.
        //
        // Only the *first* in-scope config block is preloaded. Any further one is
        // compared during the walk, against a configuration now known to equal the
        // candidate's own — which is how a candidate carrying two differing
        // contents is caught, and why it can never be resolved by adopting.
        //
        // **Ordered after the available-UTXO baseline below, not before it.** The
        // FR5 recovery documents itself as relying on this pass having zeroed the
        // marked segment's available-UTXO bits at entry and re-zeroed them on its
        // abort path; an early return above that baseline would leave bits from an
        // earlier uncommitted pass set and quietly break that contract.
        //
        // AC5 (available-UTXO lifecycle): establish the clean all-zero baseline —
        // "nothing derived" — for the marked segment's bits at entry, matching the
        // `node_info` / `vote_engine` reset above, so the pass is idempotent on
        // re-entry and the failure rollback below restores exactly this baseline
        // (not the whole vector against an unknown prior state). For the MVP
        // join/reconstruct flow the marked blocks are freshly-admitted `Stored`
        // blocks (bits already 0); the reset makes the reusable primitive
        // self-consistent for a re-derivation over a candidate whose blocks are
        // NOT shared with an already-active chain (a fresh join, the Story-5.10
        // restart). A ready-state chain switch never re-derives: it walks the
        // shared chain in place by exact per-block inverses (Story 6.3,
        // DEC-168), and ready state has no full-reconstruction path (DEC-159).
        for slot in marked.iter().take(count) {
            self.blocks.clear_available_utxo(*slot);
        }

        // The preload and the FR8 existence check, both **before** the forward
        // traversal, in the order PRD FR3 states.
        //
        // The existence half is not merely tidier here — it is load-bearing.
        // Placed at pass end (as it was), a candidate carrying *no* chain-config
        // block skips the preload guard entirely and is then forward-walked
        // against whatever unrelated tentative the node happens to hold: a
        // legitimate block dies as `BlockTooLarge` under a limit its chain never
        // set, the failure is retryable, and the retry kills a second block
        // before the missing-config verdict is finally reached. Checking first
        // bounds that to the single head deletion FR5 intends. Since Story 5.13
        // FR2 does not select a candidate naming no configuration, so from the
        // acquisition loop this check is a guard, not a path.
        //
        // Gated on a configuration actually being held. With none, there is
        // nothing for the candidate to disagree with and nothing to commit to;
        // the pass then fails where it always did — at the first FR37 vote effect,
        // with `Vote(NotParameterized)` — which is Story 5.8's ratified "refuse,
        // do not guess" behaviour and is what `receive_block`'s FR2 gate keeps
        // production out of in the first place.
        if self.held_chain_config_content().is_some() {
            if first_config_idx == NONE_REF {
                return Err(ProcessingError::Invalid {
                    block_idx: candidate_tip_idx,
                    reason: ValidationReason::MissingChainConfigBlock,
                });
            }
            match self.candidate_chain_config_readable_match(first_config_idx) {
                ConfigPreload::Matches => {}
                // FR16: a mismatch is exact evidence; an unreadable block is not.
                // Pre-5.9 an unreadable candidate block was `StorageRead` — head
                // only, non-retryable — and converting a failed read into
                // `ChainConfigMismatch` would route the node's own I/O trouble
                // into the adopt path and, on a second failed read there, delete
                // this block *and its whole descendant subtree*.
                ConfigPreload::Differs => {
                    return Err(ProcessingError::Invalid {
                        block_idx: first_config_idx,
                        reason: ValidationReason::ChainConfigMismatch,
                    });
                }
                ConfigPreload::Unreadable => return Err(ProcessingError::StorageRead),
            }
        }

        // A genesis-anchored candidate (anchor == block #0) is re-derivable in full,
        // so it has NO pre-seed trust zone: an unseeded creator / initializer is
        // exact evidence of invalidity (FR6). A window-anchored candidate legitimately
        // trusts its pre-window history (AC4). The anchor is `marked[count - 1]`.
        let genesis_anchored = count > 0
            && self
                .blocks
                .get(marked[count - 1])
                .is_some_and(|e| e.sequence() == 0);

        // AC1: chain-config preload. The candidate's chain-config block(s)
        // (`payload_type == 3`) are inside the marked set and read during the
        // forward pass below; the byte-identical FR6 compliance verify and the
        // FR7/FR8 tentative-vs-durable commitment are Story 5.6 — the derive-only
        // 5.3 scope has no preload consumer, so no separate scan is built.

        // FR3 existence-floor seed (window-anchored only). `max_known_node_id` is
        // the node-existence bound for the vote-target range check *and* the
        // registration-monotonicity reference. On a window-anchored candidate the
        // segment's earliest balance block already carries the full node count
        // (`max_node_id`, incl. pre-window nodes) — reading that single block
        // up-front seeds the watermark so a block that *precedes* the first balance
        // block is measured against the true count, not 0. Genesis-anchored
        // candidates re-derive from block #0, so their watermark must build from 0
        // (the floor would wrongly pre-inflate it); skipped for them. One extra
        // storage read; the block is re-read (and re-validated) in the forward walk.
        // One read buffer for the floor read and the whole forward walk.
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        if !genesis_anchored
            && floor_balance_idx != NONE_REF
            && let Some(view) = self.view_retained(floor_balance_idx, &mut buf)
            && let Some(payload) = view.balances()
        {
            // DEC-228: an over-cap floor is exact evidence here, before it could
            // seed a watermark the chain forbids — and before a block that
            // precedes it is measured against one.
            if payload.max_node_id() >= self.max_node_count() {
                return Err(ProcessingError::Invalid {
                    block_idx: floor_balance_idx,
                    reason: ValidationReason::NodeCountExceeded,
                });
            }
            self.node_info.set_max_known_node_id(payload.max_node_id());
        }

        // `max_known_node_id` is an authoritative node-existence bound only once it
        // is established: from block #0 on a genesis-anchored candidate, or from the
        // floor (earliest balance block) on a window-anchored one. A window-anchored
        // segment with no balance block has no reliable bound, so referenced-node-id
        // range checks are trusted there (AC4) rather than measured against a 0
        // watermark. Drives the FR6 `check_node_id_in_range` gate below.
        let roster_bounded = genesis_anchored || floor_balance_idx != NONE_REF;

        // AC1/AC2-AC7 (Story 5.4): forward traversal anchor → tip, validating
        // each block against the FR6 invariant set at the point it becomes
        // checkable — interleaved with the FR3 derivation, so every check reads
        // the state derived from the *preceding* candidate blocks. The earliest
        // offending block aborts with `ProcessingError::Invalid { block_idx, .. }`
        // (the FR5 recovery, Story 5.5, reads `block_idx` as its deletion target).
        // Available-UTXO bits set or cleared mid-pass are rolled back below on any
        // abort (the FR5 working-set rollback's UTXO half); on success they persist
        // as the active chain's unspent-output state.
        // The earliest block `a` of a window-anchored segment and `a + H`
        // (DEC-177's seed bound, D4's unknown-run bound); 0 when complete.
        let (anchor, anchor_plus_h) = if genesis_anchored {
            (0, 0)
        } else {
            let a = self
                .blocks
                .get(marked[count - 1])
                .map_or(0, |e| e.sequence());
            (
                a,
                a.saturating_add(self.verification_horizon().unwrap_or(0)),
            )
        };
        let mut projection = Projection {
            complete: genesis_anchored,
            roster_bounded,
            saw_balance_block: false,
            vote_seed_from: anchor_plus_h,
            first_segment_registration: u32::MAX,
            run_unknown_below: anchor_plus_h,
            counter_tail: u32::MAX,
            anchor,
        };
        let mut prev_hash: Option<[u8; 32]> = None;
        // Story 6.1 D5: the FR21 value of the window the promotion will
        // establish, summed from the blocks this walk reads anyway — no read
        // and no failure mode of its own at Ready entry.
        let window_tail = self.window_tail_sequence(
            self.blocks
                .get(marked[count - 1])
                .map_or(0, |e| e.sequence()),
            self.blocks.get(marked[0]).map_or(0, |e| e.sequence()),
        );
        let mut window_value = 0u64;
        // FR48 in the pass (Story 6.14 AC9, DEC-204): the block at `marked[i]`
        // drops `marked[i + W]` — the block `W` sequences below it — whenever
        // that block lies in the segment: every block at `s ≥ W` of a
        // genesis-anchored segment, every block at `s ≥ a + W` of a
        // window-anchored one. Earlier blocks of a window-anchored segment
        // drop a block below it: pre-window trust. `W` is the candidate's own
        // (the preload made it the held configuration).
        let w = self.active_chain_length().map(|w| w as usize);
        let mut result = Ok(());
        for i in (0..count).rev() {
            let idx = marked[i];
            // The exact stored length, so the byte-exact FR6 checks
            // (block-creator signature, chain-config content-identity, hash
            // linkage) see the bytes originally signed (Story 5.4).
            let Some(view) = self.view_retained(idx, &mut buf) else {
                result = Err(ProcessingError::StorageRead);
                break;
            };
            // Before the step: it clears the bits this block spends from the
            // dropped block, and its commit moves seed pointers — the
            // classification must see the pre-state a head extension sees.
            if let Some(dropped) = w
                .and_then(|w| i.checked_add(w))
                .filter(|&d| d < count)
                .and_then(|d| marked.get(d))
            {
                match classify_tail_drop(&self.blocks, &self.node_info, *dropped) {
                    // An empty slot is the node's own inconsistency: local.
                    Err(_) => {
                        result = Err(ProcessingError::MissingBlock);
                        break;
                    }
                    Ok(obligation) => {
                        if tail_drop_binding(obligation, &view) == TailBinding::Invalid {
                            result = Err(ProcessingError::Invalid {
                                block_idx: idx,
                                reason: ValidationReason::TailDropUnpreserved,
                            });
                            break;
                        }
                    }
                }
            }
            let this_hash = view.hash();
            let step = self
                .derive_block(&view, idx, prev_hash, &mut projection)
                .and_then(|derivation| {
                    self.judge_evidence_step(&view, idx, &projection)
                        .map(|()| derivation)
                })
                .and_then(|derivation| self.commit_block(&view, idx, derivation));
            if let Err(e) = step {
                result = Err(e);
                break;
            }
            if view.sequence() > window_tail {
                window_value += block_value::<MAX_NODES>(&view);
            }
            prev_hash = Some(this_hash);
        }

        if result.is_err() {
            for slot in marked.iter().take(count) {
                self.blocks.clear_available_utxo(*slot);
            }
        }
        result.map(|()| window_value)
    }

    /// Whether a non-complete FR3 pass may judge `node`'s accumulated vote
    /// (DEC-177, Story 6.14 AC8): always in a complete projection; for a node
    /// registered inside the segment (vote 0 is exact); otherwise once its
    /// seed source lies at or after `a + H`. Before that, every check that
    /// depends on the node's vote is auto-accepted, as in its pre-seed zone;
    /// its balance and key are seeded as before. Pass-local, no stored state.
    pub(super) fn vote_seeded(&self, node: u32, projection: &Projection) -> bool {
        projection.complete
            || node >= projection.first_segment_registration
            || self
                .node_info
                .seed_source_of(node)
                .and_then(|slot| self.blocks.get(slot))
                .is_some_and(|source| source.sequence() >= projection.vote_seed_from)
    }

    /// Story 6.7 D5 — [`Self::vote_seeded`] at `p − 1` in a window-anchored
    /// pass standing at a later tip: a node whose latest seed source lies at
    /// or above `p` had an earlier one at `p − 1`, which the pass no longer
    /// knows, so its vote there is not known to be exact.
    pub(super) fn vote_seeded_below(&self, node: u32, p: u32, projection: &Projection) -> bool {
        projection.complete
            || node >= projection.first_segment_registration
            || self
                .node_info
                .seed_source_of(node)
                .and_then(|slot| self.blocks.get(slot))
                .is_some_and(|source| (projection.vote_seed_from..p).contains(&source.sequence()))
    }
}
