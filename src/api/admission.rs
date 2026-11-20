//! FR9 Tier 1 admission and `receive_block`, the block-intake entry point
//! (Stories 4.2, 4.4).

use super::*;

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
    /// FR9 Tier 1 admission (Story 4.2). Runs the full Tier 1 gating check set
    /// over `block`; on pass, persists the block through the storage seam and
    /// inserts it into the block-tree at [`BlockStatus::Stored`], returning its
    /// storage/tree index. On any exact-evidence failure the block is neither
    /// persisted nor inserted, and the failing [`Tier1Failure`] is returned.
    ///
    /// This is the internal entry point Story 4.3's `receive_block` intake
    /// surface calls; it deliberately stops at "Tier 1 verdict + Stored
    /// admission." The single-outcome `ReceiveBlockOutcome` mapping, the
    /// collecting-vs-ready FR60 window logic, the FR11 duplicate-classification
    /// *outcome*, and the FR17 chain-config silent-discard are Story 4.3.
    ///
    /// **The caller owns FR11 de-duplication.** `classify_block` runs the
    /// authoritative `(sequence, hash)` check and classifies a known block as
    /// `DuplicateKnown` *before* calling `tier1_admit`, so admission never sees
    /// a duplicate and never re-hashes or re-scans the tree for one — the
    /// dominant mesh-rebroadcast re-arrival is filtered off the crypto path by
    /// the dispatcher, not by a second guard here (no redundant self-defense;
    /// no signature-verification cache needed). `hash` is the already-computed
    /// `block.hash()`, threaded in so it is computed exactly once per receive.
    ///
    /// **Collecting-state invariant (AC4):** every admitted block is `Stored`
    /// — no Connected/Active is assigned, because no active chain exists and no
    /// promotion driver runs in Epic 4.
    ///
    /// **Storage-first ordering:** the block is saved to durable storage at the
    /// slot [`BlockTable::next_free_index`] returns *before* the tree is
    /// mutated, so a storage failure leaves the tree untouched (there is no
    /// deletion path to roll back a tree insert until Story 4.4). The entry is
    /// then written at that same slot via [`BlockTable::insert_at`] — no
    /// second free-slot scan.
    ///
    /// **Parent linkage + FR19 chain_heads (Story 4.4):** the block's parent is
    /// resolved via `blocks.find_parent(previous_hash, sequence)` (the parent's
    /// sequence is `sequence − 1`, so no find-by-hash-alone is needed) and the
    /// entry is inserted with that `parent_ref` (or `NONE_REF` when unresolved).
    /// After insertion the chain_heads mutation events (i) new-block admission
    /// and (ii) tail-pointing parent admission run, tracking the tip and
    /// scheduling parent-recovery for a missing ancestor. `now` stamps the head
    /// arrival timestamp (FR18) and drives the bootstrap `last_request_timestamp`.
    pub(crate) fn tier1_admit(
        &mut self,
        block: &BlockView,
        hash: &[u8; 32],
        now: u64,
    ) -> Result<u32, AdmitError> {
        // Single-genesis guard (Story 5.1, deferred from the Story-4.4 review).
        // There is structurally exactly one genesis anchor. A distinct `sequence
        // == 0` block (FR11 dedup already filtered an identical one upstream) that
        // arrives once the active chain is anchored is rejected as exact evidence
        // (FR16) — BEFORE any storage write — rather than admitted. Admitting it
        // would either reseat the anchor (the Story-4.4 defect this guard closes)
        // or, as a `parent.is_none()` orphan, create a `sequence == 0` Stored head
        // that emits a perpetual bogus parent-recovery request for a nonexistent
        // seq-0 parent (violating the `chain_heads` "tail-point never has sequence
        // 0" invariant). It needs no Tier 1 verdict, so it runs first: a block #0
        // arriving once an anchor is held costs no verification at all (DEC-270),
        // not even the proof of possession its registration carries.
        let is_block_zero = block.sequence() == 0;
        if is_block_zero && self.active_chain_head_idx != NONE_REF {
            return Err(AdmitError::Rejected(Tier1Failure::DuplicateGenesis));
        }

        // FR9: enforceable, not merely declared — a tentative must not reject.
        let block_size_limit = self.enforceable_block_size_limit();
        tier1_gate(
            block,
            &self.node_zero_public_key,
            block_size_limit,
            self.enforceable_max_utxo_outputs(),
            &self.crypto,
        )
        .map_err(AdmitError::Rejected)?;

        // DEC-270 (Story 6.10): the first block #0 — `tier1_gate` has pinned its
        // FR54 shape, so its creator is node #0 — must carry the trust anchor's
        // signature before it takes the single anchor slot, in every phase; a
        // forged one would otherwise lock the real genesis out with
        // `DuplicateGenesis` until the FR3 pass condemned it. A pass is marked
        // below, so the per-block step does not verify it again (DEC-157).
        if is_block_zero && self.verify_block_creator_signature(block) != Some(true) {
            return Err(AdmitError::Rejected(Tier1Failure::CreatorSignatureInvalid));
        }

        // FR19 parent resolution (Story 4.4), a pure RAM lookup. Resolved here,
        // ahead of the signature check that needs it (Story 6.4 D3).
        // `previous_hash()` is a 32-byte slice; convert to the array key.
        // Genesis (`sequence == 0`) has no parent.
        let prev_hash: [u8; 32] = block.previous_hash().try_into().unwrap_or([0; 32]);
        let parent = self.blocks.find_parent(&prev_hash, block.sequence());

        // FR9 Tier 1 case (2) (Story 6.2 D6, DEC-157): in Ready, the creator
        // signature is exact evidence, before anything is written, whenever the
        // creator's key is the same on every branch that can connect. A pass
        // marks the entry, so the per-block step never verifies it again.
        //
        // Story 6.4 D3: a block whose parent is a flagged active-chain block has
        // the active chain up to its parent as its own ancestry, so a key seeded
        // at or below the parent is this block's own branch key. The bound is
        // then the parent's sequence instead of the tail's — never below it
        // (`p − 1 ≥ S_head − H ≥ S_tail` for anything intake admits), so it
        // only ever verifies more. FR12 needs it: a deviating sibling must be
        // signature-verified to be endorsed, and a bad signature is exact
        // evidence here, before the write.
        let signature_verified = is_block_zero
            || (self.lifecycle_phase == LifecyclePhase::Ready
                && self
                    .blocks
                    .get(self.snake_chain_tail_idx)
                    .is_some_and(|tail| {
                        let parent_on_chain = parent
                            .and_then(|p| self.blocks.get(p))
                            .filter(|entry| entry.is_on_active_chain())
                            .map(|entry| entry.sequence());
                        let bound =
                            parent_on_chain.map_or(tail.sequence(), |seq| seq.max(tail.sequence()));
                        self.key_is_branch_independent(block.creator(), bound)
                    })
                && match self.verify_block_creator_signature(block) {
                    Some(false) => {
                        return Err(AdmitError::Rejected(Tier1Failure::CreatorSignatureInvalid));
                    }
                    Some(true) => true,
                    // No key verdict: nothing is judged or marked here.
                    None => false,
                });

        // Story 6.7 AC4 (D4): a block whose parent is held is judged against
        // the FR27 run rules now, before the write — they read only the block
        // and its ancestry. In Ready the direct extension's step and a side
        // block's Tier 2 check (a Connected or Active parent) judge them later
        // in this call; every other held parent (a Stored one in Ready, any
        // outside Ready) is judged here by the header walk. Rules 4 and 5 read
        // the configuration, so they wait for the lock (a tentative one may not
        // be the chain's; the FR3 pass judges them).
        let judged_later = self.lifecycle_phase == LifecyclePhase::Ready
            && parent.is_some_and(|q| {
                q == self.active_chain_head_idx
                    || self
                        .blocks
                        .get(q)
                        .is_some_and(|entry| entry.status() != BlockStatus::Stored)
            });
        if !judged_later && let Some(q) = parent {
            let h = if self.chain_config.is_durable_locked() {
                self.verification_horizon()
            } else {
                None
            };
            // An unreadable ancestry leaves rules 1–4 to a later judgement;
            // the slot rule reads the block alone.
            let verdict = match self.deviation_run_at(q) {
                Ok(run) => run_rules(block, run, h),
                Err(()) => slot_rule(block, h),
            };
            if verdict.is_err() {
                return Err(AdmitError::Rejected(Tier1Failure::DeviationRun));
            }
        }

        // Peek the slot; the entry and the durable write both land there
        // (`persist` reconstructs the owned `Block` the storage seam takes).
        let idx = self.blocks.next_free_index().ok_or(AdmitError::TableFull)?;

        // FR8 tentative load (Story 5.9, AC2). The **first** chain-config block
        // whose FR7 content-signature verified — `tier1_gate` above owns that,
        // so passing it is a precondition here — and whose content the
        // configuration module accepts is loaded tentatively, and is then
        // retained like any other admitted block.
        //
        // **Only the first, and only when nothing is held.** `active_configuration()`
        // answers `Some` for a tentative *and* for a durable configuration, which
        // is exactly the guard FR8 asks for in both directions: a later config
        // block arriving while Collecting "shall be stored in the block-tree
        // subject to FR16 and shall not override the tentative configuration",
        // and a config block arriving after the lock is either a faithful replay
        // (admitted, nothing to load) or a mismatch the FR17 gate already
        // discarded before this function ran.
        //
        // **Placement — after every other fallible pre-storage step, before the
        // durable write.** FR8 requires that a refused content leaves the block
        // out of durable storage *and* no configuration loaded. `load_tentative`
        // gives the second half for free: the module runs its whole acceptance
        // pass before it retains anything, so a refusal leaves its state exactly
        // as it was (Story 5.7). The first half is this ordering — nothing is
        // written yet, so the `?` below is a complete rollback. Sitting *after*
        // the slot peek and the `Block` reconstruction means the only fallible
        // step left is the durable write itself, which is the single place that
        // has to undo the load.
        //
        // Ordering is load-then-check (FR56): only the configuration module
        // parses content, so the three structural bounds cannot be evaluated
        // before the load. This surfaces the module's refusal as exact evidence
        // of invalidity (FR16) — never as a silent discard, which would make a
        // node with a smaller build look like a node seeing a bad chain.
        let is_chain_config = block.payload_type() == PAYLOAD_TYPE_CHAIN_CONFIG;
        let loads_tentative = is_chain_config && self.chain_config.active_configuration().is_none();
        if loads_tentative {
            self.chain_config
                .load_tentative(block.payload())
                .map_err(|_| AdmitError::Rejected(Tier1Failure::ChainConfigContentRejected))?;
        } else if is_chain_config {
            // PRD FR8 states of each structural bound that a violating chain-config
            // "is exact evidence of invalidity per FR16 and **shall not enter
            // durable storage**" — unconditionally, not only for the block that
            // happens to load. Evaluating only the loading block would let a
            // structurally illegal configuration occupy a slot in a bounded table,
            // and would make whether a block is stored depend on arrival order
            // (AC9).
            //
            // `accept_content` is the configuration module's own acceptance pass,
            // exported as a pure function, so FR56 still holds: the blockchain does
            // not parse configuration content, it asks the module. Nothing is
            // loaded here — a configuration is already held and FR8 forbids
            // overriding it; this only decides whether the block is worth keeping.
            moonblokz_configuration::accept_content(block.payload(), Self::BUILD_LIMITS)
                .map_err(|_| AdmitError::Rejected(Tier1Failure::ChainConfigContentRejected))?;
        }

        // FR19 bootstrap (AC7): a genesis block (sequence 0, no parent) anchors
        // the active chain — mark it on-chain and record it as the active head so
        // event (i) classifies its head Connected. The single-genesis guard above
        // already rejected any seq-0 block once an anchor exists, so this only ever
        // fires for the *first* genesis (`active_chain_head_idx == NONE_REF`).
        let is_genesis = block.sequence() == 0 && parent.is_none();

        let mut entry = BlockEntry::new(*hash, parent.unwrap_or(NONE_REF), block.sequence());
        entry.set_status(BlockStatus::Stored);
        entry.set_len(block.len() as u32); // exact length for the FR6 byte-exact checks (Story 5.4)
        entry.set_payload_type(block.payload_type()); // cached in flags for the FR3 floor scan (Story 5.4 review)
        if signature_verified {
            entry.set_signature_verified();
        }
        if is_genesis {
            entry.set_on_active_chain(true);
        }
        // The entry takes its slot before the durable write and leaves it again
        // on any refusal below, so a refused block leaves the tree as it was.
        // The per-block step needs it there: the UTXO resolver walks from it
        // and the commit tail sets its bits.
        self.blocks.insert_at(idx, entry);

        // Story 6.0 AC3 (D2): in Ready, a direct extension of the active head
        // is judged now, against the head's derived state — its verdict is
        // final, so a failing one is never stored.
        let mut extension = None;
        if self.lifecycle_phase == LifecyclePhase::Ready
            && self.active_chain_head_idx != NONE_REF
            && parent == Some(self.active_chain_head_idx)
        {
            match self.judge_head_extension(block, idx, self.snake_chain_tail_idx) {
                Extension::Valid {
                    advance,
                    derivation,
                } => extension = Some((advance, derivation)),
                Extension::Invalid => {
                    self.blocks.delete(idx);
                    return Err(AdmitError::InvalidExtension);
                }
                // No evidence (FR16): the block is admitted as Stored and the
                // continuation retries it at a later admission.
                Extension::Local => {}
            }
        }

        // Story 6.1 D4: in Ready, a block whose parent is Connected or Active
        // but not the head already reaches the active chain, so its Tier 2
        // verdict is final now — check first, then write (DEC-019). Only Tier
        // 2: its Tier 3 is the chain switch's (6.3).
        let mut side_judged = false;
        if let Some(p) = parent
            && self.lifecycle_phase == LifecyclePhase::Ready
            && p != self.active_chain_head_idx
            && self
                .blocks
                .get(p)
                .is_some_and(|entry| entry.status() != BlockStatus::Stored)
        {
            match self.tier2_check(block, idx, p) {
                Ok(()) => side_judged = true,
                Err(err) if is_evidence(&err) => {
                    self.blocks.delete(idx);
                    return Err(AdmitError::InvalidExtension);
                }
                // No evidence (FR16): stored as Stored; the side-branch
                // driver judges it again.
                Err(_) => {}
            }
        }

        if self.persist(idx, block).is_err() {
            // The durable write is the one step after the load that can still
            // fail. Undo the load rather than keep a configuration whose block
            // was never persisted: on the next boot the block is not there, so a
            // node that kept it would be deriving from a configuration it can no
            // longer justify (and FR49 replay could not reproduce).
            if loads_tentative {
                self.chain_config.discard_tentative();
            }
            // A judged extension is not blamed: its effects are inverted (D1).
            if extension.is_some() {
                self.invert_transactions(block, idx, usize::MAX);
            }
            self.blocks.delete(idx);
            return Err(AdmitError::StorageSaveFailed);
        }

        // The vote apply and the commit tail of a judged extension, before
        // `chain_heads` learns of the block (DEC-138). The vote apply is the
        // step's last fallible operation; it refuses atomically and inverts
        // the step. Without parameters that is the node's own fault and the
        // block stays Stored. An arithmetic refusal is evidence: the block
        // leaves again before anything links to it — no child was resolved
        // onto it and no head evicted for it — so the tree is as it was; only
        // its bytes stay in the freed slot until reuse, as for every deletion.
        let mut promote = None;
        if let Some((advance, derivation)) = extension {
            match self.commit_block(block, idx, derivation) {
                Ok(()) => promote = Some(advance),
                Err(err) if is_evidence(&err) => {
                    self.blocks.delete(idx);
                    return Err(AdmitError::InvalidExtension);
                }
                Err(_) => {}
            }
        }

        if is_genesis {
            self.active_chain_head_idx = idx;
            // A Collecting anchor, not a Ready head: no window yet (FR48).
            self.snake_chain_tail_idx = NONE_REF;
        }
        // FR8 provenance (AC8): record which retained block supplied the
        // tentative content, now that it has a slot. Written only on the path
        // that actually loaded, so it always names a live block.
        if loads_tentative {
            self.tentative_config_block_idx = idx;
        }

        // A Connected parent that is a head is extended (FR21 (i)): its value
        // is read before event (i) moves its entry onto this block.
        let parent_value = match parent {
            Some(p)
                if side_judged
                    && self
                        .blocks
                        .get(p)
                        .is_some_and(|entry| entry.status() == BlockStatus::Connected) =>
            {
                self.chain_heads.branch_value_of(p)
            }
            _ => None,
        };

        // FR19 chain_heads mutation events (i) + (ii).
        let active_head = self.active_chain_head_idx;
        self.chain_heads.on_block_admitted(
            &mut self.blocks,
            idx,
            parent,
            prev_hash,
            now,
            active_head,
        );

        if let Some(advance) = promote {
            self.promote_head_extension(
                idx,
                block_value::<MAX_NODES>(block),
                block.creator(),
                advance,
            );
        }
        if side_judged && let Some(p) = parent {
            self.connect_judged_side_block(idx, p, block_value::<MAX_NODES>(block), parent_value);
        }
        Ok(idx)
    }

    /// Saves `block` at `idx` through the storage seam, which takes an owned
    /// [`Block`]. The copy lives only in this frame, never alongside the
    /// per-block step (stack budget, DEC-136). A view that does not convert
    /// cannot occur — it parsed at intake — and is reported as a failed save.
    #[inline(never)]
    fn persist(&mut self, idx: u32, block: &BlockView) -> Result<(), ()> {
        let owned = Block::from_bytes(block.serialized_bytes()).map_err(|_| ())?;
        self.storage.save_block(idx, &owned).map_err(|_| ())
    }

    /// FR10 block-intake surface (Story 4.3). Classifies a submitted block into
    /// exactly one [`ReceiveBlockOutcome`] (single-outcome scheduling-pull, AR4)
    /// and pairs it with a [`NextCall`]. Classification is deterministic in the
    /// block bytes + current authoritative state and independent of transport
    /// origin (there is no origin parameter). Delegates to the stateless
    /// [`crate::intake::classify_block`] dispatcher (FR11 dedup → FR60 window →
    /// FR17 chain-config → Story 4.2 Tier 1).
    ///
    /// After admission (Story 4.4), returns `NextCall::At(exact next-eligible
    /// instant)` when the tree holds ≥1 Stored head — so the bridge calls
    /// [`Self::on_tick`] exactly when the FR19 parent-recovery scheduler can emit
    /// — else `NextCall::Idle`. The request itself is emitted from the tick
    /// (never inline here), gated by the FR46 global cooldown; see [`TickOutcome`].
    ///
    /// **A block above this build's capacity never arrives here** (DEC-225). The
    /// caller frames it with `BlockView::from_bytes`, which refuses anything
    /// larger than `MAX_BLOCK_SIZE` (`InputTooLarge`): a local refusal, never
    /// evidence. And a build never locks a chain whose `block_size_limit`
    /// exceeds that capacity (configuration §6 check 5), so a locked node only
    /// ever judges sizes it can hold; `Tier1Failure::BlockTooLarge` measures the
    /// chain's limit, the same on every build.
    pub fn receive_block(
        &mut self,
        block: BlockView<'_>,
        now: u64,
    ) -> CallResult<ReceiveBlockOutcome> {
        // FR60 window if Ready+available (Epic 9); any `Err` → no window → FR60 skipped.
        // A refused restart leaves an empty tree over a populated durable store,
        // so `next_free_index()` would hand out slot 0 and `save_block` would
        // overwrite a durable block: the node would silently start destroying
        // the chain it failed to load. Refuse operationally. `Unstorable`
        // already means "the block may be perfectly valid but could not be
        // stored", which is exactly the situation.
        //
        // Deliberately **not** `NotReady`: that is the FR1 phase gate, which is
        // transient and self-healing, while this is terminal and needs an
        // operator. `ReceiveBlockOutcome` has no such arm in any case, because
        // FR1 keeps block intake active while Collecting.
        if self.restart_refused {
            return (
                ReceiveBlockOutcome::Rejected(RejectReason::Unstorable),
                NextCall::Idle,
            );
        }

        let window = self.active_snake_chain_window().ok();
        // Read before the Collecting branch below, which can reach Ready
        // inside this same call (AC4).
        let was_ready = self.lifecycle_phase == LifecyclePhase::Ready;
        let (mut outcome, admitted) = classify_block(self, &block, window, now);
        // Story 6.4 AC3: the admitted block's key, so the support evaluation at
        // the end re-finds it — the drive or a switch may have deleted it.
        let admitted_key = admitted
            .and_then(|idx| self.blocks.get(idx))
            .map(|entry| (entry.sequence(), *entry.hash()));
        // FR2 dominant-chain acquisition (Story 5.2): a successful collecting-phase
        // admission may complete a candidate segment. Evaluate the stopping
        // condition and, on success, transition Collecting→Processing. Runs only
        // after a real admission (not on duplicate/reject) and only while
        // Collecting (Processing/Ready never re-trigger). `classify_block`
        // reports every admission as `AcceptedSilently`, and the gates below
        // test exactly that. An `AcceptedAndSend*` variant replaces it only in
        // the return value, after the last gate (Story 6.4: support is decided
        // once, at the end), so no admission misses a gate; a later variant
        // must keep that rule.
        //
        // The configuration is part of the gate (Story 5.8): the FR3 derivation
        // reads the FR37 vote parameters, so without a loaded configuration the
        // pass would run on `vote_parameters`' inert baseline and produce a
        // projection the node would then go `Ready` on. Specification §5.2: the
        // block is simply not advanced past the last stage that needs no
        // configuration-derived parameter — it stays admitted, the node stays
        // `Collecting`, and the next admission after a configuration loads
        // re-evaluates FR2 over the same tree. Gated here rather than inside
        // `run_processing_pass`, because a refusal there is a `ProcessingError`
        // and would trigger the FR5 recovery's block deletion — punishing a block
        // for the node's own missing configuration.
        if outcome == ReceiveBlockOutcome::AcceptedSilently
            && self.lifecycle_phase == LifecyclePhase::Collecting
            && self.chain_config.active_configuration().is_some()
        {
            self.drive_dominant_chain_acquisition();
        }
        if outcome == ReceiveBlockOutcome::AcceptedSilently && was_ready && !self.reentry_due {
            self.drive_forward_extension();
        }
        // Story 6.1 AC6: after the continuation, whose promotion turns a
        // sibling into a side block, and at the end of a Ready entry, after
        // the FR8 lock-time cleanups (a cleanup retarget onto a Connected block
        // must not keep a value the driver computed before it).
        let mut driver_best = None;
        if outcome == ReceiveBlockOutcome::AcceptedSilently && self.is_ready() && !self.reentry_due
        {
            driver_best = self.connect_side_branches();
        }
        // Story 6.2 D1 (DEC-152): FR22 — one comparison at the end of the
        // admission, after the continuation and the driver, between the active
        // branch and the higher-ranked admissible of the block judged at intake
        // and the driver's best. Never inside the loops: a switch (6.3) rewrites
        // `chain_heads` and the active chain under them.
        if outcome == ReceiveBlockOutcome::AcceptedSilently && self.is_ready() && !self.reentry_due
        {
            self.compare_and_switch([admitted, driver_best], now);
        }
        // Story 6.7 AC8: an evidence check whose vote projection could not
        // restore the engine (a transient read fault) left it unusable; the
        // re-entry runs here, at the root, after the step and any switch.
        if self.reentry_due {
            self.reentry_due = false;
            self.reenter_after_failed_restore(now);
        }
        // Story 6.4 (FR12, D3): support is decided once, here, on the state
        // the node now holds, and replaces `AcceptedSilently` only in the
        // return value.
        if outcome == ReceiveBlockOutcome::AcceptedSilently
            && self.is_ready()
            && let Some((sequence, hash)) = admitted_key
            && let Some(x_idx) = self.blocks.find(sequence, &hash)
            && let Some(message) =
                self.evaluate_support(x_idx, block.creator(), block.first_voted_node())
        {
            outcome = ReceiveBlockOutcome::AcceptedAndSendSupport(message);
        }
        (outcome, self.next_parent_recovery_call())
    }
}
