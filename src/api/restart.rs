//! FR59 restart: the block tree rebuilt from durable storage (Story 5.10).

use super::*;

/// What an FR59 rebuild sweep found: how many blocks entered the tree, and how
/// many slots held something that could not be turned into one. `unusable` is
/// what separates a damaged store from an empty one.
pub(super) struct RebuildStats {
    admitted: usize,
    unusable: usize,
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
    /// Join/restart init follow-up (FR1/FR59): the storage-reading counterpart
    /// to the [`Self::init`] constructor. Construction writes the fields in
    /// place and lands the node in `Collecting`; this method then reads durable
    /// storage — the deliberate construction/follow-up split (architecture §3.6
    /// "in-place constructor + role-specific follow-up"), so the raw-pointer
    /// memory init stays isolated from the storage-reading business logic.
    ///
    /// **Empty storage** is the fresh-join path: the node stays `Collecting` and
    /// returns `StartedCollecting` (FR1).
    ///
    /// **Durable blocks present** is the FR59 restart. The minimal durable
    /// footprint is the node id, the private key (held by the `Crypto` handle,
    /// never by this module), the chain-config block, and the retained blocks —
    /// no lifecycle marker, no derived projection, no `snake_chain` buffer. The
    /// rebuild therefore:
    ///
    /// 1. reads the control plane **once** and re-establishes the FR8/FR54
    ///    durable lock from it, *before* anything can consult a configuration;
    /// 2. rebuilds the block-tree from the retained slots, then their parent
    ///    linkage, then `chain_heads`;
    /// 3. drives the **same** FR2/FR3/FR6 acquisition spine a fresh join drives
    ///    ([`Self::drive_dominant_chain_acquisition`]), reaching `Ready` or
    ///    staying `Collecting`.
    ///
    /// The phase is `Collecting` unconditionally on entry and is never restored
    /// from storage — FR59 persists no lifecycle marker, and any in-flight
    /// processing state from the previous session is discarded. The pass is
    /// **not resumable**: nothing partial was ever written, so an interrupted
    /// restart simply re-runs from the same footprint.
    ///
    /// **Intake is suspended for the whole rebuild flow** (FR59). The module's
    /// synchronous single-threaded execution model enforces this structurally —
    /// no call can interleave with this one — but it is stated here as a
    /// contract so the radio and local-interface callers may rely on it
    /// independently of any future scheduling reorganization. Ordinary intake
    /// resumes when this method returns.
    ///
    /// The mempool is not durable (FR30) and is not reconstructed; it is empty.
    ///
    /// **Two things do not survive, by construction.** A head's FR18
    /// `arrival_timestamp` is not persisted, so every rebuilt head takes `now`;
    /// and `last_request_timestamp` restarts at zero, which the FR19 scheduler
    /// reads as "never requested". A restarted node's parent-recovery schedule
    /// therefore **restarts rather than resumes** — callers relying on recovery
    /// pacing across a reboot should expect one immediate round.
    ///
    /// Carries a `NextCall` per AR4 (a state-changing init step).
    pub fn initialize_from_storage(&mut self, now: u64) -> CallResult<InitOutcome> {
        // Step 0 — this is a one-shot boot step (AR6 / architecture §3.6). A
        // second call would rebuild over live state: `insert_at` would overwrite
        // occupied entries and `rebuild_from_blocks` would interleave duplicate
        // head entries, both guarded only by `debug_assert!`s that compile out
        // in exactly the release builds that run on the device. Refused at
        // runtime instead.
        if self.blocks.len() != 0 || !matches!(self.lifecycle_phase, LifecyclePhase::Collecting) {
            return (
                InitOutcome::Rejected(RestartRejectReason::AlreadyInitialized),
                NextCall::Idle,
            );
        }

        // Step 1 — the durable footprint, read exactly once.
        //
        // A store whose control plane was never initialized is indistinguishable
        // from a fresh node, so it is only an error when blocks are actually
        // present: then the node would be rebuilding a chain without knowing the
        // configuration those blocks were accepted under.
        let control = match self.storage.load_control_data() {
            Ok(control) => control,
            Err(_) => {
                return if !self.durable_blocks_present() {
                    (InitOutcome::StartedCollecting, NextCall::Idle)
                } else {
                    self.restart_refused = true;
                    (
                        InitOutcome::Rejected(RestartRejectReason::ControlPlaneUnreadable),
                        NextCall::Idle,
                    )
                };
            }
        };

        // Step 2 — re-establish the FR8/FR54 durable lock before the scan.
        //
        // `chain_configuration.is_some()` is the **only** durable evidence of the
        // lock: no boolean is persisted. Ordering matters three ways, all
        // pointing here: the FR19/FR46 cadence is `None` while unconfigured (so
        // the returned `NextCall` would be `Idle`), `enforceable_block_size_limit`
        // answers the structural ceiling until a lock exists, and the FR2 gate
        // below refuses to run the derivation unconfigured.
        let mut restored_durable_config = false;
        if let Some(config_block) = control.chain_configuration.as_ref() {
            let bytes = config_block.serialized_bytes();
            // The control plane stores the block zero-padded to the slot width
            // and records no length, exactly like a block slot, so the payload
            // has to come from the recovered exact length — never from
            // `serialized_bytes().len()`.
            let Some(view) = Self::exact_view(bytes) else {
                self.restart_refused = true;
                return (
                    InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable),
                    NextCall::Idle,
                );
            };
            // FR7 before an irrevocable commitment (review decision, 2026-09-21).
            // `load_durable` runs the module's structural acceptance and no
            // signature check, so without this the node would take a permanent
            // FR8/FR54 lock on the control plane's word alone — while the
            // *revocable* tentative path below verifies. The control plane's
            // CRC32 is bit-rot detection, explicitly not tamper resistance, and
            // `node_zero_public_key` is a construction parameter precisely so a
            // corrupted store cannot supply its own trust anchor.
            if tier1_chain_config_block(&view, &self.node_zero_public_key, &self.crypto).is_err() {
                self.restart_refused = true;
                return (
                    InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable),
                    NextCall::Idle,
                );
            }
            let payload = view.payload();
            if self.chain_config.load_durable(payload).is_err() {
                self.restart_refused = true;
                return (
                    InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable),
                    NextCall::Idle,
                );
            }
            self.reset_vote_engine();
            restored_durable_config = true;
        }

        // Step 3 — rebuild the tree, its linkage and its heads.
        let RebuildStats { admitted, unusable } = self.rebuild_block_tree_from_storage(now);
        if admitted == 0 {
            let outcome = if unusable != 0 {
                // Slots were present and not one of them could be rebuilt. This
                // is a damaged store, not an empty one; answering
                // `StartedCollecting` here would discard the node's whole chain
                // and present it as fresh.
                self.restart_refused = true;
                InitOutcome::Rejected(RestartRejectReason::NoUsableTree)
            } else if restored_durable_config {
                // No blocks, but a configuration *was* restored from the control
                // plane: something was resumed, and the node is not the pure
                // receiver `StartedCollecting` promises — it will refuse any
                // chain-config that disagrees with the lock it now holds. Keyed
                // on the restore actually having happened, not on
                // `is_durable_locked()`, which is also true for a node
                // constructed already-locked and never restarted.
                InitOutcome::ResumedCollecting
            } else {
                InitOutcome::StartedCollecting
            };
            return (outcome, self.next_parent_recovery_call());
        }

        // Step 4 — FR8 tentative re-establishment.
        //
        // A node that shut down before the durable lock held its configuration
        // only tentatively, and the tentative is not persisted. Nothing in the
        // rebuild path re-loads it, because the rebuild deliberately does not go
        // through `tier1_admit`. Without this the restarted node would hold no
        // configuration at all, the FR2 gate would refuse, and it could not
        // converge until some *new* chain-config block happened to arrive —
        // while a fresh node fed the same blocks would adopt one immediately.
        // That gap would break the FR59 equivalence the whole story is about.
        if self.chain_config.active_configuration().is_none() {
            self.reestablish_tentative_chain_config();
        }

        // Step 5 — the identical acquisition spine a fresh join runs.
        if self.chain_config.active_configuration().is_some() {
            self.drive_dominant_chain_acquisition();
        }

        // Step 6 — the FR8 lock-time cleanups, for a lock that was *restored*
        // rather than newly taken (review decision, 2026-09-21).
        //
        // Both cleanups sit behind `if !is_durable_locked()` in the spine, so a
        // restart that restored the lock in step 2 never reaches them — and the
        // FR17 intake gate that would otherwise catch a post-lock mismatching
        // config block is bypassed too, because the rebuild does not go through
        // `tier1_admit`. Without this, AC9's convergence argument is only half
        // true: a mismatching config block or an FR9-oversized block that is
        // *off* the candidate chain is never re-condemned and occupies a slot in
        // the bounded table forever. On the candidate chain the FR3/FR6 pass plus
        // FR5 recovery already handle it.
        if self.chain_config.is_durable_locked() {
            self.delete_mismatching_chain_config_blocks();
            self.reevaluate_retained_blocks_against_lock();
        }
        // Story 6.1 AC3: side branches get their Tier 2 and their values after
        // the cleanups, so no retarget lands on a value computed before them.
        // Every head valued here went Stored → Connected, an FR22 trigger
        // (Story 6.2 D1): one comparison follows.
        if self.is_ready() {
            let driver_best = self.connect_side_branches();
            self.compare_and_switch([None, driver_best], now);
        }

        let outcome = if self.is_ready() {
            InitOutcome::ResumedReady
        } else {
            InitOutcome::ResumedCollecting
        };
        (outcome, self.next_parent_recovery_call())
    }

    /// Parses `bytes` and trims it to the block's own structurally recovered
    /// length, so hashing and signature verification see the bytes that were
    /// originally signed.
    ///
    /// Durable backends return blocks zero-padded to a fixed slot and record no
    /// length, and `BlockView::len()` reports the slice it was handed — so a
    /// view over the raw slot hashes the padding too. Every restart path goes
    /// through here; `moonblokz_chain_types::BlockView::content_length` explains
    /// why the recovery is a structural walk and not a trailing-zero scan.
    pub(super) fn exact_view(bytes: &[u8]) -> Option<BlockView<'_>> {
        let probe = BlockView::from_bytes(bytes).ok()?;
        let exact = probe.content_length()?;
        BlockView::from_bytes(bytes.get(..exact)?).ok()
    }

    /// Whether any durable slot reads back as a block. Used only to tell a
    /// never-initialized store apart from a populated one whose control plane is
    /// unreadable, so presence is the whole question — it stops at the first hit
    /// rather than counting, which matters because this runs precisely when the
    /// device has already suffered a storage fault.
    fn durable_blocks_present(&self) -> bool {
        let limit = self.durable_scan_limit();
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        (0..limit).any(|idx| self.storage.read_block_into(idx, &mut buf).is_ok())
    }

    /// Upper bound for a durable scan: the storage's slot capacity, never past
    /// the in-memory table (`blocks[i] <-> storage_index = i` is 1:1, so a slot
    /// the table cannot address could not have been written by this node).
    fn durable_scan_limit(&self) -> u32 {
        let capacity = self.storage.capacity();
        let table = MAX_BLOCKS as u32;
        if capacity < table { capacity } else { table }
    }

    /// FR59 step (1): rebuilds the block-tree, the `(sequence, hash)` duplicate
    /// index, parent linkage and `chain_heads` from the retained durable blocks.
    /// Returns how many blocks were admitted to the tree.
    ///
    /// **Blocks land at their own durable index.** `blocks[i]` and
    /// `storage_index = i` are the same slot by construction, so the rebuild
    /// uses `insert_at(i, ..)` rather than allocating a fresh index — and writes
    /// nothing back to storage, because the bytes are already there.
    ///
    /// **No Tier-1 re-run.** Every byte in a slot got there through
    /// `tier1_admit`, which persists only after the gate passes, so each block
    /// was already verified under exactly those rules. Re-verifying N Schnorr
    /// signatures at boot would buy nothing the FR6 pass does not redo for the
    /// candidate it actually adopts.
    ///
    /// **A slot that cannot be understood is skipped, not fatal** — a single bad
    /// slot must not cost the node its chain. That covers an unreadable slot
    /// (`IntegrityFailure`, which the rp2040 backend can produce and the memory
    /// backend cannot) and one whose payload does not frame coherently enough to
    /// recover its exact length.
    ///
    /// **Blocks deleted before the restart come back** (ratified 2026-09-20).
    /// `StorageTrait` has no delete: freeing a slot releases it, and the durable
    /// bytes survive until the next `save_block` overwrites them. Storage cannot
    /// tell a released slot from a live one, so the durable footprint is simply
    /// what is readable. This is safe because every deletion driver is
    /// deterministic and re-fires — the FR3/FR6 pass re-condemns an invalid
    /// block on the candidate chain, and [`Self::initialize_from_storage`]'s
    /// step 6 re-runs the FR8 lock-time cleanups over everything off it — so the
    /// node still converges. What is **not** claimed is that the rebuilt tree
    /// equals the pre-shutdown tree.
    pub(super) fn rebuild_block_tree_from_storage(&mut self, now: u64) -> RebuildStats {
        let limit = self.durable_scan_limit();
        let mut admitted = 0usize;
        let mut unusable = 0usize;
        let mut genesis_admitted = false;

        // Pass 1 — materialize every readable slot at its own index. Parent
        // linkage is deliberately left unresolved: durable slot order is not
        // topological, so a parent may live at a higher index than its child.
        // One read buffer for the whole scan; a successful read overwrites
        // all of it (`read_block_into`), and a failed one is skipped.
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        for idx in 0..limit {
            // A slot that cannot be read (`BlockAbsent` for an empty one;
            // `IntegrityFailure`, which only the rp2040 backend can produce) or
            // whose payload does not frame coherently enough to measure is
            // skipped rather than fatal — one bad slot must not cost the node
            // its chain. `InvalidIndex` cannot occur: the scan is already bounded
            // by `capacity()`.
            //
            // FR64 — the skipped-slot count is a structured-log event, not a
            // field: surfacing it would mean carrying a counter no caller reads
            // until Epic 11 builds the log sink. Emission point marked here.
            match self.storage.read_block_into(idx, &mut buf) {
                Ok(()) => {}
                // An empty slot is not damage; anything else is.
                Err(StorageError::BlockAbsent) => continue,
                Err(_) => {
                    unusable += 1;
                    continue;
                }
            }
            let Some(view) = Self::exact_view(&buf) else {
                unusable += 1;
                continue;
            };
            let hash = view.hash();
            let sequence = view.sequence();

            // The single-genesis rule, which lives in `tier1_admit` and is
            // therefore bypassed by this path. Pass 1 de-duplicates on
            // `(sequence, hash)`, so two *distinct* sequence-0 blocks would both
            // insert and pass 3 would anoint whichever sat at the lower slot —
            // a state live intake can never produce. Reachable exactly through
            // the AC9 resurrection of a condemned genesis whose slot was never
            // reused. First by index wins, matching the live first-come rule.
            if sequence == 0 {
                if genesis_admitted {
                    continue;
                }
                genesis_admitted = true;
            }
            // FR11: the tree must never hold the same (sequence, hash) twice —
            // cheap insurance against a corrupt store, and what `insert_at`
            // debug-asserts.
            if sequence == NONE_REF || self.blocks.find(sequence, &hash).is_some() {
                continue;
            }

            let mut entry = BlockEntry::new(hash, NONE_REF, sequence);
            entry.set_status(BlockStatus::Stored);
            entry.set_len(view.len() as u32);
            entry.set_payload_type(view.payload_type());
            self.blocks.insert_at(idx, entry);
            admitted += 1;
        }

        // Pass 2 — resolve parent linkage now that every block is present.
        // One read buffer for the whole scan; a successful read overwrites
        // all of it (`read_block_into`), and a failed one is skipped.
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        for idx in 0..limit {
            if self.blocks.get(idx).is_none() {
                continue;
            }
            if self.storage.read_block_into(idx, &mut buf).is_err() {
                continue;
            }
            let Some(view) = Self::exact_view(&buf) else {
                continue;
            };
            let Ok(prev_hash) = <[u8; 32]>::try_from(view.previous_hash()) else {
                continue;
            };
            if let Some(parent) = self.blocks.find_parent(&prev_hash, view.sequence()) {
                self.blocks.resolve_parent_ref(idx, parent);
            }
        }

        // Pass 3 — re-establish the genesis anchor, the same way the FR5
        // recovery re-establishes it after a deletion: the single surviving
        // sequence-0 block is the active-chain root. `chain_heads` needs this
        // before it classifies heads, because a head is Connected only if it
        // walks to a block flagged on-active-chain.
        self.active_chain_head_idx = NONE_REF;
        self.snake_chain_tail_idx = NONE_REF;
        self.active_branch_value = 0;
        for idx in 0..limit {
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

        // Pass 4 — heads and branch bookkeeping from the finished graph.
        self.chain_heads
            .rebuild_from_blocks(&mut self.blocks, now, self.active_chain_head_idx);

        // Pass 5 — seed each Stored head's missing-parent cache.
        //
        // This is the one `chain_heads` cache field a rebuild cannot derive from
        // the tree: `BlockEntry` holds a block's own hash and its parent *index*,
        // never its `previous_hash`. Left unseeded, every Stored head keeps the
        // all-zero sentinel and `select_parent_recovery` emits FR19 requests for
        // a hash that can never resolve — for the lifetime of the node. The
        // crate warns about exactly that state twice already.
        self.seed_missing_parent_hashes();

        RebuildStats { admitted, unusable }
    }

    /// Seeds every Stored head's missing-parent cache from its tail-point's
    /// durable `previous_hash` — the one `chain_heads` field the tree cannot
    /// derive. One read per Stored head; an unreadable tail keeps its value.
    /// Used by the FR59 rebuild and the index self-repair.
    pub(super) fn seed_missing_parent_hashes(&mut self) {
        for slot in 0..MAX_BRANCH_COUNT {
            let Some(tail_idx) = self.chain_heads.stored_head_tail(slot) else {
                continue;
            };
            let Some(prev_hash) = self.previous_hash_of(tail_idx) else {
                continue;
            };
            self.chain_heads.set_missing_parent_hash(slot, &prev_hash);
        }
    }

    /// Index self-repair after a `MissingBlock` failure (DEC-134): every block
    /// whose `parent_ref` names a freed slot is unlinked, becoming the
    /// tail-point of a Stored fragment that FR19 parent recovery asks for
    /// again. The tree is then classified afresh and the new tail-points' missing
    /// parents read from storage. Nothing is deleted; no deletion path leaves
    /// such a reference (every deletion is child-closed and the tail release
    /// unlinks the new tail), so this only guards against a defect.
    /// O(`MAX_BLOCKS`), plus one read per Stored head when anything changed.
    pub(super) fn unlink_dangling_parents(&mut self) {
        let mut unlinked = false;
        for idx in 0..MAX_BLOCKS as u32 {
            let Some(parent) = self.blocks.get(idx).map(|entry| entry.parent_ref()) else {
                continue;
            };
            if parent != NONE_REF && self.blocks.get(parent).is_none() {
                self.blocks.set_parent_ref(idx, NONE_REF);
                unlinked = true;
            }
        }
        if unlinked {
            // The event-(iv) follow-up with nothing deleted: caches and the
            // FR19 `head_ref_count`s re-derived from the repaired tree.
            self.chain_heads
                .on_blocks_deleted(&mut self.blocks, &[], NONE_REF);
            self.seed_missing_parent_hashes();
        }
    }

    /// The `previous_hash` of the block in durable slot `idx`, trimmed to its
    /// recovered exact length. `None` when the slot cannot be read or measured.
    fn previous_hash_of(&self, idx: u32) -> Option<[u8; 32]> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        self.storage.read_block_into(idx, &mut buf).ok()?;
        let view = Self::exact_view(&buf)?;
        <[u8; 32]>::try_from(view.previous_hash()).ok()
    }

    /// FR8 tentative re-establishment after a restart that found no durable
    /// configuration.
    ///
    /// The tentative phase is not persisted, so a node that shut down while
    /// still collecting comes back holding nothing — yet its retained tree may
    /// already carry the chain-config block it had adopted. Re-adopting keeps
    /// the restart equivalent to a fresh node fed the same blocks, which is the
    /// FR59 guarantee; without it the node could not run the FR3 derivation at
    /// all until another config block happened to arrive.
    ///
    /// FR8 defines the tentative as "the first chain-config block whose
    /// signature verifies and whose content is accepted", which is an
    /// arrival-ordered fact — and arrival order is exactly what a restart has
    /// lost. The lowest durable index is used instead: deterministic, and enough
    /// for the property that is actually required, since Story 5.9 already
    /// recorded that convergence on the same end state, not identity of the
    /// intermediate tentative, is what FR8 can guarantee across orderings.
    fn reestablish_tentative_chain_config(&mut self) {
        let limit = self.durable_scan_limit();
        // One read buffer for the whole scan; a successful read overwrites
        // all of it (`read_block_into`), and a failed one is skipped.
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        for idx in 0..limit {
            let is_config = self
                .blocks
                .get(idx)
                .is_some_and(|entry| entry.payload_type() == PAYLOAD_TYPE_CHAIN_CONFIG);
            if !is_config {
                continue;
            }
            if self.storage.read_block_into(idx, &mut buf).is_err() {
                continue;
            }
            let Some(view) = Self::exact_view(&buf) else {
                continue;
            };
            // The same state-free FR7 gate the intake path uses, so the two
            // cannot drift.
            if tier1_chain_config_block(&view, &self.node_zero_public_key, &self.crypto).is_err() {
                continue;
            }
            if self.chain_config.load_tentative(view.payload()).is_ok() {
                self.tentative_config_block_idx = idx;
                self.reset_vote_engine();
                return;
            }
        }
    }
}
