//! Construction (`BUILD_LIMITS`, `init` / `new`), node zero's FR54 genesis
//! bootstrap and the lifecycle phase helpers (Stories 1.4, 5.1).

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
    /// This build's capacities, stated for the configuration module's §6
    /// acceptance checks — the bounds that crate cannot derive because the
    /// capacities live here (specification §6, `BuildLimits`).
    ///
    /// Hand this to `ChainConfiguration::new` rather than restating the numbers
    /// at the construction site: the module keeps no copy of them, so the two §6
    /// checks read exactly what this constant says, and drift between the
    /// blockchain's arrays and the module's bounds stays unrepresentable.
    ///
    /// - `utxo_unspent_bits` — `Self::UTXO_BITFIELD_WIDTH`, the per-block
    ///   available-UTXO bitfield width of `BlockEntry`, `AVAILABLE_UTXO_BYTES ·
    ///   8` (DEC-318).
    /// - `snake_chain_length_max` — `SNAKE_CHAIN_LENGTH_MAX`, the active-chain
    ///   capacity. The chain's own window `W` must fit inside it, whether the
    ///   content declares `W` or leaves it at its default.
    /// - `max_blocks` — `MAX_BLOCKS`, the block table. The window, the FR58
    ///   verification horizon and one competing branch of depth `H` must fit:
    ///   `W + 2·H ≤ MAX_BLOCKS` (§6 check 16).
    /// - `block_size_max` — `MAX_BLOCK_SIZE`, the block buffer of this build's
    ///   size tier (DEC-220). The chain's `block_size_limit` must fit it (§6
    ///   check 5), so a block above it is a local refusal, never evidence.
    /// - `node_count_max` — `MAX_NODES`, the node-indexed arrays. The chain's
    ///   `max_node_count` must fit it (§6 check 18), so every registered node id
    ///   has a slot (DEC-228).
    /// - `signature_scheme` — `moonblokz_crypto::SIGNATURE_SCHEME`, the build's
    ///   scheme. The chain's `signature_scheme` (ID 33, default `schnorr`) must
    ///   equal it (§6 check 19, DEC-252).
    pub const BUILD_LIMITS: BuildLimits = BuildLimits {
        utxo_unspent_bits: Self::UTXO_BITFIELD_WIDTH,
        snake_chain_length_max: {
            // Every chain declares `W >= 1` (configuration §6 check 7), so a
            // zero capacity would compile into a node that refuses every chain.
            assert!(
                SNAKE_CHAIN_LENGTH_MAX >= 1,
                "SNAKE_CHAIN_LENGTH_MAX must hold a window of at least one block"
            );
            // Story 6.4 D2: the active-set counter holds at most one count per
            // window block in a `u16`.
            assert!(
                SNAKE_CHAIN_LENGTH_MAX <= u16::MAX as u32,
                "SNAKE_CHAIN_LENGTH_MAX must fit the active-set counter"
            );
            // Acceptance admits any `W` up to this capacity, and FR2 needs a
            // `W`-long segment in the block table to leave Collecting. A
            // capacity above the table would accept chains this node can never
            // acquire.
            assert!(
                SNAKE_CHAIN_LENGTH_MAX as usize <= MAX_BLOCKS,
                "SNAKE_CHAIN_LENGTH_MAX must fit the block table (MAX_BLOCKS)"
            );
            SNAKE_CHAIN_LENGTH_MAX
        },
        max_blocks: {
            assert!(
                MAX_BLOCKS <= u32::MAX as usize,
                "MAX_BLOCKS must fit the configuration module's u32 capacity"
            );
            MAX_BLOCKS as u32
        },
        // Lossless: chain-types asserts `MAX_BLOCK_SIZE <= u32::MAX`.
        block_size_max: MAX_BLOCK_SIZE as u32,
        node_count_max: {
            assert!(
                MAX_NODES <= u32::MAX as usize,
                "MAX_NODES must fit the configuration module's u32 capacity"
            );
            MAX_NODES as u32
        },
        // The scheme the crypto crate was built with: a chain founded on
        // another one is refused at acceptance (configuration check 19, DEC-252).
        signature_scheme: moonblokz_crypto::SIGNATURE_SCHEME,
    };

    /// Constructs the node in place, inside caller-provided storage, and
    /// hands back a `&mut` to the initialized value. This is the type's
    /// **only** constructor.
    ///
    /// `Self` is large (dominated by `blocks: BlockTable<MAX_BLOCKS, …>`,
    /// e.g. 31.2 KB at the default `MAX_BLOCKS = 600`) — large enough that no
    /// construction technique *inside* a function that returns `Self` by
    /// value can avoid needing a full `size_of::<Self>()`-sized stack
    /// allocation somewhere (measured across several approaches: a
    /// struct-literal, and `MaybeUninit` + per-field pointer writes with
    /// and without an element-by-element large-array fill — all landed at
    /// the same floor). A by-value `new()` existed earlier and was fine for
    /// the desktop simulator (architecture §10 / FR62 — plain owned value,
    /// no `'static`/global state, and no tight stack budget there) and for
    /// tests, but it was removed from the production surface once every
    /// caller was confirmed able to use this constructor instead: a plain
    /// owned `Blockchain` is still reachable anywhere it's needed via a local
    /// `MaybeUninit` + `assume_init()` (exactly as this crate's own tests
    /// do), it just always goes through an in-place write rather than a
    /// by-value return. `new()` survives only under `cfg(test)`, as the
    /// executable specification `init` is checked against ([`Self::new`]).
    /// This is the single constructor for every node; node zero then runs
    /// [`Self::process_genesis`] on the constructed instance to bootstrap the
    /// chain (FR54).
    ///
    /// For embedded firmware, use this from *inside* a
    /// `#[embassy_executor::task]` fn — no `unsafe` is needed at the call
    /// site:
    ///
    /// ```ignore
    /// #[embassy_executor::task]
    /// async fn blockchain_task(/* ... */) {
    ///     let mut slot = core::mem::MaybeUninit::<BlockchainT>::uninit();
    ///     let bc = BlockchainT::init(&mut slot, /* ... */);
    ///
    ///     // Load-bearing: `slot` must stay live across an `.await`, or the
    ///     // compiler has no reason to place it in the task's Future state
    ///     // rather than a transient local within this poll segment —
    ///     // measured to make the difference between ~66.6 KiB in the shared
    ///     // poll-time call stack and ~66.6 KiB in the task's own
    ///     // statically-sized `TaskStorage` instead (moonblokz-node round-7
    ///     // stack investigation, Story 4.1 deferred-work follow-up).
    ///     embassy_futures::yield_now().await;
    ///
    ///     // ... use `bc` ...
    /// }
    /// ```
    ///
    /// Declaring `slot` as a plain local of a synchronous function (or
    /// never crossing an `.await` while it's live) gets none of this
    /// benefit — the ~66.6 KB then sits in that function's own transient
    /// stack frame regardless of how carefully it's written.
    ///
    /// This function is **safe**: a `&mut MaybeUninit<Self>` already
    /// guarantees a non-null, aligned, exclusively borrowed destination that
    /// is valid for writes, and the caller only receives the `&mut Self` once
    /// every field has been written — a panic before that point leaves `slot`
    /// uninitialized, which is a safe state (nothing is dropped). The single
    /// obligation the type system cannot check — every field is written, none
    /// is read before its write — lives inside the `unsafe` block below and is
    /// pinned by `init_is_equivalent_to_new`: the test-only [`Self::new`]
    /// struct literal is the specification (the language forces it to name
    /// every field), and the test holds `init` to it field by field.
    pub fn init(
        slot: &mut core::mem::MaybeUninit<Self>,
        crypto: Crypto,
        storage: Storage,
        chain_config: Config,
        local_node_id: u32,
        node_zero_public_key: [u8; PUBLIC_KEY_SIZE],
        prng_seed: u64,
    ) -> &mut Self {
        // The two §6 capacities this build states to the configuration module
        // must leave a bound violation expressible in each parameter's declared
        // width, or the module's acceptance check goes quiet (see
        // [`Self::BUILD_LIMITS`]). Monomorphization-time, like
        // `ChainHeadsTable::init`'s own const assert: invisible to `cargo check`
        // while it passes.
        const { assert!(limits_are_expressible(Self::BUILD_LIMITS)) };

        let p = slot.as_mut_ptr();
        // SAFETY: `p` is derived from a live `&mut MaybeUninit<Self>`, so it
        // is non-null, aligned, valid for writes of `Self` and not aliased.
        // Every field is written exactly once below and none is read before
        // its write; the nested tables are initialized through their own safe
        // `init`, each handed a `&mut MaybeUninit<_>` view of its field.
        unsafe {
            (&raw mut (*p).crypto).write(crypto);
            (&raw mut (*p).storage).write(storage);
            (&raw mut (*p).chain_config).write(chain_config);
            (&raw mut (*p).local_node_id).write(local_node_id);
            (&raw mut (*p).node_zero_public_key).write(node_zero_public_key);
            (&raw mut (*p).prng).write(Prng::new(prng_seed));
            (&raw mut (*p).lifecycle_phase).write(LifecyclePhase::Collecting);
            (&raw mut (*p).restart_refused).write(false);
            BlockTable::init(field_slot(&raw mut (*p).blocks));
            ChainHeadsTable::init(field_slot(&raw mut (*p).chain_heads));
            // SoA + vote registry init in place (never a MAX_NODES-scaled stack
            // temporary — Epic-4-retro §8 RAM watch-item).
            NodeInfoState::init(field_slot(&raw mut (*p).node_info));
            // Unparameterized: the FR37 values are chain configuration, which a
            // node need not hold yet. `reset_vote_engine` supplies them the
            // moment one is loaded; until then every vote effect refuses with
            // `VoteEngineError::NotParameterized`.
            VoteEngine::init(field_slot(&raw mut (*p).vote_engine));
            (&raw mut (*p).last_parent_request_emit_timestamp).write(0);
            (&raw mut (*p).active_chain_head_idx).write(NONE_REF);
            (&raw mut (*p).tentative_config_block_idx).write(NONE_REF);
            (&raw mut (*p).snake_chain_tail_idx).write(NONE_REF);
            (&raw mut (*p).active_branch_value).write(0);
            ActiveSetCounter::init(field_slot(&raw mut (*p).active_set));
            (&raw mut (*p).non_conflict).write(NonConflictRing::new());
            (&raw mut (*p).support_dedupe).write(SupportDedupe::new(
                Prng::new(prng_seed).derive_subseed(DEDUPE_SALT_LABEL),
            ));
            ApprovalAccumulator::init(field_slot(&raw mut (*p).approval));
            (&raw mut (*p).active_open_run).write(NO_OPEN_RUN);
            (&raw mut (*p).reentry_due).write(false);
        }
        // SAFETY: every field of `Self` was written above.
        unsafe { slot.assume_init_mut() }
    }

    /// The by-value constructor, kept as the **executable specification** of
    /// [`Self::init`]: a plain struct literal, which the language forces to
    /// name every field, so adding a field to `Blockchain` is a compile error
    /// here until the literal — and therefore the specification — is updated.
    /// `init_is_equivalent_to_new` then holds `init` to it field by field.
    ///
    /// Test-only: returning `Self` by value costs a `size_of::<Self>()`-sized
    /// transient (~66 KB), which is exactly what `init` exists to avoid on
    /// the embedded stack. Never a production code path.
    #[cfg(test)]
    pub(crate) fn new(
        crypto: Crypto,
        storage: Storage,
        chain_config: Config,
        local_node_id: u32,
        node_zero_public_key: [u8; PUBLIC_KEY_SIZE],
        prng_seed: u64,
    ) -> Self {
        Self {
            crypto,
            storage,
            chain_config,
            local_node_id,
            node_zero_public_key,
            prng: Prng::new(prng_seed),
            lifecycle_phase: LifecyclePhase::Collecting,
            restart_refused: false,
            blocks: BlockTable::new(),
            chain_heads: ChainHeadsTable::new(),
            node_info: NodeInfoState::new(),
            vote_engine: VoteEngine::new(),
            last_parent_request_emit_timestamp: 0,
            active_chain_head_idx: NONE_REF,
            tentative_config_block_idx: NONE_REF,
            snake_chain_tail_idx: NONE_REF,
            active_branch_value: 0,
            active_set: ActiveSetCounter::new(),
            non_conflict: NonConflictRing::new(),
            support_dedupe: SupportDedupe::new(
                Prng::new(prng_seed).derive_subseed(DEDUPE_SALT_LABEL),
            ),
            approval: ApprovalAccumulator::new(),
            active_open_run: NO_OPEN_RUN,
            reentry_due: false,
        }
    }

    /// FR54 genesis bootstrap: builds **both** genesis blocks in a single call
    /// on an already-constructed (empty, `Collecting`) node-zero `Blockchain`,
    /// persists them through the storage seam, and returns both so the caller
    /// can broadcast them over the radio (lowest-sequence first):
    ///
    /// - **Block #0** — node-#0 registration + an initial self-transfer of
    ///   `initial_total_network_currency` (`PAYLOAD_TYPE_TRANSACTION`).
    /// - **Block #1** — the chain-config block carrying
    ///   `initial_chain_config_bytes` (`PAYLOAD_TYPE_CHAIN_CONFIG`), with
    ///   `previous_hash` chained to Block #0's hash. Signed over its full
    ///   canonical content via [`BlockBuilder::set_chain_config_payload`].
    ///
    /// This is a plain `&mut self` state transition, not a constructor: the node
    /// is built once through [`Self::init`], then genesis runs against
    /// it. That keeps the single infallible in-place constructor and lets genesis
    /// use ordinary fallible control flow. (Non-zero nodes never call this; they
    /// construct via `init` and receive the chain over the mesh.)
    ///
    /// Refusal (`Err(GenesisRejectReason::_)`, `self` left unchanged): the local
    /// node id is not `0`; the chain is not empty (`StorageNotEmpty` — already
    /// bootstrapped, which after FR54 means the configuration is durably
    /// locked); the storage control plane is not initialized
    /// (`StorageNotInitialized`); `initial_chain_config_bytes` plus its
    /// signature trailer does not fit (`InitialChainConfigTooLarge`); the
    /// configuration module refuses the content (`InitialChainConfigRejected`);
    /// a genesis block exceeds the block-size limit that configuration declares
    /// (`GenesisBlockExceedsBlockSizeLimit`); or a block cannot be persisted
    /// (`StorageSaveFailed`).
    ///
    /// Every check but the last runs before any storage write, and both blocks
    /// are built before either is saved, so those refusals leave nothing behind.
    /// `StorageSaveFailed` is the exception and the honest limit of this method:
    /// a backend that accepts one write and then fails leaves the earlier one
    /// persisted, and the non-empty-chain guard above then refuses the retry.
    /// The **systematic** version of that hazard — a backend whose control
    /// plane was never initialized, where `save_block` succeeds and
    /// `set_chain_configuration` cannot — is what the `StorageNotInitialized`
    /// probe removes. A mid-sequence I/O failure is a genuinely partial write
    /// and belongs to the Story 5.10 restart/repair path, not here.
    ///
    /// Unlike the other state-changing methods, genesis carries **no
    /// `NextCall`** (the return is a plain `Result<GenesisBlocks, _>`, not a
    /// `CallResult`). Genesis is a one-per-chain bootstrap with no follow-up work
    /// scheduled immediately after it, so it is deliberately kept out of the AR4
    /// single-outcome scheduling-pull contract that the recurring methods share —
    /// there is never a real deadline to return here. Normal scheduling begins
    /// with the caller's regular `on_tick` cadence. (No `now` parameter is needed
    /// for the same reason.)
    ///
    /// **Chain-config framing (FR54, Story 5.8).** `initial_chain_config_bytes`
    /// is raw configuration *content*. This method frames Block #1's payload as
    /// that content plus the node-#0 content signature it produces itself — at
    /// genesis the local key *is* node #0's key — loads it into the
    /// configuration module durably (acceptance first, so a refusal writes
    /// nothing), and hands the block to the durable `set_chain_configuration`
    /// seam. Detecting a non-empty *persisted* store on reboot is Story 5.10;
    /// the `StorageNotEmpty` guard here inspects in-memory chain state and the
    /// FR8 lock.
    pub fn process_genesis(
        &mut self,
        initial_total_network_currency: u64,
        initial_chain_config_bytes: &[u8],
    ) -> Result<GenesisBlocks, GenesisRejectReason> {
        if self.local_node_id != 0 {
            return Err(GenesisRejectReason::LocalNodeIdNotZero);
        }
        // FR68 (DEC-293): the instance must hold node #0's key, the anchor every
        // node checks blocks #0 and #1 against (FR69). Before the storage probe,
        // which can write a replica repair, and before anything is signed.
        if self.crypto.public_key().serialize() != &self.node_zero_public_key {
            return Err(GenesisRejectReason::KeyMismatch);
        }
        // Genesis is only valid on a fresh chain. Re-running it would overwrite
        // an existing Block #0, and FR54's lock is set-once — the module itself
        // would refuse the second load, so the guard reads the lock rather than
        // a retention flag.
        if self.blocks.len() != 0 || self.chain_config.is_durable_locked() {
            return Err(GenesisRejectReason::StorageNotEmpty);
        }

        // The durable configuration commit below needs the storage control
        // plane; `save_block` does not. Probing it here keeps the method's
        // contract ("all non-persistence checks run before any storage write"):
        // without the probe an uninitialized backend persists both blocks, then
        // refuses the configuration, and every retry is turned away by the
        // non-empty-chain guard above — a node that can never bootstrap.
        if self.storage.load_control_data().is_err() {
            return Err(GenesisRejectReason::StorageNotInitialized);
        }

        // The framed chain-config payload (content + node-#0 signature) must
        // fit block #1. Checked before anything is built or signed.
        if initial_chain_config_bytes
            .len()
            .checked_add(SIGNATURE_SIZE)
            .is_none_or(|len| len > MAX_PAYLOAD_SIZE)
        {
            return Err(GenesisRejectReason::InitialChainConfigTooLarge);
        }

        // Both blocks are built once, in place, into this value (Story 12.2,
        // DEC-301), which every path from here returns: it is moved once into
        // the caller's slot, never assembled from copies.
        let mut genesis = unbuilt_genesis();
        if let Ok(blocks) = &mut genesis
            && let Err(reason) = self.build_and_commit_genesis(
                blocks,
                initial_total_network_currency,
                initial_chain_config_bytes,
            )
        {
            genesis = Err(reason);
        }
        genesis
    }

    /// The rest of [`Self::process_genesis`] after the storage probe: builds
    /// both blocks into `blocks`, checks and derives them, persists them and
    /// mirrors them into the tree. A refusal is returned in the method's order.
    fn build_and_commit_genesis(
        &mut self,
        blocks: &mut GenesisBlocks,
        initial_total_network_currency: u64,
        initial_chain_config_bytes: &[u8],
    ) -> Result<(), GenesisRejectReason> {
        let node_zero_public_key = *self.crypto.public_key().serialize();

        // Each block is built out of line, in its own step: the builders and
        // the framed payload live only in the steps' frames, popped before the
        // storage writes below. Block #0 cannot be refused, so building it
        // before the content check leaves the refusal order as it was.
        genesis_block_zero(
            &self.crypto,
            &node_zero_public_key,
            initial_total_network_currency,
            &mut blocks.block_zero,
        );
        self.genesis_block_one(
            blocks.block_zero.hash(),
            initial_chain_config_bytes,
            &mut blocks.block_one,
        )?;

        // Both blocks must fit the block-size limit **the genesis configuration
        // itself declares**, which is a chain value now rather than the framing
        // constant it was while the stub answered. The registry admits anything
        // above `HEADER_SIZE`, so a founder can legally declare a limit smaller
        // than the blocks this bootstrap produces — and then every peer refuses
        // Block #1 at Tier 1 (`BlockTooLarge`) and the founder's own restart
        // refuses it again at FR6. Checked before any write: a chain that cannot
        // carry its own genesis must not be created.
        let block_size_limit = self.block_size_limit() as usize;
        if blocks.block_zero.len() > block_size_limit || blocks.block_one.len() > block_size_limit {
            return Err(GenesisRejectReason::GenesisBlockExceedsBlockSizeLimit);
        }

        // D6 (Story 6.0): node #0 runs the ordinary per-block step over its own
        // blocks, in the complete context (D3) — one code path, no node-#0
        // trust zone; the FR54 exemptions are the step's own genesis branches.
        // It runs before any write, against the tentative configuration (the
        // vote parameters and the content block #1 must match), so a refusal
        // leaves nothing behind. The blocks are built here from the local key
        // and the caller's content, so the configuration is the only input the
        // derivation can refuse.
        self.node_info.reset();
        self.reset_vote_engine();
        let mut projection = Projection::COMPLETE;
        let derived = self
            .validate_and_derive_block(&blocks.block_zero.view(), 0, None, &mut projection)
            .and_then(|()| {
                self.validate_and_derive_block(
                    &blocks.block_one.view(),
                    1,
                    Some(blocks.block_zero.hash()),
                    &mut projection,
                )
            });
        if derived.is_err() {
            return Err(self.abandon_genesis(GenesisRejectReason::InitialChainConfigRejected));
        }

        // Persist both blocks (only after both are built, so a build failure
        // never leaves a partially-persisted chain) AND mirror them into the
        // in-memory block-tree as node #0's active chain, so storage and the tree
        // stay consistent and the node is immediately operational. The
        // `StorageNotEmpty` guard above guarantees slots 0/1 are free. Genesis
        // blocks are valid by construction, so they bypass the tier1 intake gate;
        // they are placed exactly as that path establishes the genesis anchor
        // (`on_active_chain` + active head + `chain_heads`), with a sentinel
        // arrival timestamp of 0 — genesis heads sit on the active chain and are
        // never parent-recovery-scheduled, so the timestamp is unused. Both are
        // Active: the step above validated them (D7).

        // Block #0 — active-chain anchor (no parent).
        self.storage
            .save_block(0, &blocks.block_zero)
            .map_err(|_| self.abandon_genesis(GenesisRejectReason::StorageSaveFailed))?;
        let mut entry_0 = BlockEntry::new(blocks.block_zero.hash(), NONE_REF, 0);
        entry_0.set_status(BlockStatus::Active);
        entry_0.set_on_active_chain(true);
        entry_0.set_len(blocks.block_zero.len() as u32);
        entry_0.set_payload(&blocks.block_zero.view());
        self.blocks.insert_at(0, entry_0);
        self.active_chain_head_idx = 0;
        let active_head = self.active_chain_head_idx;
        self.chain_heads
            .on_block_admitted(&mut self.blocks, 0, None, [0u8; 32], 0, active_head);

        // Block #1 — chain-config, chained to Block #0; becomes the active tip.
        self.storage
            .save_block(1, &blocks.block_one)
            .map_err(|_| self.abandon_genesis(GenesisRejectReason::StorageSaveFailed))?;
        // The durable chain-configuration seam (FR54): the blockchain owns the
        // storage handle, so the durable commit is made here rather than by the
        // configuration module (configuration specification §8.2).
        self.storage
            .set_chain_configuration(&blocks.block_one)
            .map_err(|_| self.abandon_genesis(GenesisRejectReason::StorageSaveFailed))?;
        // Every durable write has succeeded: promote the tentative to FR54's
        // set-once lock. `promote_durable` can only fail with `NotLoaded` or
        // `DurableLocked`, and the load above plus the guard at the top of this
        // method rule both out.
        self.chain_config
            .promote_durable()
            .map_err(|_| self.abandon_genesis(GenesisRejectReason::InitialChainConfigRejected))?;
        // The vote engine was parameterized from this same content, tentative,
        // before the derivation above; the lock changes nothing it reads.
        let block_1_prev_hash = blocks.block_zero.hash();
        let mut entry_1 = BlockEntry::new(blocks.block_one.hash(), 0, 1);
        entry_1.set_status(BlockStatus::Active);
        entry_1.set_on_active_chain(true);
        entry_1.set_len(blocks.block_one.len() as u32);
        entry_1.set_payload(&blocks.block_one.view());
        self.blocks.insert_at(1, entry_1);
        self.active_chain_head_idx = 1;
        let active_head = self.active_chain_head_idx;
        self.chain_heads.on_block_admitted(
            &mut self.blocks,
            1,
            Some(0),
            block_1_prev_hash,
            0,
            active_head,
        );
        self.establish_snake_chain_window();
        // The window value stays 0 (Story 6.1 D5): block #1, the only block
        // the window `(#0, #1]` can hold, is built above with
        // `consumed_votes = 0`. The tree holds nothing else, so there is no
        // side branch for the driver to connect.

        // Node #0 authored a complete, valid chain, so it is immediately Ready:
        // there is no FR2 dominant-chain acquisition or FR3 reconstruction to do
        // for the author (join/restart nodes still go through Collecting).
        // This is an **init-time** establishment of the initial phase, NOT a
        // runtime `Collecting→Ready` transition (which is illegal, Story 5.1) —
        // genesis therefore writes the field directly rather than through the
        // guarded `set_lifecycle_phase`.
        self.lifecycle_phase = LifecyclePhase::Ready;
        Ok(())
    }

    /// Block #1 of FR54: the chain-config block, chained to block #0
    /// (`block_zero_hash`), loaded into the configuration module tentatively.
    ///
    /// FR54 framing: the payload is the content region followed by the
    /// node-#0 content signature (the Story 5.7 envelope). Framed here rather
    /// than taken framed, because the signature is node #0's and genesis is
    /// the one place that key is the local one.
    ///
    /// Out of line (Story 12.2, DEC-301): the framed payload and the builder
    /// live in this frame, popped before `process_genesis` writes storage.
    #[inline(never)]
    fn genesis_block_one(
        &mut self,
        block_zero_hash: [u8; 32],
        initial_chain_config_bytes: &[u8],
        out: &mut Block,
    ) -> Result<(), GenesisRejectReason> {
        // `process_genesis` bounded the framed length by `MAX_PAYLOAD_SIZE`.
        let content_len = initial_chain_config_bytes.len();
        let payload_len = content_len + SIGNATURE_SIZE;
        let mut payload = [0u8; MAX_PAYLOAD_SIZE];
        payload[..content_len].copy_from_slice(initial_chain_config_bytes);
        payload[content_len..payload_len]
            .copy_from_slice(self.crypto.sign(initial_chain_config_bytes).serialize());
        let chain_config_payload = &payload[..payload_len];

        // Tentative first: acceptance runs inside the load and before anything
        // is retained, so a content refusal leaves the module exactly as it was
        // and genesis writes nothing. The **durable** lock is engaged only
        // after the last storage write succeeds (`process_genesis`) — FR54's
        // lock is set-once, and a module locked by a call that then failed on
        // storage would refuse every retry, with `StorageNotEmpty`, for the
        // life of the process. A tentative left behind by a failed genesis is
        // harmless: the next attempt replaces it.
        self.chain_config
            .load_tentative(chain_config_payload)
            .map_err(|_| GenesisRejectReason::InitialChainConfigRejected)?;

        let block_1_header = BlockHeader {
            version: 1,
            sequence: 1,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: block_zero_hash,
            signature: [0u8; SIGNATURE_SIZE],
        };
        let mut cfg_builder = BlockBuilder::new().header(block_1_header);
        // `process_genesis` bounded the framed payload by `MAX_PAYLOAD_SIZE`,
        // so it fits block #1.
        if cfg_builder
            .set_chain_config_payload(chain_config_payload)
            .is_err()
        {
            unreachable!("the framed chain-config payload was capacity-checked");
        }
        if cfg_builder.build_signed_into(&self.crypto, out).is_err() {
            unreachable!("Block #1 header.version = 1 and payload fits MAX_BLOCK_SIZE");
        }
        Ok(())
    }

    /// A refused genesis leaves no derived projection behind: the D6 step ran
    /// before the writes, so every refusal after it resets what it derived.
    fn abandon_genesis(&mut self, reason: GenesisRejectReason) -> GenesisRejectReason {
        self.node_info.reset();
        self.reset_vote_engine();
        reason
    }

    /// Read-only query — returns the current lifecycle phase (FR1–FR4).
    ///
    /// Carries no `NextCall` per AR4 (read-only queries do not change
    /// scheduling).
    pub fn current_phase(&self) -> LifecyclePhase {
        match self.lifecycle_phase {
            LifecyclePhase::Collecting => LifecyclePhase::Collecting,
            LifecyclePhase::Processing => LifecyclePhase::Processing,
            LifecyclePhase::Ready => LifecyclePhase::Ready,
        }
    }

    /// Guarded runtime lifecycle transition (FR1/FR4). Debug-asserts the edge is
    /// legal per [`crate::lifecycle::is_legal_transition`] (`Collecting→Processing`,
    /// `Processing→Ready`, `Processing→Collecting`; never `Collecting→Ready`),
    /// then writes the new phase. The assert compiles out in release, where the
    /// transition is trusted (the same debug-assert-invariant discipline the
    /// intake/admission path uses). The FR2/FR6/FR5 drivers in Stories 5.2/5.4/5.5
    /// are the only callers. **Genesis does not use this** — it establishes the
    /// initial `Ready` phase directly at bootstrap (initialization, not a runtime
    /// transition; see [`Self::process_genesis`]).
    // First runtime caller is the Story 5.2 FR2 dominant-chain acquisition hook in
    // `receive_block` (Collecting→Processing); Stories 5.4/5.5 add the other edges.
    pub(crate) fn set_lifecycle_phase(&mut self, to: LifecyclePhase) {
        debug_assert!(
            is_legal_transition(&self.lifecycle_phase, &to),
            "illegal lifecycle transition"
        );
        self.lifecycle_phase = to;
    }

    /// The single readiness gate (FR1). `true` iff the node is in `Ready`; every
    /// Ready-state-only surface consults this before operating. In `Collecting` /
    /// `Processing` it is `false`, so those surfaces return their uniform
    /// not-ready indication.
    pub(crate) fn is_ready(&self) -> bool {
        self.lifecycle_phase == LifecyclePhase::Ready
    }
}

/// The value `process_genesis` returns, before its steps build the blocks
/// into it: two header-only blocks. Out of line, so the value is built in
/// the caller's slot rather than assembled in its frame and copied there.
#[inline(never)]
fn unbuilt_genesis() -> Result<GenesisBlocks, GenesisRejectReason> {
    let mut header = [0u8; HEADER_SIZE];
    header[0] = 1;
    match (Block::from_bytes(&header), Block::from_bytes(&header)) {
        (Ok(block_zero), Ok(block_one)) => Ok(GenesisBlocks {
            block_zero,
            block_one,
        }),
        _ => unreachable!("a version-1 header is a valid block"),
    }
}

/// Block #0 exactly as FR54 fixes it (DEC-269): node #0's registration
/// (`new_node_id` 0, key `node_zero_public_key`), then node #0's self-transfer
/// of `initial_total_network_currency`; creator 0, every other header and
/// transaction field 0, all-zeros `previous_hash`. `process_genesis` builds its
/// block #0 here, and the Tier 1 genesis-shape check
/// (`staged_validation::is_genesis_zero_shape`) accepts exactly this layout with
/// any amount. The order is load-bearing: the registration seeds node #0, so
/// the self-transfer then credits it the amount.
///
/// Built into `out` in place, out of line (Story 12.2, DEC-301): its builder
/// lives in this frame only.
#[inline(never)]
pub(super) fn genesis_block_zero<C: CryptoTrait>(
    crypto: &C,
    node_zero_public_key: &[u8; PUBLIC_KEY_SIZE],
    initial_total_network_currency: u64,
    out: &mut Block,
) {
    let registration = Registration::new_signed(
        0, // vote
        0, // initializer (node #0)
        0, // new_node_id (node #0)
        0, // registration_price
        0, // fee
        node_zero_public_key,
        crypto,
    );
    let self_transfer = NodeTransfer::new_signed(
        0, // vote
        0, // anchor_sequence
        0, // initializer (node #0)
        0, // receiver (self)
        initial_total_network_currency,
        0, // fee
        0, // comment
        crypto,
    );

    let block_0_header = BlockHeader {
        version: 1,
        sequence: 0,
        creator: 0,
        mined_amount: 0,
        payload_type: PAYLOAD_TYPE_TRANSACTION,
        consumed_votes: 0,
        first_voted_node: 0,
        consumed_votes_from_first_voted_node: 0,
        previous_hash: [0u8; 32],
        // Ignored by `BlockBuilder::build_signed`; the builder signs the
        // FR70 preimage (the header before this field, then `H(payload)`),
        // then stores the generated signature here.
        signature: [0u8; SIGNATURE_SIZE],
    };

    // The chain-types builder errors only on payload-type mismatch or
    // capacity overflow — neither applies to these fixed-size bootstrap
    // payloads. The walking-skeleton uses `unreachable!` to make the
    // invariant explicit; Story 5.6+ may surface BlockError through a
    // new GenesisRejectReason variant when the assembly grows.
    let mut builder = BlockBuilder::new().header(block_0_header);
    if builder.add_registration(&registration).is_err() {
        unreachable!("Block #0 registration is fixed-size and cannot overflow payload");
    }
    if builder.add_node_transfer(&self_transfer).is_err() {
        unreachable!("Block #0 self-transfer is fixed-size and cannot overflow payload");
    }
    if builder.build_signed_into(crypto, out).is_err() {
        unreachable!("Block #0 header.version = 1 and payload fits MAX_BLOCK_SIZE");
    }
}
