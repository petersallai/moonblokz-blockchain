//! Primary public API surface for `moonblokz-blockchain` (FR66). All
//! blockchain-facing state is reachable only through types defined or
//! re-exported here; internal modules stay crate-private. The temporary
//! `chain_config` seam remains public only until the standalone
//! `moonblokz-configuration` crate exists.
//!
//! Story 1.3 scope: trait seams (`CryptoTrait`/`StorageTrait`/
//! `ChainConfigTrait`), construction-time init parameters
//! (`local_node_id`/`node_zero_public_key`/`prng_seed`), and the
//! Xoshiro-rooted replay seam. The full 18-method method set and outcome
//! enums arrive in Story 1.4+ per architecture §3.1–§3.6.
//!
//! Replay determinism — the module performs **no internal wall-clock reads
//! and no internal entropy source**. Callers supply `prng_seed: u64` at
//! construction and `now: u64` to every state-changing method (forthcoming),
//! so the same construction inputs + the same event sequence yield identical
//! state (FR62 / FR63 precondition).

use moonblokz_chain_types::{
    Block, BlockBuilder, BlockHeader, BlockView, NodeTransfer, PAYLOAD_TYPE_TRANSACTION,
    Registration,
};
use moonblokz_crypto::{CryptoTrait, PUBLIC_KEY_SIZE, PublicKeyTrait};
use moonblokz_storage::StorageTrait;

use crate::blocks::{BlockEntry, BlockTable, BlockTableError, NONE_REF};
use crate::chain_config::{ChainConfigError, ChainConfigTrait};
use crate::intake::classify_block;
use crate::prng::Prng;
use crate::staged_validation::{BlockStatus, Tier1Failure, tier1_gate};

/// Next-call deadline carried alongside every state-changing outcome.
///
/// Single-outcome scheduling-pull pattern (architecture §3.2): each
/// state-changing call returns at most one semantic outcome plus a
/// [`NextCall`] telling the bridge layer when to call back via
/// `embassy_time::Timer::at(...)`.
// Deliberately no derives yet: in the embedded target, every generated trait impl
// must justify its code-size cost. Re-evaluate Copy/Clone/Debug only when a later
// story demonstrates a concrete API/scheduler need.
pub enum NextCall {
    /// Call back at the given absolute monotonic timestamp (ms).
    /// `At(now)` (or any past instant) means "call back as soon as possible".
    At(u64),
    /// Nothing scheduled; do not wake.
    Idle,
}

/// `(outcome, scheduling)` pair returned by every state-changing API call.
pub type CallResult<T> = (T, NextCall);

/// Reasons the FR54 genesis bootstrap can be refused.
///
/// Story 1.4 surfaces `LocalNodeIdNotZero` (the FR54 caller-side
/// precondition), initial chain-config retention errors, and storage
/// persistence failure. Additional reasons
/// (`StorageNotEmpty`, broader `InvalidConfig`) arrive when Story 5.6+
/// enforces the full precondition set.
pub enum GenesisRejectReason {
    /// `local_node_id` was not `0`. Genesis is a node-zero-only operation
    /// (FR54).
    LocalNodeIdNotZero,
    /// `initial_chain_config_bytes` would not fit in the future Block #1
    /// chain-config payload.
    InitialChainConfigTooLarge,
    /// The initial chain-config payload has already been retained and must
    /// not be overwritten.
    InitialChainConfigAlreadyStored,
    /// Block #0 could not be persisted through the storage seam, so genesis
    /// must not report success.
    StorageSaveFailed,
}

/// Outcome of `Blockchain::initialize_genesis`.
///
/// Walking-skeleton (Story 1.4) scope: returns an **owned** [`Block`] for
/// Block #0. The architectural `BlockView<'a>` borrow form arrives once
/// `EmitScratch` exists (Story 4.3 / 8.3 per architecture §6.2).
pub enum InitGenesisOutcome {
    /// Genesis Block #0 was created and persisted. Caller should broadcast
    /// it; the next `on_tick(...)` will emit Block #1 (chain-config) per
    /// AR6 / decisions log #19.
    Created(Block),
    /// Genesis was refused; no `Blockchain` instance exists on this path.
    /// Currently unreachable from the success-path return — kept for
    /// forward-compatibility with Story 5.6+ when the precondition set
    /// expands. The `Result::Err` carries the actual refusal.
    #[allow(dead_code)]
    Rejected(GenesisRejectReason),
}

/// Authoritative-interpretation lifecycle phase (FR1–FR4).
///
/// - `Collecting`: empty chain or accumulating tree; query surfaces return
///   not-ready (FR1, FR14, FR42).
/// - `Processing`: full-chain reconstruction in progress (FR3).
/// - `Ready`: validated active chain; full intake/query surface available
///   (FR4, FR9 fully active).
// `PartialEq`/`Eq` are needed for lifecycle gate checks and phase-transition
// assertions in the planned state machine. Avoid Copy/Clone until a concrete
// later story needs value duplication beyond borrowing/matching.
#[derive(PartialEq, Eq)]
pub enum LifecyclePhase {
    Collecting,
    Processing,
    Ready,
}

/// Outcome of the internal FR9 Tier 1 admission entry point
/// [`Blockchain::tier1_admit`]. Story 4.3's `receive_block` intake surface
/// maps each variant to the single-outcome `ReceiveBlockOutcome`:
/// `Rejected(Tier1Failure)` → `Rejected(RejectReason)`, `AlreadyPresent` →
/// `DuplicateKnown`, success → `AcceptedSilently`. `TableFull` /
/// `StorageSaveFailed` are capacity/IO failures, not FR16 exact evidence —
/// their outcome mapping is Story 4.3/4.4's concern.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub(crate) enum AdmitError {
    /// FR16 exact evidence of invalidity — the block is not stored.
    Rejected(Tier1Failure),
    /// `(sequence, hash)` already in the block-tree (FR11). Not re-stored.
    AlreadyPresent,
    /// The bounded block-tree is at capacity (`MAX_BLOCKS`); no eviction path
    /// exists until Story 4.4 (FR19 chain_heads-eviction).
    TableFull,
    /// The block passed Tier 1 but could not be persisted through the storage
    /// seam — it is not inserted into the tree (storage-first admission).
    StorageSaveFailed,
}

/// Single-outcome classification returned by [`Blockchain::receive_block`]
/// (FR10; single-outcome scheduling-pull pattern, AR4). Exactly one variant is
/// produced per submitted block, and the response carries no descriptive
/// payload beyond the [`RejectReason`] discriminant (FR10 minimal-response
/// convention). Classification is deterministic in the block bytes + current
/// authoritative state and is independent of transport origin.
///
/// Epic 4 realizes the three terminal variants below. The `AcceptedAndSend*`
/// addendum variants of architecture §3.2 are a forward-tagged extension, each
/// added **with its payload type by its owning story**:
/// `AcceptedAndSendParentRecoveryRequest(ParentRecoveryRequest)` by Story 4.4
/// (FR19 missing parent), `AcceptedAndSendBlock(BlockView<'_>)` by Epic 8
/// (FR26 relay), and `AcceptedAndSendSupport(SupportView<'_>)` by Epic 6
/// (FR12 deviance support). The `ParentRecoveryRequest` variant is
/// non-borrowing (Story 4.4 adds it without a lifetime); the two borrowing
/// variants introduce the `<'a>` lifetime when they land.
// Same derive discipline as `AdmitError`/`LifecyclePhase`: no `Copy`/`Clone` in
// production (binary-size cost on embedded targets); `Debug` only under test.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum ReceiveBlockOutcome {
    /// FR11 — the block's `(sequence, block_hash)` is already in the retained
    /// block-tree; it is not re-stored and not re-advanced through FR9.
    DuplicateKnown,
    /// FR16 — the block passed Tier 1 and was stored at [`BlockStatus::Stored`];
    /// no addendum effect is produced in Epic 4.
    AcceptedSilently,
    /// FR16 / FR60 — the block was refused; see [`RejectReason`].
    Rejected(RejectReason),
}

/// Why a block was refused at intake. Per the FR10 minimal-response convention
/// the caller observes only this discriminant, never the granular
/// [`Tier1Failure`].
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum RejectReason {
    /// FR60 — outside the active `snake_chain` window (`S_new >= S_head + W` or
    /// `S_new < S_tail`). Ready-state only; never produced in collecting state.
    OutOfWindow,
    /// FR16 exact evidence of invalidity — any Story 4.2 Tier 1 gating failure,
    /// or the FR17 chain-config content mismatch. Not stored, not added to the
    /// tree, not advanced through FR9.
    InvalidEvidence,
    /// Operational refusal — the block could not be persisted or retained
    /// (`AdmitError::TableFull` before Story 4.4 eviction, or a storage-save
    /// failure). This is **not** an FR10 block-validity classification: the
    /// block may be perfectly valid but could not be stored. `TableFull`
    /// becomes unreachable once Story 4.4 `chain_heads` eviction lands.
    Unstorable,
}

/// Authoritative blockchain state for a MoonBlokz node.
///
/// Const generics define the compile-time-bounded memory model (AR9 /
/// architecture §5). No runtime allocation occurs at any point — every
/// internal buffer is sized from these parameters.
///
/// `Crypto`, `Storage`, and `Config` are the adjacent-component seams:
/// - `Crypto: CryptoTrait` — the module calls `crypto.sign` / `crypto.verify`
///   through the handle; it never holds raw signing-key bytes (FR68, AR13).
/// - `Storage: StorageTrait` — the module persists and reads state through
///   the trait; storage is a service it consumes (FR66 boundary).
/// - `Config: ChainConfigTrait` — chain-configurable parameters arrive via
///   the trait; the AR14 [`FixedChainConfig`](crate::FixedChainConfig) stub
///   satisfies it in MVP.
///
/// Defaults (architecture §5): `MAX_NODES = 1000`,
/// `SNAKE_CHAIN_LENGTH = 500`, `VERIFICATION_HORIZON = 20`,
/// `MAX_BLOCKS = 600`, `MAX_BRANCH_COUNT = 40`,
/// `MAX_BLOCK_UTXO_OUTPUT = 256`.
// Fields are consumed by the state-changing methods landing in Story 1.4+;
// silencing dead_code here keeps the scaffold clean.
#[allow(dead_code)]
pub struct Blockchain<
    Crypto: CryptoTrait,
    Storage: StorageTrait,
    Config: ChainConfigTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH: usize,
    const VERIFICATION_HORIZON: usize,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const MAX_BLOCK_UTXO_OUTPUT: usize,
> {
    // Adjacent-component handles (immutable construction inputs).
    crypto: Crypto,
    storage: Storage,
    chain_config: Config,

    // FR67 / FR69 / AR11 immutable construction inputs.
    local_node_id: u32,
    node_zero_public_key: [u8; PUBLIC_KEY_SIZE],
    prng: Prng,

    // FR1–FR4 lifecycle state. Default `Collecting`; transitions to
    // `Processing` then `Ready` land in Story 5.1–5.4.
    lifecycle_phase: LifecyclePhase,

    // FR18 bounded block-tree — data layer landed in Story 4.1.
    blocks: BlockTable<MAX_BLOCKS>,

    // Const-sized placeholders for future real bounded tables (Story 1.2).
    // `()` is zero-sized until the owning story replaces it with the real
    // entry layout (Story 4.4 / 7.1).
    _chain_heads: [(); MAX_BRANCH_COUNT],
    _node_info: [(); MAX_NODES],

    // Real snake-chain state is two block-table indices, not a W-sized
    // window. `SNAKE_CHAIN_LENGTH` remains an algorithmic bound for
    // maintaining the tail index relative to the active head.
    _active_chain_head_idx: u32,
    _snake_chain_tail_idx: u32,
    //
    // Deliberately no standalone placeholders for:
    // - `VERIFICATION_HORIZON`: cheap/deep-zone algorithm boundary only.
    // - `MAX_BLOCK_UTXO_OUTPUT`: NOT wired into `BlockEntry.spent_bits` sizing
    //   (Story 4.1 fixes that field at a 32-byte constant — see
    //   `blocks::SPENT_BITS_BYTES` — because deriving an array length from a
    //   generic const parameter via division requires the unstable
    //   `generic_const_exprs` feature). Epic 7 resolves this when it gives
    //   `spent_bits` real semantics.
}

impl<
    Crypto: CryptoTrait,
    Storage: StorageTrait,
    Config: ChainConfigTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH: usize,
    const VERIFICATION_HORIZON: usize,
    const MAX_BLOCKS: usize,
    const MAX_BRANCH_COUNT: usize,
    const MAX_BLOCK_UTXO_OUTPUT: usize,
>
    Blockchain<
        Crypto,
        Storage,
        Config,
        MAX_NODES,
        SNAKE_CHAIN_LENGTH,
        VERIFICATION_HORIZON,
        MAX_BLOCKS,
        MAX_BRANCH_COUNT,
        MAX_BLOCK_UTXO_OUTPUT,
    >
{
    /// Constructs a `Blockchain` with adjacent-component handles and
    /// construction-time init parameters (FR67, FR69, AR11).
    ///
    /// Parameters:
    /// - `crypto`/`storage`/`chain_config`: adjacent-component seam handles.
    ///   The module never receives raw signing-key bytes — only the `crypto`
    ///   handle (FR68 / AR13).
    /// - `local_node_id`: this node's canonical id on the active chain (FR67).
    /// - `node_zero_public_key`: node-zero trust anchor (FR69), sized via
    ///   `moonblokz_crypto::PUBLIC_KEY_SIZE` (backend-derived).
    /// - `prng_seed`: deterministic-replay PRNG root (AR11 / FR62 precondition).
    ///
    /// All init parameters are stored as immutable construction inputs; the
    /// module performs no internal wall-clock reads and no internal entropy
    /// source — callers must supply `now: u64` to every state-changing
    /// method (forthcoming in Story 1.4+).
    pub fn new(
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
            blocks: BlockTable::new(),
            _chain_heads: [(); MAX_BRANCH_COUNT],
            _node_info: [(); MAX_NODES],
            _active_chain_head_idx: 0,
            _snake_chain_tail_idx: 0,
        }
    }

    /// In-place construction for embedded/task use: writes directly into
    /// caller-provided `dst` instead of returning `Self` by value.
    ///
    /// `Self` is large (dominated by `blocks: BlockTable<MAX_BLOCKS>`, e.g.
    /// ~45.6 KB at the default `MAX_BLOCKS = 600`) — large enough that no
    /// construction technique *inside* a function that returns `Self` by
    /// value can avoid needing a full `size_of::<Self>()`-sized stack
    /// allocation somewhere (measured across several approaches: a
    /// struct-literal, and `MaybeUninit` + per-field pointer writes with
    /// and without an element-by-element large-array fill — all landed at
    /// the same floor). [`Self::new`] is fine for the desktop simulator
    /// (architecture §10 / FR62 — plain owned value, no `'static`/global
    /// state, and no tight stack budget there) and for tests.
    ///
    /// For embedded firmware, use this instead, from *inside* a
    /// `#[embassy_executor::task]` fn:
    ///
    /// ```ignore
    /// #[embassy_executor::task]
    /// async fn blockchain_task(/* ... */) {
    ///     let mut storage = core::mem::MaybeUninit::<BlockchainT>::uninit();
    ///     unsafe { BlockchainT::init_in_place(storage.as_mut_ptr(), /* ... */); }
    ///
    ///     // Load-bearing: `storage` must be referenced again after an
    ///     // `.await`, or the compiler has no reason to place it in the
    ///     // task's Future state rather than a transient local within
    ///     // this poll segment — measured to make the difference between
    ///     // ~66.6 KiB in the shared poll-time call stack and ~66.6 KiB in
    ///     // the task's own statically-sized `TaskStorage` instead
    ///     // (moonblokz-node round-7 stack investigation, Story 4.1
    ///     // deferred-work follow-up).
    ///     embassy_futures::yield_now().await;
    ///
    ///     let bc = unsafe { storage.assume_init_mut() };
    ///     // ... use `bc` ...
    /// }
    /// ```
    ///
    /// Declaring `storage` as a plain local of a synchronous function (or
    /// never crossing an `.await` while it's live) gets none of this
    /// benefit — the ~66.6 KB then sits in that function's own transient
    /// stack frame regardless of how carefully it's written.
    ///
    /// # Safety
    /// `dst` must be valid for writes of `Self` and not yet initialized.
    /// Every field is written exactly once; no field is read before its
    /// write; no panic can occur between the first write and the last.
    pub unsafe fn init_in_place(
        dst: *mut Self,
        crypto: Crypto,
        storage: Storage,
        chain_config: Config,
        local_node_id: u32,
        node_zero_public_key: [u8; PUBLIC_KEY_SIZE],
        prng_seed: u64,
    ) {
        unsafe {
            core::ptr::addr_of_mut!((*dst).crypto).write(crypto);
            core::ptr::addr_of_mut!((*dst).storage).write(storage);
            core::ptr::addr_of_mut!((*dst).chain_config).write(chain_config);
            core::ptr::addr_of_mut!((*dst).local_node_id).write(local_node_id);
            core::ptr::addr_of_mut!((*dst).node_zero_public_key).write(node_zero_public_key);
            core::ptr::addr_of_mut!((*dst).prng).write(Prng::new(prng_seed));
            core::ptr::addr_of_mut!((*dst).lifecycle_phase).write(LifecyclePhase::Collecting);
            let blocks_ptr = core::ptr::addr_of_mut!((*dst).blocks);
            BlockTable::init_in_place(blocks_ptr);
            core::ptr::addr_of_mut!((*dst)._chain_heads).write([(); MAX_BRANCH_COUNT]);
            core::ptr::addr_of_mut!((*dst)._node_info).write([(); MAX_NODES]);
            core::ptr::addr_of_mut!((*dst)._active_chain_head_idx).write(0);
            core::ptr::addr_of_mut!((*dst)._snake_chain_tail_idx).write(0);
        }
    }

    /// FR54 genesis bootstrap. Constructs the `Blockchain`, builds genesis
    /// Block #0 (node-zero registration + initial self-transfer), persists
    /// it through the storage seam, and returns the immediate-callback
    /// `NextCall::At(now)` so the bridge will call `on_tick(...)` to emit
    /// Block #1 (chain-config) per AR6.
    ///
    /// Refusal: returns `Err(GenesisRejectReason::LocalNodeIdNotZero)` if
    /// `local_node_id != 0` (FR54 caller-side precondition). No
    /// `Blockchain` instance is constructed on the refusal path.
    ///
    /// **Walking-skeleton scope (Story 1.4).** The Block #0 layout is
    /// minimum-buildable: registration + self-transfer per FR54. The block
    /// and bootstrap transactions are finalized through chain-types signed
    /// builders; full canonical validation still lands in Stories 4.2 / 5.4 /
    /// 5.6. The `initial_chain_config_bytes` parameter is retained by the
    /// `chain_config` seam for the later Block #1 emission; validation and
    /// durable-lock semantics land in Story 5.6.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize_genesis(
        crypto: Crypto,
        storage: Storage,
        mut chain_config: Config,
        local_node_id: u32,
        initial_total_network_currency: u64,
        initial_chain_config_bytes: &[u8],
        prng_seed: u64,
        now: u64,
    ) -> Result<(Self, InitGenesisOutcome, NextCall), GenesisRejectReason> {
        if local_node_id != 0 {
            return Err(GenesisRejectReason::LocalNodeIdNotZero);
        }
        let node_zero_public_key = *crypto.public_key().serialize();
        chain_config
            .store_initial_chain_config_bytes(initial_chain_config_bytes)
            .map_err(|err| match err {
                ChainConfigError::InitialChainConfigTooLarge => {
                    GenesisRejectReason::InitialChainConfigTooLarge
                }
                ChainConfigError::InitialChainConfigAlreadyStored => {
                    GenesisRejectReason::InitialChainConfigAlreadyStored
                }
            })?;

        // Assemble signed Block #0: registration of node #0 + a self-transfer
        // of the initial total network currency.
        let registration = Registration::new_signed(
            0, // vote
            0, // initializer (node #0)
            0, // new_node_id (node #0)
            0, // registration_price
            0, // fee
            &node_zero_public_key,
            &crypto,
        );
        let self_transfer = NodeTransfer::new_signed(
            0, // vote
            0, // anchor_sequence
            0, // initializer (node #0)
            0, // receiver (self)
            initial_total_network_currency,
            0, // fee
            0, // comment
            &crypto,
        );

        let header = BlockHeader {
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
            // full canonical block bytes with this field zero-filled, then
            // stores the generated signature here.
            signature: [0u8; 64],
        };

        // The chain-types builder errors only on payload-type mismatch or
        // capacity overflow — neither applies to two small bootstrap
        // transactions. The walking-skeleton uses `unreachable!` to make the
        // invariant explicit; Story 5.6+ may surface BlockError through a
        // new InitGenesisOutcome::Rejected variant when the assembly grows.
        let mut builder = BlockBuilder::new().header(header);
        if builder.add_registration(&registration).is_err() {
            unreachable!("Block #0 registration is fixed-size and cannot overflow payload");
        }
        if builder.add_node_transfer(&self_transfer).is_err() {
            unreachable!("Block #0 self-transfer is fixed-size and cannot overflow payload");
        }
        let block_0 = match builder.build_signed(&crypto) {
            Ok(b) => b,
            Err(_) => unreachable!("Block #0 header.version = 1 and payload fits MAX_BLOCK_SIZE"),
        };

        let mut bc = Self::new(
            crypto,
            storage,
            chain_config,
            local_node_id,
            node_zero_public_key,
            prng_seed,
        );

        // Exercise the storage seam end-to-end. If persistence fails, do not
        // return a `Created` outcome: the caller must not broadcast a Block #0
        // that this node failed to retain locally.
        bc.storage
            .save_block(0, &block_0)
            .map_err(|_| GenesisRejectReason::StorageSaveFailed)?;

        Ok((bc, InitGenesisOutcome::Created(block_0), NextCall::At(now)))
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

    /// Read-only query — returns the local node id (FR67).
    pub fn local_node_id(&self) -> u32 {
        self.local_node_id
    }

    /// FR9 Tier 1 admission (Story 4.2). Rejects a block whose `(sequence, hash)`
    /// is already in the tree as `AlreadyPresent` first, then runs the full
    /// Tier 1 gating check set over `block`; on pass, persists the block through
    /// the storage seam and inserts it into the block-tree at
    /// [`BlockStatus::Stored`], returning its storage/tree index. On any
    /// exact-evidence failure the block is neither persisted nor inserted, and
    /// the failing [`Tier1Failure`] is returned.
    ///
    /// This is the internal entry point Story 4.3's `receive_block` intake
    /// surface will call; it deliberately stops at "Tier 1 verdict + Stored
    /// admission." The single-outcome `ReceiveBlockOutcome` mapping, the
    /// collecting-vs-ready FR60 window logic, the FR11 duplicate-classification
    /// *outcome*, and the FR17 chain-config silent-discard are Story 4.3.
    ///
    /// **Collecting-state invariant (AC4):** every admitted block is `Stored`
    /// — no Connected/Active is assigned, because no active chain exists and no
    /// promotion driver runs in Epic 4.
    ///
    /// **Duplicate-first ordering (FR11 / FR10):** the `(sequence, hash)` guard
    /// runs *before* Tier 1, so a re-arriving already-stored block is rejected
    /// as `AlreadyPresent` without re-running signature verification — a purely
    /// structural check (a stored block already passed Tier 1, and an identical
    /// hash means identical bytes, so the verdict cannot differ). This — not a
    /// signature-verification cache — is what keeps the dominant mesh-rebroadcast
    /// re-arrival case off the crypto path. (Story 4.3's `receive_block` is the
    /// authoritative FR11 duplicate classifier; this guard makes `tier1_admit`
    /// cheap and robust on its own, independent of the caller.)
    ///
    /// **Storage-first ordering:** the block is saved to durable storage at the
    /// slot [`BlockTable::insert`] will choose *before* the tree is mutated, so
    /// a storage failure leaves the tree untouched (there is no deletion path
    /// to roll back a tree insert until Story 4.4).
    ///
    /// **Parent linkage is deferred to Story 4.4:** the entry is inserted with
    /// an unresolved parent (`NONE_REF`). Resolving `previous_hash` to a parent
    /// index (and FR19 parent-recovery for a missing parent) is Story 4.4's
    /// `chain_heads` work — this crate has no find-by-hash yet.
    pub(crate) fn tier1_admit(&mut self, block: &BlockView) -> Result<u32, AdmitError> {
        // Duplicate-first (FR11 / FR10): reject an already-stored (sequence, hash)
        // before any Tier 1 crypto. A stored block already passed Tier 1, and an
        // identical hash means identical bytes, so re-verification could only
        // reach the same verdict — skipping it is safe and keeps mesh-rebroadcast
        // re-arrivals off the signature-verification path (the reason this story
        // needs no signature-verification cache).
        let hash = block.hash();
        if self.blocks.find(block.sequence(), &hash).is_some() {
            return Err(AdmitError::AlreadyPresent);
        }

        let block_size_limit = self.chain_config.current_block_size_limit();
        tier1_gate(
            block,
            &self.node_zero_public_key,
            block_size_limit,
            &self.crypto,
        )
        .map_err(AdmitError::Rejected)?;

        // Storage-first: reserve the slot `insert` will pick, persist there,
        // then insert. Reconstruct an owned `Block` for the storage seam
        // (`save_block` takes `&Block`); this copy happens only on the success
        // path, after Tier 1 passed.
        let idx = self.blocks.next_free_index().ok_or(AdmitError::TableFull)?;
        let owned = Block::from_bytes(block.serialized_bytes())
            .map_err(|_| AdmitError::Rejected(Tier1Failure::MalformedPayload))?;
        self.storage
            .save_block(idx, &owned)
            .map_err(|_| AdmitError::StorageSaveFailed)?;

        let mut entry = BlockEntry::new(hash, NONE_REF, block.sequence());
        entry.set_status(BlockStatus::Stored);
        match self.blocks.insert(entry) {
            Ok(inserted) => {
                debug_assert_eq!(inserted, idx, "storage-first slot must match insert slot");
                Ok(inserted)
            }
            Err(BlockTableError::Full) => Err(AdmitError::TableFull),
            Err(BlockTableError::DuplicateEntry) => Err(AdmitError::AlreadyPresent),
            Err(BlockTableError::ReservedSequence) => {
                // Unreachable: `tier1_gate` already rejects sequence == u32::MAX
                // (FR53 (ii)) before we get here.
                Err(AdmitError::Rejected(Tier1Failure::SequenceCeiling))
            }
        }
    }

    /// FR10 block-intake surface (Story 4.3). Classifies a submitted block into
    /// exactly one [`ReceiveBlockOutcome`] (single-outcome scheduling-pull, AR4)
    /// and pairs it with a [`NextCall`]. Classification is deterministic in the
    /// block bytes + current authoritative state and independent of transport
    /// origin (there is no origin parameter). Delegates to the stateless
    /// [`crate::intake::classify_block`] dispatcher (FR11 dedup → FR60 window →
    /// FR17 chain-config → Story 4.2 Tier 1).
    ///
    /// Epic 4 always returns [`NextCall::Idle`] — no follow-up work is queued.
    /// Story 4.4 returns `NextCall::At(now)` when the classification queues an
    /// FR19 parent-recovery request. `now` is threaded for that forward use.
    pub fn receive_block(
        &mut self,
        block: BlockView<'_>,
        now: u64,
    ) -> CallResult<ReceiveBlockOutcome> {
        let window = self.active_snake_chain_window();
        let outcome = classify_block(self, &block, window, now);
        (outcome, NextCall::Idle)
    }

    /// The current active-chain `(S_tail, S_head)` sequence bounds, or `None`
    /// in collecting state (which suppresses the FR60 window check + its
    /// `long-disconnect-detected` log per AC7).
    ///
    /// Epic 4 is collecting-only: there is no lifecycle machine (Epic 5) and no
    /// snake-chain head/tail state (Epic 9), so this returns `None`
    /// unconditionally. Epic 5 will gate it on `lifecycle_phase == Ready`; Epic 9
    /// (`snake_chain.rs`) will derive `(S_tail, S_head)` from the
    /// `_snake_chain_tail_idx` / `_active_chain_head_idx` block-table indices.
    fn active_snake_chain_window(&self) -> Option<(u32, u32)> {
        None
    }

    /// FR11 duplicate-index probe used by the intake dispatcher: `true` iff a
    /// block with this `(sequence, hash)` is already in the block-tree.
    pub(crate) fn block_tree_contains(&self, sequence: u32, hash: &[u8; 32]) -> bool {
        self.blocks.find(sequence, hash).is_some()
    }

    /// Number of blocks currently retained in the block-tree. Test-only
    /// accessor for the `intake.rs` tests (a separate module cannot reach the
    /// private `blocks` field); `api.rs`'s own tests read `self.blocks.len()`.
    #[cfg(test)]
    pub(crate) fn block_tree_len(&self) -> usize {
        self.blocks.len()
    }

    /// FR8 durable-lock state of the chain-config (via the FR56 seam).
    pub(crate) fn is_chain_config_durable_locked(&self) -> bool {
        self.chain_config.is_durable_locked()
    }

    /// The durable-locked chain-config payload bytes, if any have been retained
    /// (the FR17 content-mismatch comparand). `None` before genesis retention.
    pub(crate) fn locked_chain_config_bytes(&self) -> Option<&[u8]> {
        self.chain_config.initial_chain_config_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_config::{
        ChainConfigTrait, FixedChainConfig, INITIAL_CHAIN_CONFIG_BYTES_CAPACITY,
    };
    use moonblokz_chain_types::MAX_BLOCK_SIZE;
    use moonblokz_crypto::{Crypto, PRIVATE_KEY_SIZE};
    use moonblokz_storage::backend_memory::MemoryBackend;

    fn any_nonzero(bytes: &[u8]) -> bool {
        bytes.iter().any(|value| *value != 0)
    }

    /// Helper: construct a (Crypto, MemoryBackend, FixedChainConfig) triple
    /// for the walking-skeleton tests. Uses real backends so the trait-bound
    /// seam is exercised end-to-end.
    fn test_backends() -> (
        Crypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        FixedChainConfig,
    ) {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let crypto = Crypto::new(private_key)
            .ok()
            .expect("test private key should be accepted by the backend");
        let storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
        let chain_config = FixedChainConfig::new();
        (crypto, storage, chain_config)
    }

    /// `init_in_place`'s `unsafe` per-field writes (out-param signature,
    /// `blocks` filled element-by-element via `BlockTable::init_in_place`)
    /// must produce a struct indistinguishable from `new()`'s — a wrong
    /// field order, a skipped field, or an off-by-one in the `unsafe`
    /// block would silently corrupt memory rather than panic, so this is
    /// verified directly rather than trusted by construction.
    #[test]
    fn init_in_place_matches_new() {
        let (crypto_a, storage_a, chain_config_a) = test_backends();
        let a = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::new(
            crypto_a,
            storage_a,
            chain_config_a,
            7,
            [3u8; PUBLIC_KEY_SIZE],
            0xDEAD_BEEF,
        );

        let (crypto_b, storage_b, chain_config_b) = test_backends();
        let mut result =
            core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 4, 16, 4, 16>>::uninit();
        let b = unsafe {
            Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::init_in_place(
                result.as_mut_ptr(),
                crypto_b,
                storage_b,
                chain_config_b,
                7,
                [3u8; PUBLIC_KEY_SIZE],
                0xDEAD_BEEF,
            );
            result.assume_init()
        };

        assert_eq!(a.local_node_id(), b.local_node_id());
        assert!(a.current_phase() == LifecyclePhase::Collecting);
        assert!(b.current_phase() == LifecyclePhase::Collecting);
        assert_eq!(a.blocks.len(), b.blocks.len());
        assert_eq!(a.blocks.len(), 0);
        assert_eq!(a.node_zero_public_key, b.node_zero_public_key);
    }

    /// AC1, AC4, AC5 — successful genesis bootstrap on `local_node_id == 0`
    /// yields Block #0 + `NextCall::At(now)` (immediate callback for the
    /// later Block #1 step), no embassy deps anywhere in the harness.
    #[test]
    fn walking_skeleton_genesis_success() {
        let (crypto, storage, chain_config) = test_backends();
        let expected_node_zero_public_key = *crypto.public_key().serialize();
        let now: u64 = 12_345;
        let initial_chain_config_bytes = [0xC0, 0xA5, 0xF6, 0x01];

        let result = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::initialize_genesis(
            crypto,
            storage,
            chain_config,
            0,                           // local_node_id
            1_000_000_000,               // initial_total_network_currency
            &initial_chain_config_bytes, // retained for the later Block #1 emit
            0xDEAD_BEEF_CAFE_F00D,
            now,
        );

        match result {
            Ok((bc, InitGenesisOutcome::Created(block), NextCall::At(t))) => {
                assert_eq!(block.sequence(), 0);
                assert_eq!(block.creator(), 0);
                assert_eq!(block.version(), 1);
                assert_eq!(block.payload_type(), PAYLOAD_TYPE_TRANSACTION);
                assert!(any_nonzero(block.signature()), "Block #0 must be signed");
                let mut transactions = block
                    .transactions()
                    .expect("genesis Block #0 should contain transaction payload")
                    .iter();
                let registration = transactions
                    .next()
                    .expect("first genesis transaction should register node #0")
                    .as_registration()
                    .expect("first genesis transaction should be Registration");
                assert_eq!(
                    registration.new_public_key(),
                    &expected_node_zero_public_key
                );
                assert!(any_nonzero(registration.new_key_signature()));
                assert!(any_nonzero(registration.signature()));
                let self_transfer = transactions
                    .next()
                    .expect("second genesis transaction should seed node #0 balance")
                    .as_node_transfer()
                    .expect("second genesis transaction should be NodeTransfer");
                assert!(any_nonzero(self_transfer.signature()));
                assert!(transactions.next().is_none());
                assert_eq!(t, now, "Block #1 needs an immediate-callback tick (AR6)");
                assert_eq!(
                    bc.chain_config.initial_chain_config_bytes(),
                    Some(&initial_chain_config_bytes[..])
                );
                assert!(bc.current_phase() == LifecyclePhase::Collecting);
                assert_eq!(bc.local_node_id(), 0);
            }
            Ok((_, InitGenesisOutcome::Rejected(_), _)) => {
                panic!("walking-skeleton success path should not return Rejected outcome");
            }
            Ok((_, _, NextCall::Idle)) => {
                panic!("genesis must schedule the Block #1 callback (AR6)");
            }
            Err(_) => panic!("genesis with local_node_id == 0 must succeed (FR54)"),
        }
    }

    /// AC2 — `local_node_id != 0` refuses genesis; no `Blockchain` is
    /// constructed. The `Err(_)` arm is forward-compat for the additional
    /// `GenesisRejectReason` variants Story 5.6+ introduces.
    #[allow(unreachable_patterns)]
    #[test]
    fn walking_skeleton_refuses_non_zero_local_node_id() {
        let (crypto, storage, chain_config) = test_backends();

        let result = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::initialize_genesis(
            crypto,
            storage,
            chain_config,
            1, // local_node_id != 0 → refusal
            1_000_000_000,
            &[],
            0,
            0,
        );

        match result {
            Err(GenesisRejectReason::LocalNodeIdNotZero) => {}
            Err(_) => panic!("expected LocalNodeIdNotZero refusal"),
            Ok(_) => panic!("FR54 precondition must refuse local_node_id != 0"),
        }
    }

    /// Oversized genesis chain-config bytes are rejected before a `Blockchain`
    /// instance is constructed; the bounded retention lives in `chain_config.rs`.
    #[test]
    fn walking_skeleton_rejects_oversized_initial_chain_config() {
        let (crypto, storage, chain_config) = test_backends();
        let oversized = [0u8; INITIAL_CHAIN_CONFIG_BYTES_CAPACITY + 1];

        let result = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::initialize_genesis(
            crypto,
            storage,
            chain_config,
            0,
            1_000_000_000,
            &oversized,
            0,
            0,
        );

        match result {
            Err(GenesisRejectReason::InitialChainConfigTooLarge) => {}
            Err(_) => panic!("expected InitialChainConfigTooLarge refusal"),
            Ok(_) => panic!("oversized initial chain-config bytes must be refused"),
        }
    }

    /// Already-retained initial chain-config bytes are not overwritten during
    /// genesis setup.
    #[test]
    fn walking_skeleton_rejects_already_stored_initial_chain_config() {
        let (crypto, storage, mut chain_config) = test_backends();
        chain_config
            .store_initial_chain_config_bytes(&[0x01, 0x02])
            .unwrap();

        let result = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::initialize_genesis(
            crypto,
            storage,
            chain_config,
            0,
            1_000_000_000,
            &[0x03, 0x04],
            0,
            0,
        );

        match result {
            Err(GenesisRejectReason::InitialChainConfigAlreadyStored) => {}
            Err(_) => panic!("expected InitialChainConfigAlreadyStored refusal"),
            Ok(_) => panic!("genesis must not overwrite retained chain-config bytes"),
        }
    }

    /// Storage persistence failure refuses genesis; no `Created` outcome is
    /// returned when Block #0 cannot be retained locally.
    #[test]
    fn walking_skeleton_refuses_storage_save_failure() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let crypto = Crypto::new(private_key)
            .ok()
            .expect("test private key should be accepted by the backend");
        let storage = MemoryBackend::<0>::new();
        let chain_config = FixedChainConfig::new();

        let result = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::initialize_genesis(
            crypto,
            storage,
            chain_config,
            0,
            1_000_000_000,
            &[],
            0,
            0,
        );

        match result {
            Err(GenesisRejectReason::StorageSaveFailed) => {}
            Err(_) => panic!("expected StorageSaveFailed refusal"),
            Ok(_) => panic!("genesis must not succeed when Block #0 cannot be persisted"),
        }
    }

    /// AC3 — read-only queries are typed to **not** carry `NextCall`.
    /// This is a compile-time guarantee: `current_phase` returns
    /// `LifecyclePhase` directly (not `CallResult<LifecyclePhase>`), and
    /// `local_node_id` returns `u32` directly.
    #[test]
    fn walking_skeleton_query_carries_no_next_call() {
        let (crypto, storage, chain_config) = test_backends();

        let (bc, _, _) = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::initialize_genesis(
            crypto,
            storage,
            chain_config,
            0,
            1_000_000_000,
            &[],
            0,
            0,
        )
        .ok()
        .expect("genesis must succeed for local_node_id == 0");

        // Type-level assertion: the query result is `LifecyclePhase`,
        // not `(LifecyclePhase, NextCall)`. If the signature ever drifts
        // back to `CallResult`, this annotation will fail to compile.
        let phase: LifecyclePhase = bc.current_phase();
        assert!(phase == LifecyclePhase::Collecting);

        let node_id: u32 = bc.local_node_id();
        assert_eq!(node_id, 0);
    }

    // --- Story 4.2: FR9 Tier 1 admission entry point ------------------------

    type TestChain = Blockchain<
        Crypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        FixedChainConfig,
        16,
        16,
        4,
        16,
        4,
        16,
    >;

    fn new_test_chain() -> TestChain {
        let (crypto, storage, chain_config) = test_backends();
        let node_zero = *crypto.public_key().serialize();
        Blockchain::new(crypto, storage, chain_config, 5, node_zero, 0)
    }

    fn node_transfer_block(seq: u32, vote: u32, anchor: u32, initializer: u32) -> Block {
        // The block-creator signature is not a Tier 1 gate in Epic 4
        // (opportunistic / ready-state), so any signer works for these tests.
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let nt = NodeTransfer::new_signed(vote, anchor, initializer, 9, 100, 1, 0, &signer);
        let header = BlockHeader {
            version: 1,
            sequence: seq,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_TRANSACTION,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: [0u8; 32],
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        builder
            .add_node_transfer(&nt)
            .ok()
            .expect("add node transfer");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// AC4: a Tier 1-passing block is admitted at `Stored` and persisted.
    #[test]
    fn tier1_admit_inserts_at_stored() {
        let mut bc = new_test_chain();
        let block = node_transfer_block(5, 3, 4, 7);
        let idx = bc
            .tier1_admit(&block.view())
            .expect("well-formed block is admitted");
        assert_eq!(bc.blocks.len(), 1);
        assert_eq!(
            bc.blocks.get(idx).expect("entry present").status(),
            BlockStatus::Stored,
            "collecting-state admission is always Stored (AC4)"
        );
        // Durable storage received the block (storage-first admission).
        assert!(bc.storage.read_block(idx).is_ok());
    }

    /// AC5: a Tier 1 failure returns the exact-evidence form and stores nothing.
    #[test]
    fn tier1_admit_rejects_and_does_not_store() {
        let mut bc = new_test_chain();
        // initializer == vote == 7 → FR6 self-vote.
        let block = node_transfer_block(5, 7, 4, 7);
        let result = bc.tier1_admit(&block.view());
        assert_eq!(result, Err(AdmitError::Rejected(Tier1Failure::SelfVote)));
        assert_eq!(bc.blocks.len(), 0, "a rejected block must not be stored");
    }

    /// FR11 defensive guard: re-admitting an identical block reports it as
    /// already present rather than double-storing it.
    #[test]
    fn tier1_admit_duplicate_is_already_present() {
        let mut bc = new_test_chain();
        let block = node_transfer_block(5, 3, 4, 7);
        bc.tier1_admit(&block.view()).expect("first admission");
        let second = bc.tier1_admit(&block.view());
        assert_eq!(second, Err(AdmitError::AlreadyPresent));
        assert_eq!(bc.blocks.len(), 1, "duplicate must not be re-stored");
    }
}
