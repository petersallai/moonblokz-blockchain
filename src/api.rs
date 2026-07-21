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
//! construction and `now: u64` to every time-dependent state-changing method
//! (forthcoming); the one-shot `process_genesis` bootstrap schedules nothing and
//! takes no timestamp. The same construction inputs + the same event sequence
//! therefore yield identical state (FR62 / FR63 precondition).

use moonblokz_chain_types::{
    Block, BlockBuilder, BlockHeader, BlockView, NodeTransfer, PAYLOAD_TYPE_CHAIN_CONFIG,
    PAYLOAD_TYPE_TRANSACTION, Registration, TransactionView,
};
use moonblokz_crypto::{CryptoTrait, PUBLIC_KEY_SIZE, PublicKeyTrait};
use moonblokz_storage::StorageTrait;

use crate::blocks::{BlockEntry, BlockTable, NONE_REF};
use crate::chain_config::{ChainConfigError, ChainConfigTrait};
use crate::chain_heads::ChainHeadsTable;
use crate::intake::classify_block;
use crate::lifecycle::is_legal_transition;
use crate::prng::Prng;
use crate::staged_validation::{BlockStatus, Tier1Failure, tier1_gate};

// `LifecyclePhase` is owned by `lifecycle.rs` (architecture §4.2) and
// re-exported here so the crate's public surface (`api::LifecyclePhase`, and in
// turn `moonblokz_blockchain::LifecyclePhase`) is unchanged after Story 5.1
// relocated the enum out of this module.
pub use crate::lifecycle::LifecyclePhase;

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
/// precondition), `StorageNotEmpty` (genesis is only valid on a fresh chain),
/// initial chain-config retention errors, and storage persistence failure.
/// The broader `InvalidConfig` precondition and full persisted-storage
/// emptiness detection on reboot arrive when Story 5.6+ enforces the complete
/// precondition set.
pub enum GenesisRejectReason {
    /// `local_node_id` was not `0`. Genesis is a node-zero-only operation
    /// (FR54).
    LocalNodeIdNotZero,
    /// The chain is not empty: this instance has already been bootstrapped
    /// (Block #0 present, or the initial chain-config already retained), so
    /// genesis must not run again and overwrite it. Walking-skeleton scope
    /// checks the in-memory chain state; detecting a non-empty *persisted*
    /// store on reboot is Story 5.6.
    StorageNotEmpty,
    /// `initial_chain_config_bytes` would not fit in the Block #1
    /// chain-config payload.
    InitialChainConfigTooLarge,
    /// The initial chain-config payload has already been retained and must
    /// not be overwritten.
    InitialChainConfigAlreadyStored,
    /// Block #0 or Block #1 could not be persisted through the storage seam,
    /// so genesis must not report success.
    StorageSaveFailed,
}

/// The two genesis blocks produced by [`Blockchain::process_genesis`], created
/// and persisted in a single call. The caller broadcasts both over the radio,
/// lowest-sequence first.
///
/// - `block_zero` — node-#0 registration + initial self-transfer (FR54).
/// - `block_one` — the chain-config block carrying `initial_chain_config_bytes`,
///   `previous_hash` chained to `block_zero`.
///
/// Refusal is carried by the `Err(GenesisRejectReason)` half of
/// `process_genesis`'s `Result`, so there is no `Rejected` variant here — this
/// is a plain product of the two success blocks, not a single-outcome enum.
///
/// Walking-skeleton (Story 1.4) scope: **owned** [`Block`] values. The
/// architectural `BlockView<'a>` borrow form arrives once `EmitScratch` exists
/// (Story 4.3 / 8.3 per architecture §6.2).
pub struct GenesisBlocks {
    pub block_zero: Block,
    pub block_one: Block,
}

/// Outcome of the join/restart init follow-up [`Blockchain::initialize_from_storage`].
///
/// A node is constructed once via the single `unsafe` [`Blockchain::init_in_place`]
/// (which lands it in `Collecting` with an empty tree) and then reads durable
/// storage through this **safe** follow-up — the split keeps the `unsafe`
/// raw-pointer construction isolated from the safe storage-reading business
/// logic (architecture §3.6 "in-place constructor + role-specific follow-up").
///
/// Story 5.1 realizes only the empty-storage (fresh-join) outcome
/// `StartedCollecting`. The restart-from-durable-blocks path — read the retained
/// blocks, rebuild the tree, evaluate FR2, run the FR3 pass — and its
/// `ResumedProcessing` / `ResumedReady` / `Rejected(_)` outcomes land in
/// **Story 5.7 (FR59)**, which fills the non-empty branch and adds those arms.
/// (Minimal now, extended then: no dead arm ships early — the crate's
/// declare-and-tag-forward discipline.)
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum InitOutcome {
    /// Storage held no blocks (fresh join): the node stays in `Collecting` as a
    /// pure receiver and acquires the chain from the mesh (FR1).
    StartedCollecting,
}

/// Not-ready result of the FR14/FR10 transaction-intake entry point
/// [`Blockchain::receive_transaction`] while the node is not `Ready`.
///
/// Story 5.1 builds only the not-ready gate (FR1: transaction intake is
/// ready-only). The ready-state classification set (`AcceptedToMempool`,
/// `AlreadyConfirmed`, `DuplicateInMempool`, `Deferred`, `Rejected`) is added by
/// **Epic 7** when it builds the body (FR14).
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum ReceiveTransactionOutcome {
    /// FR1 — the module is not in `Ready`; no classification is performed.
    NotReady,
}

/// Not-ready result of the FR55 local transaction-creation surface
/// [`Blockchain::submit_local_transaction`] while the node is not `Ready`.
///
/// Story 5.1 builds only the not-ready gate. FR55's `Created` / `Held(reason)` /
/// `Rejected(reason)` outcomes are added by **Epic 10** when it builds the body
/// (`NotReady` is FR55's mandated `Rejected(not-ready)` case).
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum LocalTransactionOutcome {
    /// FR1/FR55 — the module is not in `Ready`; the transaction is not created.
    NotReady,
}

/// Why a value/balance query [`Blockchain::query_balance`] returned no value.
///
/// A `Result` (not `Option`) so `NotReady` stays distinct from the domain
/// "absent" case: **Epic 10** adds `UnknownNode` (node not in the roster) when
/// it builds the ready-state body — neither may be conflated with a legitimate
/// zero balance (FR41).
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum BalanceQueryError {
    /// FR1 — the module is not in `Ready`; value state does not exist yet.
    NotReady,
}

/// Why a block-retrieval query ([`Blockchain::serve_block_by_hash`] /
/// [`Blockchain::serve_block_by_sequence`]) returned no block.
///
/// A `Result` (not `Option`) so `NotReady` (FR42: block-retrieval is ready-only)
/// stays distinct from the domain "absent" case: **Epic 10** adds `NotFound`
/// when it builds the ready-state body.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum BlockQueryError {
    /// FR1/FR42 — the module is not in `Ready`; block-retrieval is not served.
    NotReady,
}

/// FR40 transaction-state query result: the three states FR40 fixes. The
/// ready-state lookup that produces `InMempool`/`Confirmed`/`Unknown` is
/// **Epic 10**; the value type is defined here so the gated query can be typed.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum TransactionState {
    /// Not known to the module (neither in the mempool nor confirmed on-chain).
    Unknown,
    /// Present in the mempool but not yet confirmed on the active chain.
    InMempool,
    /// Confirmed on the active chain.
    Confirmed,
}

/// Why a transaction-state query [`Blockchain::query_transaction_state`]
/// returned no value. `NotReady` now (FR1/FR40); Epic 10 adds any domain arms.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum TxStateQueryError {
    /// FR1/FR40 — the module is not in `Ready`; transaction state is unavailable.
    NotReady,
}

/// FR44 creator-role determination result: the binary determination FR44
/// defines (local node vs. the top of the creator-order projection). The
/// ready-state comparison against the FR38 creator-order is **Epic 8**.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum CreatorRole {
    /// The local node is the currently expected block creator (FR44/FR45).
    LocalIsCurrentCreator,
    /// The local node is not the currently expected block creator.
    LocalIsNotCurrentCreator,
}

/// Why a creator-role query [`Blockchain::creator_role`] returned no value.
/// `NotReady` now (FR1/FR44); Epic 8 builds the ready-state determination.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum CreatorQueryError {
    /// FR1/FR44 — the module is not in `Ready`; creator-order does not exist yet.
    NotReady,
}

/// Outcome of the internal FR9 Tier 1 admission entry point
/// [`Blockchain::tier1_admit`]. Story 4.3's `receive_block` intake surface
/// maps each variant to the single-outcome `ReceiveBlockOutcome`:
/// `Rejected(Tier1Failure)` → `Rejected(RejectReason)`, success →
/// `AcceptedSilently`. `TableFull` / `StorageSaveFailed` are capacity/IO
/// failures, not FR16 exact evidence — mapped to `Rejected(Unstorable)`.
/// There is no `AlreadyPresent`: FR11 de-duplication is owned by the intake
/// dispatcher (`classify_block`) which classifies a known block as
/// `DuplicateKnown` *before* calling `tier1_admit`, so admission never sees a
/// duplicate.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub(crate) enum AdmitError {
    /// FR16 exact evidence of invalidity — the block is not stored.
    Rejected(Tier1Failure),
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
/// `AcceptedAndSendBlock(BlockView<'_>)` by Epic 8 (FR26 relay) and
/// `AcceptedAndSendSupport(SupportView<'_>)` by Epic 6 (FR12 deviance support);
/// these borrowing variants introduce the `<'a>` lifetime when they land.
///
/// **FR19 parent recovery is emitted from the tick, not here.** The architecture
/// §3.2 sketch also lists `AcceptedAndSendParentRecoveryRequest`, and Story 4.3
/// forward-tagged it to Story 4.4 — but per FR19/FR46 a parent-recovery request
/// is a *scheduler* effect gated by the FR46 global emit cooldown, so Story 4.4
/// emits it from [`Blockchain::on_tick`] as [`TickOutcome::SendParentRecoveryRequest`],
/// and `receive_block` that creates/retains a Stored head returns
/// `(AcceptedSilently, NextCall::At(next tick))` instead. This variant is
/// therefore **not** added to `ReceiveBlockOutcome` (it would never be emitted).
/// See the Story 4.4 "Emission surface" Dev Note.
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

/// FR19 parent-recovery request payload — the outbound message the module asks
/// the radio layer to send when a Stored head's tail-point parent is missing.
///
/// Non-borrowing owned struct (architecture §3.2): it carries the missing
/// parent's hash and the *claimed* parent sequence (`tail_point.sequence − 1`),
/// so the radio layer / peers can locate and return the block. Emitted by
/// [`Blockchain::on_tick`] as [`TickOutcome::SendParentRecoveryRequest`] — the
/// FR46 scheduler surface, **not** inline from `receive_block` (the FR46 global
/// emit cooldown is a tick concept; see the Story 4.4 "Emission surface" note).
// Same derive discipline as the outcome enums: no `Copy`/`Clone` in production;
// `Debug` only under test.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub struct ParentRecoveryRequest {
    missing_parent_hash: [u8; 32],
    claimed_parent_sequence: u32,
}

impl ParentRecoveryRequest {
    pub(crate) fn new(missing_parent_hash: [u8; 32], claimed_parent_sequence: u32) -> Self {
        Self {
            missing_parent_hash,
            claimed_parent_sequence,
        }
    }

    /// The hash of the missing parent block (the tail-point's `previous_hash`).
    pub fn missing_parent_hash(&self) -> &[u8; 32] {
        &self.missing_parent_hash
    }

    /// The claimed sequence of the missing parent (`tail_point.sequence − 1`).
    pub fn claimed_parent_sequence(&self) -> u32 {
        self.claimed_parent_sequence
    }
}

/// Single-outcome result of [`Blockchain::on_tick`] (AR4). Epic 4 realizes the
/// FR19/FR46 parent-recovery slice of the scheduler; Story 8.4 extends this enum
/// with the block-creation (FR45), grace-period (FR47), and mempool-replenishment
/// (FR43) tick effects, folding the module-scope `last_parent_request_emit_timestamp`
/// and the tick deadline into the full `SchedulerState` (architecture §6.7).
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum TickOutcome {
    /// No time-driven behavior fired this tick.
    Idle,
    /// FR19 — emit a single parent-recovery request for the selected Stored head.
    SendParentRecoveryRequest(ParentRecoveryRequest),
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
    const SNAKE_CHAIN_LENGTH: u32,
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

    // FR19 chain_heads tip table — landed in Story 4.4.
    chain_heads: ChainHeadsTable<MAX_BRANCH_COUNT>,

    // Const-sized placeholder for the future real bounded table (Story 1.2).
    // `()` is zero-sized until the owning story replaces it (Story 7.1).
    _node_info: [(); MAX_NODES],

    // FR19/FR46 module-scope global emit cooldown: wall-clock time of the most
    // recent parent-recovery request emitted across all heads (`0` = never).
    // Story 8.4 folds this (and the tick deadline) into the full `SchedulerState`
    // (architecture §6.7).
    last_parent_request_emit_timestamp: u64,

    // FR19/§6.4: the active-chain head as a block-table index (`NONE_REF` = no
    // active head yet). Genesis admission (Story 4.4 event (i)) sets it; the
    // full FR2/FR4 lifecycle drivers (Epic 5) refine it.
    active_chain_head_idx: u32,

    // Real snake-chain state is two block-table indices, not a W-sized
    // window. `SNAKE_CHAIN_LENGTH` remains an algorithmic bound for
    // maintaining the tail index relative to the active head. It is a `u32`
    // (not the array-sizing `usize` the other const generics use) because it
    // is a window *width* compared directly against `u32` block sequences —
    // never an array length — so it needs no cast at the FR60 comparison site.
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
    const SNAKE_CHAIN_LENGTH: u32,
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
    /// In-place construction for embedded/task use, and this type's **only**
    /// constructor: writes directly into caller-provided `dst` instead of
    /// returning `Self` by value.
    ///
    /// `Self` is large (dominated by `blocks: BlockTable<MAX_BLOCKS>`, e.g.
    /// ~45.6 KB at the default `MAX_BLOCKS = 600`) — large enough that no
    /// construction technique *inside* a function that returns `Self` by
    /// value can avoid needing a full `size_of::<Self>()`-sized stack
    /// allocation somewhere (measured across several approaches: a
    /// struct-literal, and `MaybeUninit` + per-field pointer writes with
    /// and without an element-by-element large-array fill — all landed at
    /// the same floor). A by-value `new()` existed earlier and was fine for
    /// the desktop simulator (architecture §10 / FR62 — plain owned value,
    /// no `'static`/global state, and no tight stack budget there) and for
    /// tests, but it was removed once every caller was confirmed able to use
    /// this constructor instead: a plain owned `Blockchain` is still
    /// reachable anywhere it's needed via a local `MaybeUninit` +
    /// `assume_init()` (exactly as this crate's own tests do), it just
    /// always goes through an in-place write rather than a by-value return.
    /// This is the single constructor for every node; node zero then runs
    /// [`Self::process_genesis`] on the constructed instance to bootstrap the
    /// chain (FR54).
    ///
    /// For embedded firmware, use this from *inside* a
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
            let chain_heads_ptr = core::ptr::addr_of_mut!((*dst).chain_heads);
            ChainHeadsTable::init_in_place(chain_heads_ptr);
            core::ptr::addr_of_mut!((*dst)._node_info).write([(); MAX_NODES]);
            core::ptr::addr_of_mut!((*dst).last_parent_request_emit_timestamp).write(0);
            core::ptr::addr_of_mut!((*dst).active_chain_head_idx).write(NONE_REF);
            core::ptr::addr_of_mut!((*dst)._snake_chain_tail_idx).write(0);
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
    /// is built once through [`Self::init_in_place`], then genesis runs against
    /// it. That keeps the single infallible in-place constructor and lets genesis
    /// use ordinary fallible control flow. (Non-zero nodes never call this; they
    /// construct via `init_in_place` and receive the chain over the mesh.)
    ///
    /// Refusal (`Err(GenesisRejectReason::_)`, `self` left unchanged): the local
    /// node id is not `0`; the chain is not empty (`StorageNotEmpty` — already
    /// bootstrapped); `initial_chain_config_bytes` does not fit or was already
    /// retained; or a block cannot be persisted (`StorageSaveFailed`). All
    /// non-persistence checks run before any storage write, and both blocks are
    /// built before either is saved, so a refusal never leaves a half-written
    /// chain from *this* call.
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
    /// **Walking-skeleton scope (Story 1.4).** Block layouts are
    /// minimum-buildable per FR54; blocks are finalized through chain-types signed
    /// builders. Full canonical validation (Stories 4.2 / 5.4 / 5.6), the
    /// chain-config durable-lock semantics, block-tree insertion, and detecting a
    /// non-empty *persisted* store on reboot land in later stories; the
    /// `StorageNotEmpty` guard here inspects in-memory chain state only.
    pub fn process_genesis(
        &mut self,
        initial_total_network_currency: u64,
        initial_chain_config_bytes: &[u8],
    ) -> Result<GenesisBlocks, GenesisRejectReason> {
        if self.local_node_id != 0 {
            return Err(GenesisRejectReason::LocalNodeIdNotZero);
        }
        // Genesis is only valid on a fresh chain. Re-running it would overwrite
        // an existing Block #0 / retained chain-config.
        if self.blocks.len() != 0 || self.chain_config.initial_chain_config_bytes().is_some() {
            return Err(GenesisRejectReason::StorageNotEmpty);
        }

        let node_zero_public_key = *self.crypto.public_key().serialize();
        self.chain_config
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
            &self.crypto,
        );
        let self_transfer = NodeTransfer::new_signed(
            0, // vote
            0, // anchor_sequence
            0, // initializer (node #0)
            0, // receiver (self)
            initial_total_network_currency,
            0, // fee
            0, // comment
            &self.crypto,
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
            // full canonical block bytes with this field zero-filled, then
            // stores the generated signature here.
            signature: [0u8; 64],
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
        let block_0 = match builder.build_signed(&self.crypto) {
            Ok(b) => b,
            Err(_) => unreachable!("Block #0 header.version = 1 and payload fits MAX_BLOCK_SIZE"),
        };

        // Assemble signed Block #1: the chain-config block, chained to Block #0.
        let block_1_header = BlockHeader {
            version: 1,
            sequence: 1,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: block_0.hash(),
            signature: [0u8; 64],
        };
        let mut cfg_builder = BlockBuilder::new().header(block_1_header);
        // `initial_chain_config_bytes` already passed the capacity check in
        // `store_initial_chain_config_bytes`, so the payload fits Block #1.
        if cfg_builder
            .set_chain_config_payload(initial_chain_config_bytes)
            .is_err()
        {
            unreachable!("initial chain-config bytes were capacity-checked and fit the payload");
        }
        let block_1 = match cfg_builder.build_signed(&self.crypto) {
            Ok(b) => b,
            Err(_) => unreachable!("Block #1 header.version = 1 and payload fits MAX_BLOCK_SIZE"),
        };

        // Persist both blocks (only after both are built, so a build failure
        // never leaves a partially-persisted chain) AND mirror them into the
        // in-memory block-tree as node #0's active chain, so storage and the tree
        // stay consistent and the node is immediately operational. The
        // `StorageNotEmpty` guard above guarantees slots 0/1 are free. Genesis
        // blocks are valid by construction, so they bypass the tier1 intake gate;
        // they are placed exactly as that path establishes the genesis anchor
        // (`on_active_chain` + active head + `chain_heads`), with a sentinel
        // arrival timestamp of 0 — genesis heads sit on the active chain and are
        // never parent-recovery-scheduled, so the timestamp is unused. (Full
        // `Stored`→`Active` status promotion is Epic 6; the FR3 derived
        // projections are Epic 7. Wiring Block #1 through the dedicated
        // `set_chain_configuration` seam lands with the Story 5.6 boot flow.)

        // Block #0 — active-chain anchor (no parent).
        self.storage
            .save_block(0, &block_0)
            .map_err(|_| GenesisRejectReason::StorageSaveFailed)?;
        let mut entry_0 = BlockEntry::new(block_0.hash(), NONE_REF, 0);
        entry_0.set_on_active_chain(true);
        self.blocks.insert_at(0, entry_0);
        self.active_chain_head_idx = 0;
        let active_head = self.active_chain_head_idx;
        self.chain_heads
            .on_block_admitted(&mut self.blocks, 0, None, [0u8; 32], 0, active_head);

        // Block #1 — chain-config, chained to Block #0; becomes the active tip.
        self.storage
            .save_block(1, &block_1)
            .map_err(|_| GenesisRejectReason::StorageSaveFailed)?;
        let block_1_prev_hash = block_0.hash();
        let mut entry_1 = BlockEntry::new(block_1.hash(), 0, 1);
        entry_1.set_on_active_chain(true);
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

        // Node #0 authored a complete, valid chain, so it is immediately Ready:
        // there is no FR2 dominant-chain acquisition or FR3 reconstruction to do
        // for the author (join/restart nodes still go through Collecting).
        // This is an **init-time** establishment of the initial phase, NOT a
        // runtime `Collecting→Ready` transition (which is illegal, Story 5.1) —
        // genesis therefore writes the field directly rather than through the
        // guarded `set_lifecycle_phase`.
        self.lifecycle_phase = LifecyclePhase::Ready;

        Ok(GenesisBlocks {
            block_zero: block_0,
            block_one: block_1,
        })
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
    // First caller lands in Story 5.2 (Collecting→Processing); declared-and-tagged-
    // forward, so allow dead_code until then.
    #[allow(dead_code)]
    pub(crate) fn set_lifecycle_phase(&mut self, to: LifecyclePhase) {
        debug_assert!(
            is_legal_transition(&self.lifecycle_phase, &to),
            "illegal lifecycle transition"
        );
        self.lifecycle_phase = to;
    }

    /// The single readiness gate (FR1). `true` iff the node is in `Ready`; every
    /// ready-only surface consults this before operating. In `Collecting` /
    /// `Processing` it is `false`, so those surfaces return their uniform
    /// not-ready indication.
    pub(crate) fn is_ready(&self) -> bool {
        self.lifecycle_phase == LifecyclePhase::Ready
    }

    /// Join/restart init follow-up (FR1/FR59): the **safe** counterpart to the
    /// `unsafe` [`Self::init_in_place`] constructor. Construction writes raw
    /// fields (unsafe) and lands the node in `Collecting`; this method then reads
    /// durable storage (safe) — the deliberate unsafe/safe split (architecture
    /// §3.6 "in-place constructor + role-specific follow-up"), so the raw-pointer
    /// memory init stays isolated from safe storage-reading business logic.
    ///
    /// **Story 5.1 scope:** the empty-storage (fresh-join) path — no durable
    /// blocks → the node stays `Collecting` and returns `StartedCollecting`
    /// (FR1). The **restart** path (durable blocks present → rebuild the
    /// block-tree / `chain_heads`, evaluate FR2, run the FR3 pass, transition to
    /// Ready-or-Collecting, returning `ResumedReady` / `ResumedProcessing`) is
    /// **Story 5.7 (FR59)**; the non-empty branch is a `todo!()` forward-tag until
    /// then (reachable only by a restart test — genesis uses
    /// [`Self::process_genesis`], fresh join uses the empty path here).
    ///
    /// Carries a `NextCall` per AR4 (a state-changing init step). The emptiness
    /// probe reads durable block index 0; Story 5.7 replaces it with the FR59
    /// control-data-driven rebuild.
    pub fn initialize_from_storage(&mut self, _now: u64) -> CallResult<InitOutcome> {
        let has_durable_blocks = self.storage.read_block(0).is_ok();
        if has_durable_blocks {
            // FR59 restart rebuild — Story 5.7 reads the retained durable blocks,
            // rebuilds the tree, and runs the FR2/FR3 spine. Not built here.
            todo!("FR59 restart rebuild from durable storage — Story 5.7");
        }
        // Fresh join: empty durable storage → remain a pure receiver (FR1).
        (InitOutcome::StartedCollecting, NextCall::Idle)
    }

    /// Read-only query — returns the local node id (FR67).
    pub fn local_node_id(&self) -> u32 {
        self.local_node_id
    }

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
        let block_size_limit = self.chain_config.current_block_size_limit();
        tier1_gate(
            block,
            &self.node_zero_public_key,
            block_size_limit,
            &self.crypto,
        )
        .map_err(AdmitError::Rejected)?;

        // Single-genesis guard (Story 5.1, deferred from the Story-4.4 review).
        // There is structurally exactly one genesis anchor. A distinct `sequence
        // == 0` block (FR11 dedup already filtered an identical one upstream) that
        // arrives once the active chain is anchored is rejected as exact evidence
        // (FR16) — BEFORE any storage write — rather than admitted. Admitting it
        // would either reseat the anchor (the Story-4.4 defect this guard closes)
        // or, as a `parent.is_none()` orphan, create a `sequence == 0` Stored head
        // that emits a perpetual bogus parent-recovery request for a nonexistent
        // seq-0 parent (violating the `chain_heads` "tail-point never has sequence
        // 0" invariant). NOTE: authenticity (only node #0 may sign a genesis) is
        // not yet enforced — the block-creator signature is not a Tier-1 check
        // until FR69 lands — so this guard enforces single-*anchor* structurally,
        // not *authenticity*; a forged first-arriving seq-0 would anchor until
        // FR69. See the Story-5.1 code-review record.
        if block.sequence() == 0 && self.active_chain_head_idx != NONE_REF {
            return Err(AdmitError::Rejected(Tier1Failure::DuplicateGenesis));
        }

        // Storage-first: peek the slot, persist there, then write the entry at
        // that same slot. Reconstruct an owned `Block` for the storage seam
        // (`save_block` takes `&Block`); this copy happens only on the success
        // path, after Tier 1 passed.
        let idx = self.blocks.next_free_index().ok_or(AdmitError::TableFull)?;
        let owned = Block::from_bytes(block.serialized_bytes())
            .map_err(|_| AdmitError::Rejected(Tier1Failure::MalformedPayload))?;
        self.storage
            .save_block(idx, &owned)
            .map_err(|_| AdmitError::StorageSaveFailed)?;

        // FR19 parent resolution (Story 4.4). `previous_hash()` is a 32-byte
        // slice; convert to the array key. Genesis (`sequence == 0`) has no parent.
        let prev_hash: [u8; 32] = block.previous_hash().try_into().unwrap_or([0; 32]);
        let parent = self.blocks.find_parent(&prev_hash, block.sequence());

        // FR19 bootstrap (AC7): a genesis block (sequence 0, no parent) anchors
        // the active chain — mark it on-chain and record it as the active head so
        // event (i) classifies its head Connected. The single-genesis guard above
        // already rejected any seq-0 block once an anchor exists, so this only ever
        // fires for the *first* genesis (`active_chain_head_idx == NONE_REF`).
        let is_genesis = block.sequence() == 0 && parent.is_none();

        let mut entry = BlockEntry::new(*hash, parent.unwrap_or(NONE_REF), block.sequence());
        entry.set_status(BlockStatus::Stored);
        if is_genesis {
            entry.set_on_active_chain(true);
        }
        self.blocks.insert_at(idx, entry);
        if is_genesis {
            self.active_chain_head_idx = idx;
        }

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
        Ok(idx)
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
    pub fn receive_block(
        &mut self,
        block: BlockView<'_>,
        now: u64,
    ) -> CallResult<ReceiveBlockOutcome> {
        let window = self.active_snake_chain_window();
        let outcome = classify_block(self, &block, window, now);
        (outcome, self.next_parent_recovery_call())
    }

    /// FR19/FR46 tick: run the parent-recovery scheduler. First evaluates the
    /// FR46 **global emit cooldown** (`last_parent_request_emit_timestamp +
    /// parent_recovery_min_emit_interval ≤ now`); only if it has cleared does it
    /// select the most-overdue Stored head (deterministic FR63 tie-breaks) and
    /// emit **exactly one** [`ParentRecoveryRequest`], updating both the head's
    /// `last_request_timestamp` and the module-scope emit timestamp to `now`.
    /// Reports `NextCall::At(exact next-eligible instant)` while Stored heads
    /// remain (`NextCall::Idle` when none do). Story 8.4 extends this into the
    /// full multi-deadline scheduler.
    pub fn on_tick(&mut self, now: u64) -> CallResult<TickOutcome> {
        let min_emit = self.chain_config.parent_recovery_min_emit_interval_ms();
        let per_head_retry = self
            .chain_config
            .parent_recovery_per_head_retry_interval_ms();

        let cooldown_cleared = self
            .last_parent_request_emit_timestamp
            .saturating_add(min_emit)
            <= now;
        let outcome = if cooldown_cleared {
            match self
                .chain_heads
                .select_parent_recovery(&self.blocks, now, per_head_retry)
            {
                Some((slot, request)) => {
                    self.chain_heads.mark_requested(slot, now);
                    self.last_parent_request_emit_timestamp = now;
                    TickOutcome::SendParentRecoveryRequest(request)
                }
                None => TickOutcome::Idle,
            }
        } else {
            TickOutcome::Idle
        };
        (outcome, self.next_parent_recovery_call())
    }

    /// The next parent-recovery wake-up as the **exact** instant a request can
    /// next be emitted (AR4 scheduling-pull — no fixed periodic tick): the later
    /// of the earliest Stored-head per-head eligibility and the FR46 global emit
    /// cooldown clearing. `NextCall::Idle` when no Stored head awaits a parent
    /// (FR46 "deadline not scheduled when no Stored heads present"). An instant
    /// already in the past means "call back ASAP" (a request is due now).
    fn next_parent_recovery_call(&self) -> NextCall {
        let per_head_retry = self
            .chain_config
            .parent_recovery_per_head_retry_interval_ms();
        match self.chain_heads.earliest_recovery_deadline(per_head_retry) {
            Some(head_ready) => {
                let min_emit = self.chain_config.parent_recovery_min_emit_interval_ms();
                let cooldown_clear = self
                    .last_parent_request_emit_timestamp
                    .saturating_add(min_emit);
                NextCall::At(head_ready.max(cooldown_clear))
            }
            None => NextCall::Idle,
        }
    }

    /// FR19 — the active-chain head's sequence, or `None` when no active head is
    /// established yet (collecting, pre-bootstrap). Architecture §3.1.
    pub fn current_active_head(&self) -> Option<u32> {
        if self.active_chain_head_idx == NONE_REF {
            return None;
        }
        self.blocks
            .get(self.active_chain_head_idx)
            .map(|entry| entry.sequence())
    }

    // ---------------------------------------------------------------------
    // Ready-only entry points — not-ready-gated in Story 5.1 (FR1).
    //
    // Each checks `is_ready()` and returns its uniform not-ready value while the
    // node is Collecting/Processing; the ready-state body (beyond the gate) is
    // built by the owning epic (`todo!()` forward-tag), reachable only by a
    // genesis(Ready) node in tests until then. Queries return `Result<_, E>`
    // (a `Result`, not `Option`, so `NotReady` ≠ the domain "absent" case).
    // ---------------------------------------------------------------------

    /// FR14/FR10 transaction intake (ready-only). While not `Ready` the module
    /// returns [`ReceiveTransactionOutcome::NotReady`] with `NextCall::Idle`
    /// (FR1: FR14's classification inputs — anchor-sequence window, already-
    /// confirmed detection, deferred evaluation — are defined against the active
    /// chain, which does not exist while collecting). Ready-state classification
    /// is **Epic 7** (FR14); Story 5.1 builds only the gate.
    pub fn receive_transaction(
        &mut self,
        _tx: TransactionView<'_>,
        _now: u64,
    ) -> CallResult<ReceiveTransactionOutcome> {
        if !self.is_ready() {
            return (ReceiveTransactionOutcome::NotReady, NextCall::Idle);
        }
        todo!("FR14 ready-state transaction classification — Epic 7")
    }

    /// FR55 local transaction-creation surface (ready-only). While not `Ready`
    /// returns [`LocalTransactionOutcome::NotReady`] (FR55's mandated
    /// `Rejected(not-ready)`). The `Created` / `Held` / `Rejected` body is
    /// **Epic 10**; Story 5.1 builds only the gate.
    pub fn submit_local_transaction(
        &mut self,
        _tx: TransactionView<'_>,
        _now: u64,
    ) -> CallResult<LocalTransactionOutcome> {
        if !self.is_ready() {
            return (LocalTransactionOutcome::NotReady, NextCall::Idle);
        }
        todo!("FR55 ready-state local transaction creation — Epic 10")
    }

    /// FR41 node-balance query (ready-only). `Err(BalanceQueryError::NotReady)`
    /// while not `Ready`; the ready-state lookup (and the `UnknownNode` arm) is
    /// **Epic 10**. A `Result`, not `Option`, so not-ready stays distinct from a
    /// missing node and from a legitimate zero balance.
    pub fn query_balance(&self, _node_id: u32) -> Result<u64, BalanceQueryError> {
        if !self.is_ready() {
            return Err(BalanceQueryError::NotReady);
        }
        todo!("FR41 ready-state balance lookup — Epic 10")
    }

    /// FR42 block-retrieval by hash (ready-only). `Err(BlockQueryError::NotReady)`
    /// while not `Ready` — a collecting node does not serve blocks, including
    /// radio-forwarded peer requests (FR1). Ready-state lookup (and the
    /// `NotFound` arm) is **Epic 10**.
    pub fn serve_block_by_hash(&self, _hash: &[u8; 32]) -> Result<BlockView<'_>, BlockQueryError> {
        if !self.is_ready() {
            return Err(BlockQueryError::NotReady);
        }
        todo!("FR42 ready-state block retrieval by hash — Epic 10")
    }

    /// FR42 block-retrieval by sequence (ready-only). `Err(BlockQueryError::NotReady)`
    /// while not `Ready`. Ready-state lookup is **Epic 10**.
    pub fn serve_block_by_sequence(&self, _seq: u32) -> Result<BlockView<'_>, BlockQueryError> {
        if !self.is_ready() {
            return Err(BlockQueryError::NotReady);
        }
        todo!("FR42 ready-state block retrieval by sequence — Epic 10")
    }

    /// FR40 transaction-state query (ready-only). `Err(TxStateQueryError::NotReady)`
    /// while not `Ready`; the `Unknown`/`InMempool`/`Confirmed` lookup against the
    /// mempool + active chain is **Epic 10**.
    pub fn query_transaction_state(
        &self,
        _tx_hash: &[u8; 32],
    ) -> Result<TransactionState, TxStateQueryError> {
        if !self.is_ready() {
            return Err(TxStateQueryError::NotReady);
        }
        todo!("FR40 ready-state transaction-state query — Epic 10")
    }

    /// FR44 creator-role determination (ready-only) — gates FR45 block creation.
    /// `Err(CreatorQueryError::NotReady)` while not `Ready`; the binary comparison
    /// of the local node id against the top of the FR38 creator-order projection
    /// is **Epic 8**.
    pub fn creator_role(&self) -> Result<CreatorRole, CreatorQueryError> {
        if !self.is_ready() {
            return Err(CreatorQueryError::NotReady);
        }
        todo!("FR44 ready-state creator-role determination — Epic 8")
    }

    /// The current active-chain `(S_tail, S_head)` sequence bounds, or `None`
    /// in collecting state (which suppresses the FR60 window check + its
    /// `long-disconnect-detected` log per AC7).
    ///
    /// Gated on `Ready` (Story 5.1): while the node is not `Ready` (Collecting /
    /// Processing) there is no active chain, so this returns `None` and the FR60
    /// window check stays inactive — every admitted block is `Stored` (FR9/AC6).
    /// The decision is now phase-driven, not a hardcoded `None`. Epic 9
    /// (`snake_chain.rs`) supplies the real `(S_tail, S_head)` from the
    /// `_snake_chain_tail_idx` / `active_chain_head_idx` block-table indices once
    /// Ready; until it lands, the Ready branch also yields `None`.
    fn active_snake_chain_window(&self) -> Option<(u32, u32)> {
        if !self.is_ready() {
            return None;
        }
        // Epic 9 derives the real (S_tail, S_head) here.
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

    /// Helper: build an empty node via `init_in_place` ready for a
    /// `process_genesis` call. Genesis is node-zero-only, so node zero's own
    /// key (derived from `crypto`) is stored as the trust anchor.
    fn new_chain(
        crypto: Crypto,
        storage: MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        chain_config: FixedChainConfig,
        local_node_id: u32,
        prng_seed: u64,
    ) -> Blockchain<
        Crypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        FixedChainConfig,
        16,
        16,
        4,
        16,
        4,
        16,
    > {
        let node_zero = *crypto.public_key().serialize();
        let mut bc_slot = core::mem::MaybeUninit::uninit();
        unsafe {
            Blockchain::init_in_place(
                bc_slot.as_mut_ptr(),
                crypto,
                storage,
                chain_config,
                local_node_id,
                node_zero,
                prng_seed,
            );
            bc_slot.assume_init()
        }
    }

    /// `init_in_place`'s `unsafe` per-field writes (out-param signature,
    /// `blocks` filled element-by-element via `BlockTable::init_in_place`)
    /// must land every field in its correct default state — a wrong field
    /// order, a skipped field, or an off-by-one in the `unsafe` block would
    /// silently corrupt memory rather than panic, so this is verified
    /// directly rather than trusted by construction.
    #[test]
    fn init_in_place_sets_expected_defaults() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc_slot =
            core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 4, 16, 4, 16>>::uninit();
        let bc = unsafe {
            Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::init_in_place(
                bc_slot.as_mut_ptr(),
                crypto,
                storage,
                chain_config,
                7,
                [3u8; PUBLIC_KEY_SIZE],
                0xDEAD_BEEF,
            );
            bc_slot.assume_init()
        };

        assert_eq!(bc.local_node_id(), 7);
        assert!(bc.current_phase() == LifecyclePhase::Collecting);
        assert_eq!(bc.blocks.len(), 0);
        assert_eq!(bc.node_zero_public_key, [3u8; PUBLIC_KEY_SIZE]);
        // Story 4.4: the `chain_heads` table + scheduler state must init to
        // their empty/sentinel values too (the unsafe
        // `ChainHeadsTable::init_in_place` writes every entry element-by-element).
        assert_eq!(bc.chain_heads.count(), 0);
        assert_eq!(bc.active_chain_head_idx, NONE_REF);
        assert_eq!(bc.last_parent_request_emit_timestamp, 0);
    }

    /// AC1, AC4, AC5 — successful genesis bootstrap on `local_node_id == 0`
    /// yields **both** Block #0 and Block #1 in a single `process_genesis`
    /// call (no `NextCall`), with no embassy deps anywhere in the harness.
    #[test]
    fn walking_skeleton_genesis_success() {
        let (crypto, storage, chain_config) = test_backends();
        let expected_node_zero_public_key = *crypto.public_key().serialize();
        let initial_chain_config_bytes = [0xC0, 0xA5, 0xF6, 0x01];

        let mut bc = new_chain(crypto, storage, chain_config, 0, 0xDEAD_BEEF_CAFE_F00D);
        let GenesisBlocks {
            block_zero,
            block_one,
        } = bc
            .process_genesis(1_000_000_000, &initial_chain_config_bytes)
            .ok()
            .expect("genesis with local_node_id == 0 must succeed (FR54)");

        // --- Block #0: registration + self-transfer ---
        assert_eq!(block_zero.sequence(), 0);
        assert_eq!(block_zero.creator(), 0);
        assert_eq!(block_zero.version(), 1);
        assert_eq!(block_zero.payload_type(), PAYLOAD_TYPE_TRANSACTION);
        assert!(
            any_nonzero(block_zero.signature()),
            "Block #0 must be signed"
        );
        let mut transactions = block_zero
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

        // --- Block #1: chain-config, chained to Block #0 ---
        assert_eq!(block_one.sequence(), 1);
        assert_eq!(block_one.version(), 1);
        assert_eq!(block_one.payload_type(), PAYLOAD_TYPE_CHAIN_CONFIG);
        assert_eq!(
            block_one.previous_hash(),
            &block_zero.hash()[..],
            "Block #1 must chain to Block #0"
        );
        assert_eq!(
            block_one.payload(),
            &initial_chain_config_bytes[..],
            "Block #1 payload is the initial chain-config verbatim"
        );
        assert!(
            any_nonzero(block_one.signature()),
            "Block #1 must be signed"
        );

        assert_eq!(
            bc.chain_config.initial_chain_config_bytes(),
            Some(&initial_chain_config_bytes[..])
        );
        // Node #0 authored the whole chain — it is immediately Ready.
        assert!(bc.current_phase() == LifecyclePhase::Ready);
        assert_eq!(bc.local_node_id(), 0);

        // Both genesis blocks are mirrored into the in-memory tree (in sync with
        // storage), forming the active chain with Block #1 as the tip.
        assert_eq!(bc.blocks.len(), 2);
        assert_eq!(bc.active_chain_head_idx, 1, "Block #1 is the active tip");
        let head_0 = bc.blocks.get(0).expect("Block #0 in tree");
        let head_1 = bc.blocks.get(1).expect("Block #1 in tree");
        assert!(head_0.is_on_active_chain());
        assert!(head_1.is_on_active_chain());
        assert_eq!(head_1.sequence(), 1);
        assert_eq!(head_1.parent_ref(), 0, "Block #1 parent is Block #0's slot");
        assert_eq!(bc.chain_heads.count(), 1, "one active head after genesis");
    }

    /// The single genesis head is **Connected** (on the active chain), not a
    /// Stored tail-point — so there is nothing to parent-recover: `on_tick`
    /// stays `Idle` and no `SendParentRecoveryRequest` is emitted for the
    /// self-authored chain. Guards against a misclassified genesis head.
    #[test]
    fn genesis_head_is_connected_no_parent_recovery() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        bc.process_genesis(1_000_000_000, &[0xAB])
            .ok()
            .expect("genesis must succeed");

        assert!(
            !bc.chain_heads.has_stored_head(),
            "the genesis head must be Connected, not a Stored tail-point"
        );
        let (outcome, _next) = bc.on_tick(1_000_000);
        assert!(
            matches!(outcome, TickOutcome::Idle),
            "a complete genesis chain schedules no parent-recovery"
        );
    }

    /// AC2 — `local_node_id != 0` refuses genesis and leaves the chain empty.
    /// The `Err(_)` arm is forward-compat for the additional
    /// `GenesisRejectReason` variants Story 5.6+ introduces.
    #[allow(unreachable_patterns)]
    #[test]
    fn walking_skeleton_refuses_non_zero_local_node_id() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 1, 0);

        let outcome = bc.process_genesis(1_000_000_000, &[]);

        match outcome {
            Err(GenesisRejectReason::LocalNodeIdNotZero) => {}
            Err(_) => panic!("expected LocalNodeIdNotZero refusal"),
            Ok(_) => panic!("FR54 precondition must refuse local_node_id != 0"),
        }
        // Nothing was retained on the refusal path.
        assert!(bc.chain_config.initial_chain_config_bytes().is_none());
    }

    /// Oversized genesis chain-config bytes are rejected; the bounded
    /// retention lives in `chain_config.rs`.
    #[test]
    fn walking_skeleton_rejects_oversized_initial_chain_config() {
        let (crypto, storage, chain_config) = test_backends();
        let oversized = [0u8; INITIAL_CHAIN_CONFIG_BYTES_CAPACITY + 1];
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

        let outcome = bc.process_genesis(1_000_000_000, &oversized);

        match outcome {
            Err(GenesisRejectReason::InitialChainConfigTooLarge) => {}
            Err(_) => panic!("expected InitialChainConfigTooLarge refusal"),
            Ok(_) => panic!("oversized initial chain-config bytes must be refused"),
        }
    }

    /// A chain that already retains initial chain-config bytes is not empty, so
    /// genesis is refused before it can overwrite them (`StorageNotEmpty`).
    #[test]
    fn walking_skeleton_refuses_genesis_when_chain_config_already_retained() {
        let (crypto, storage, mut chain_config) = test_backends();
        chain_config
            .store_initial_chain_config_bytes(&[0x01, 0x02])
            .unwrap();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

        let outcome = bc.process_genesis(1_000_000_000, &[0x03, 0x04]);

        match outcome {
            Err(GenesisRejectReason::StorageNotEmpty) => {}
            Err(_) => panic!("expected StorageNotEmpty refusal"),
            Ok(_) => panic!("genesis must not overwrite retained chain-config bytes"),
        }
        // The pre-existing bytes are untouched.
        assert_eq!(
            bc.chain_config.initial_chain_config_bytes(),
            Some(&[0x01, 0x02][..])
        );
    }

    /// Genesis is a one-shot bootstrap: a second `process_genesis` on the same
    /// node refuses with `StorageNotEmpty` (the chain now carries genesis state).
    #[test]
    fn walking_skeleton_refuses_second_genesis() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

        let first = bc.process_genesis(1_000_000_000, &[0xAA]);
        assert!(first.is_ok(), "first genesis must succeed");

        let second = bc.process_genesis(1_000_000_000, &[0xBB]);
        match second {
            Err(GenesisRejectReason::StorageNotEmpty) => {}
            Err(_) => panic!("expected StorageNotEmpty on the second genesis"),
            Ok(_) => panic!("genesis must run at most once per chain"),
        }
    }

    /// Storage persistence failure refuses genesis; no `Created` outcome is
    /// returned when a genesis block cannot be retained locally.
    #[test]
    fn walking_skeleton_refuses_storage_save_failure() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let crypto = Crypto::new(private_key)
            .ok()
            .expect("test private key should be accepted by the backend");
        let storage = MemoryBackend::<0>::new();
        let chain_config = FixedChainConfig::new();
        let node_zero = *crypto.public_key().serialize();

        let mut bc_slot =
            core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 4, 16, 4, 16>>::uninit();
        let mut bc = unsafe {
            Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::init_in_place(
                bc_slot.as_mut_ptr(),
                crypto,
                storage,
                chain_config,
                0,
                node_zero,
                0,
            );
            bc_slot.assume_init()
        };

        let outcome = bc.process_genesis(1_000_000_000, &[]);

        match outcome {
            Err(GenesisRejectReason::StorageSaveFailed) => {}
            Err(_) => panic!("expected StorageSaveFailed refusal"),
            Ok(_) => panic!("genesis must not succeed when a genesis block cannot be persisted"),
        }
    }

    /// AC3 — read-only queries are typed to **not** carry `NextCall`.
    /// This is a compile-time guarantee: `current_phase` returns
    /// `LifecyclePhase` directly (not `CallResult<LifecyclePhase>`), and
    /// `local_node_id` returns `u32` directly.
    #[test]
    fn walking_skeleton_query_carries_no_next_call() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        bc.process_genesis(1_000_000_000, &[])
            .ok()
            .expect("genesis must succeed for local_node_id == 0");

        // Type-level assertion: the query result is `LifecyclePhase`,
        // not `(LifecyclePhase, NextCall)`. If the signature ever drifts
        // back to `CallResult`, this annotation will fail to compile.
        let phase: LifecyclePhase = bc.current_phase();
        assert!(phase == LifecyclePhase::Ready);

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
        let mut bc_slot = core::mem::MaybeUninit::<TestChain>::uninit();
        unsafe {
            TestChain::init_in_place(
                bc_slot.as_mut_ptr(),
                crypto,
                storage,
                chain_config,
                5,
                node_zero,
                0,
            );
            bc_slot.assume_init()
        }
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
            .tier1_admit(&block.view(), &block.view().hash(), 1_000)
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
        let result = bc.tier1_admit(&block.view(), &block.view().hash(), 1_000);
        assert_eq!(result, Err(AdmitError::Rejected(Tier1Failure::SelfVote)));
        assert_eq!(bc.blocks.len(), 0, "a rejected block must not be stored");
    }

    // (FR11 de-duplication is owned by `classify_block`, not `tier1_admit`, so
    // there is no `tier1_admit` duplicate case — the dedup outcome is covered
    // by `intake::tests::receive_block_duplicate_is_duplicate_known`.)

    // --- Story 4.4: FR19 chain_heads admission / scheduler / bootstrap -------

    /// A transfer block whose `previous_hash` is set to `prev` (so it can extend
    /// a specific parent). `node_transfer_block` zero-fills `previous_hash`, which
    /// makes an orphan (Stored head); this helper links a child to its parent.
    fn linked_transfer_block(seq: u32, prev: [u8; 32]) -> Block {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let nt = NodeTransfer::new_signed(3, seq.saturating_sub(1), 7, 9, 100, 1, 0, &signer);
        let header = BlockHeader {
            version: 1,
            sequence: seq,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_TRANSACTION,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: prev,
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        builder
            .add_node_transfer(&nt)
            .ok()
            .expect("add node transfer");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// AC7 — a genesis block (sequence 0, no parent) anchors the active chain: it
    /// becomes a Connected head, `active_chain_head_idx` is set, and no Stored
    /// head (hence no parent-recovery tick) is scheduled.
    #[test]
    fn receive_block_genesis_anchors_active_head() {
        let mut bc = new_test_chain();
        // Block-zero waives the self-vote / anchor Tier 1 checks.
        let genesis = node_transfer_block(0, 7, 0, 7);
        let (outcome, next) = bc.receive_block(genesis.view(), 100);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(
            bc.current_active_head(),
            Some(0),
            "genesis is the active head"
        );
        assert!(
            matches!(next, NextCall::Idle),
            "a Connected genesis head schedules no parent recovery"
        );
    }

    /// AC7 — a non-genesis first block with an unresolved parent creates a Stored
    /// head and schedules the initial parent-recovery tick.
    #[test]
    fn receive_block_orphan_creates_stored_head_and_schedules() {
        let mut bc = new_test_chain();
        let orphan = node_transfer_block(5, 3, 4, 7);
        let (outcome, next) = bc.receive_block(orphan.view(), 1_000);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert!(bc.current_active_head().is_none());
        assert!(
            matches!(next, NextCall::At(_)),
            "orphan schedules parent recovery"
        );
    }

    /// AC2 — `on_tick` emits exactly one FR19 request for the Stored head, with
    /// the tail-point's missing-parent hash and `tail.sequence − 1`.
    #[test]
    fn on_tick_emits_parent_recovery_request() {
        let mut bc = new_test_chain();
        let orphan = node_transfer_block(5, 3, 4, 7); // previous_hash == [0; 32]
        bc.receive_block(orphan.view(), 0);
        // Advance past the FR46 global cooldown + per-head retry (lrt == 0).
        let (outcome, next) = bc.on_tick(1_000_000);
        match outcome {
            TickOutcome::SendParentRecoveryRequest(req) => {
                assert_eq!(req.missing_parent_hash(), &[0u8; 32]);
                assert_eq!(req.claimed_parent_sequence(), 4, "tail.sequence - 1");
            }
            TickOutcome::Idle => panic!("a Stored head past its retry window must emit"),
        }
        assert!(
            matches!(next, NextCall::At(_)),
            "Stored head still awaits its parent"
        );
    }

    /// AC2/AC3 — the FR46 global emit cooldown suppresses a second emission within
    /// `parent_recovery_min_emit_interval`, even with an eligible head.
    #[test]
    fn on_tick_global_cooldown_suppresses_second_emission() {
        let mut bc = new_test_chain();
        // Two orphan heads so a head is always eligible.
        bc.receive_block(node_transfer_block(5, 3, 4, 7).view(), 0);
        bc.receive_block(linked_transfer_block(9, [0xAB; 32]).view(), 0);
        let t = 1_000_000;
        let (first, _) = bc.on_tick(t);
        assert!(matches!(first, TickOutcome::SendParentRecoveryRequest(_)));
        // min_emit is 10_000ms; a tick 5_000ms later is inside the cooldown.
        let (second, _) = bc.on_tick(t + 5_000);
        assert_eq!(second, TickOutcome::Idle, "global cooldown suppresses");
        // Past the cooldown, emission resumes.
        let (third, _) = bc.on_tick(t + 10_000);
        assert!(matches!(third, TickOutcome::SendParentRecoveryRequest(_)));
    }

    /// The `NextCall` is the **exact** next-eligible instant (AR4 pull model),
    /// not `now + a fixed periodic tick`. A fresh orphan (`lrt == 0`, module
    /// never emitted) is gated only by the FR46 boot-time global cooldown, so the
    /// deadline is `min_emit` regardless of `now`; after an emission it is the
    /// per-head window end.
    #[test]
    fn parent_recovery_nextcall_is_exact_deadline() {
        let mut bc = new_test_chain();
        let orphan = node_transfer_block(5, 3, 4, 7);
        // min_emit (stub) = 10_000; last_emit = 0 → deadline = max(0, 10_000).
        let (_, next) = bc.receive_block(orphan.view(), 5_000);
        assert!(
            matches!(next, NextCall::At(10_000)),
            "exact cooldown deadline, independent of now (5_000)"
        );
        // Emit at a large now; the next deadline is the per-head window end
        // (lrt 1_000_000 + per_head_retry 120_000), not now + a fixed interval.
        let (_, next2) = bc.on_tick(1_000_000);
        assert!(
            matches!(next2, NextCall::At(1_120_000)),
            "exact per-head window end after emission"
        );
    }

    /// AC3 — a fresh chain (no Stored heads) ticks Idle with no wake-up.
    #[test]
    fn on_tick_idle_without_stored_heads() {
        let mut bc = new_test_chain();
        let (outcome, next) = bc.on_tick(5_000);
        assert_eq!(outcome, TickOutcome::Idle);
        assert!(matches!(next, NextCall::Idle));
    }

    /// AC4 — an extend admission advances the single head (no second head).
    #[test]
    fn receive_block_extend_advances_head() {
        let mut bc = new_test_chain();
        let a = node_transfer_block(5, 3, 4, 7);
        bc.receive_block(a.view(), 0);
        let a_hash = a.view().hash();
        let b = linked_transfer_block(6, a_hash);
        let (outcome, _) = bc.receive_block(b.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(bc.block_tree_len(), 2);
        // Still one Stored head (A's orphan tail), advanced to B: on_tick emits a
        // request whose claimed parent is A's missing parent (tail seq 5 - 1 = 4).
        let (outcome, _) = bc.on_tick(1_000_000);
        match outcome {
            TickOutcome::SendParentRecoveryRequest(req) => {
                assert_eq!(req.claimed_parent_sequence(), 4);
            }
            TickOutcome::Idle => {
                panic!("the advanced Stored head must still request its tail parent")
            }
        }
    }

    /// AC9 — replaying an identical block + tick sequence against two fresh chains
    /// yields identical emitted `ParentRecoveryRequest`s and tree/head state,
    /// regardless of the `now` values used for scheduling.
    #[test]
    fn parent_recovery_is_deterministic_replay() {
        // `no_std`: collect emitted claimed-sequences into a fixed array
        // (at most one per tick).
        fn run(ticks: &[u64; 3]) -> (usize, [Option<u32>; 3]) {
            let mut bc = new_test_chain();
            // Three orphan heads with distinct sequences.
            for seq in [7u32, 5, 9] {
                bc.receive_block(node_transfer_block(seq, 3, seq - 1, 7).view(), 0);
            }
            let mut claimed: [Option<u32>; 3] = [None; 3];
            for (i, &t) in ticks.iter().enumerate() {
                if let (TickOutcome::SendParentRecoveryRequest(req), _) = bc.on_tick(t) {
                    claimed[i] = Some(req.claimed_parent_sequence());
                }
            }
            (bc.block_tree_len(), claimed)
        }
        // Widely spaced ticks so each clears the global cooldown + per-head retry.
        let ticks = [1_000_000, 2_000_000, 3_000_000];
        let (len_a, claims_a) = run(&ticks);
        let (len_b, claims_b) = run(&ticks);
        assert_eq!(len_a, len_b);
        assert_eq!(
            claims_a, claims_b,
            "identical emission order across replays"
        );
        // Deterministic selection: smallest head_sequence (5) first → claimed 4.
        assert_eq!(claims_a[0], Some(4));
    }

    // --- Story 5.1: lifecycle state machine, init paths, not-ready gating -----

    /// AC1/AC3 — a freshly constructed node (join path via `init_in_place`) is in
    /// `Collecting` and not ready.
    #[test]
    fn fresh_node_is_collecting_and_not_ready() {
        let bc = new_test_chain();
        assert!(bc.current_phase() == LifecyclePhase::Collecting);
        assert!(!bc.is_ready());
    }

    /// AC2 — a node that authored genesis is `Ready` (init-time direct-set, not a
    /// runtime transition).
    #[test]
    fn genesis_node_is_ready() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 1);
        bc.process_genesis(1_000_000_000, &[0xAB])
            .ok()
            .expect("genesis must succeed");
        assert!(bc.current_phase() == LifecyclePhase::Ready);
        assert!(bc.is_ready());
    }

    /// AC1 — the guarded mutator accepts every legal runtime edge.
    #[test]
    fn set_lifecycle_phase_accepts_legal_edges() {
        // Collecting → Processing → Ready.
        let mut bc = new_test_chain();
        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        assert!(bc.current_phase() == LifecyclePhase::Processing);
        bc.set_lifecycle_phase(LifecyclePhase::Ready);
        assert!(bc.current_phase() == LifecyclePhase::Ready);

        // Processing → Collecting (FR5 recovery edge).
        let mut bc2 = new_test_chain();
        bc2.set_lifecycle_phase(LifecyclePhase::Processing);
        bc2.set_lifecycle_phase(LifecyclePhase::Collecting);
        assert!(bc2.current_phase() == LifecyclePhase::Collecting);
    }

    /// AC1 — the guarded mutator rejects the illegal direct `Collecting → Ready`
    /// edge (debug-assert; `cargo test` runs debug).
    #[test]
    #[should_panic(expected = "illegal lifecycle transition")]
    fn set_lifecycle_phase_rejects_collecting_to_ready() {
        let mut bc = new_test_chain();
        bc.set_lifecycle_phase(LifecyclePhase::Ready);
    }

    /// AC5 — the snake-chain window seam is phase-gated: `None` while not Ready
    /// (so FR60 stays inactive and every admitted block is Stored, AC6).
    #[test]
    fn snake_chain_window_none_while_collecting() {
        let bc = new_test_chain();
        assert!(bc.active_snake_chain_window().is_none());
    }

    /// AC3 — the join follow-up on empty durable storage keeps the node
    /// Collecting and reports `StartedCollecting`.
    #[test]
    fn initialize_from_storage_empty_starts_collecting() {
        let mut bc = new_test_chain();
        let (outcome, next) = bc.initialize_from_storage(0);
        assert_eq!(outcome, InitOutcome::StartedCollecting);
        assert!(matches!(next, NextCall::Idle));
        assert!(bc.current_phase() == LifecyclePhase::Collecting);
    }

    /// AC4 — read-only ready-only queries return `Err(NotReady)` while Collecting
    /// (a `Result`, so not-ready is a distinct signal, not `None`).
    #[test]
    fn collecting_gates_ready_only_queries() {
        let bc = new_test_chain();
        assert_eq!(bc.query_balance(1), Err(BalanceQueryError::NotReady));
        assert!(matches!(
            bc.serve_block_by_hash(&[0u8; 32]),
            Err(BlockQueryError::NotReady)
        ));
        assert!(matches!(
            bc.serve_block_by_sequence(0),
            Err(BlockQueryError::NotReady)
        ));
        assert_eq!(
            bc.query_transaction_state(&[0u8; 32]),
            Err(TxStateQueryError::NotReady)
        );
        assert_eq!(bc.creator_role(), Err(CreatorQueryError::NotReady));
    }

    /// AC4 — state-changing ready-only intake surfaces return `NotReady` with
    /// `NextCall::Idle` while Collecting.
    #[test]
    fn collecting_gates_transaction_intake() {
        let mut bc = new_test_chain();
        let block = node_transfer_block(5, 3, 4, 7);
        let bv = block.view();
        let payload = bv.transactions().expect("transaction payload");

        let tx1 = payload.iter().next().expect("one transaction");
        let (o1, n1) = bc.receive_transaction(tx1, 1_000);
        assert_eq!(o1, ReceiveTransactionOutcome::NotReady);
        assert!(matches!(n1, NextCall::Idle));

        let tx2 = payload.iter().next().expect("one transaction");
        let (o2, n2) = bc.submit_local_transaction(tx2, 1_000);
        assert_eq!(o2, LocalTransactionOutcome::NotReady);
        assert!(matches!(n2, NextCall::Idle));
    }

    /// AC5 — the single-genesis guard: once an anchor exists, a second distinct
    /// `sequence == 0` block is rejected as invalid evidence (FR16) — not stored,
    /// not made a Stored orphan (which would emit perpetual bogus parent-recovery
    /// and break the `chain_heads` "tail never seq 0" invariant), and it never
    /// reseats the active chain.
    #[test]
    fn single_genesis_guard_rejects_second_seq0() {
        let mut bc = new_test_chain();

        // First genesis (seq 0) anchors the active chain at slot 0.
        let g1 = node_transfer_block(0, 7, 0, 7);
        let (o1, _) = bc.receive_block(g1.view(), 100);
        assert_eq!(o1, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(bc.active_chain_head_idx, 0);
        assert_eq!(bc.current_active_head(), Some(0));
        assert_eq!(bc.blocks.len(), 1);

        // A second, distinct seq-0 block (different vote/initializer → different
        // hash) is rejected and leaves the chain untouched.
        let g2 = node_transfer_block(0, 3, 0, 3);
        assert_ne!(
            g1.view().hash(),
            g2.view().hash(),
            "distinct genesis blocks"
        );
        let (o2, _) = bc.receive_block(g2.view(), 200);
        assert_eq!(
            o2,
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(
            bc.active_chain_head_idx, 0,
            "second genesis must not reseat the active chain"
        );
        assert_eq!(bc.blocks.len(), 1, "second genesis must not be stored");
        assert_eq!(bc.chain_heads.count(), 1, "no spurious Stored head created");
    }

    /// AC8 (FR63/NFR5) — the lifecycle/gating surface is deterministic and
    /// wall-clock-independent: replaying the identical init + block sequence with
    /// **different** `now` values yields identical phase, active-head, and gate
    /// outcomes. `now` affects only scheduling, never a phase/gate decision.
    #[test]
    fn lifecycle_surface_is_now_independent() {
        fn run(now_base: u64) -> (bool, Option<u32>, bool, bool) {
            let mut bc = new_test_chain();
            // Empty-storage init path (join).
            let (init_outcome, _) = bc.initialize_from_storage(now_base);
            assert_eq!(init_outcome, InitOutcome::StartedCollecting);
            // Anchor a genesis, then a rejected second genesis — with now derived
            // from now_base so the two runs use different timestamps.
            let g1 = node_transfer_block(0, 7, 0, 7);
            let o1 = bc.receive_block(g1.view(), now_base + 10).0;
            let g2 = node_transfer_block(0, 3, 0, 3);
            let o2 = bc.receive_block(g2.view(), now_base + 20).0;
            (
                o1 == ReceiveBlockOutcome::AcceptedSilently,
                bc.current_active_head(),
                o2 == ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
                bc.is_ready(),
            )
        }
        // Two replays with widely different wall-clock bases must agree.
        assert_eq!(run(1_000), run(9_999_999));
    }
}
