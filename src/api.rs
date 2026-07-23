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
    Block, BlockBuilder, BlockHeader, BlockView, HEADER_SIZE, MAX_BLOCK_SIZE, NodeTransfer,
    PAYLOAD_TYPE_BALANCE, PAYLOAD_TYPE_CHAIN_CONFIG, PAYLOAD_TYPE_TRANSACTION, REGISTRATION_SIZE,
    Registration, TransactionView,
};
use moonblokz_crypto::{CryptoTrait, PUBLIC_KEY_SIZE, PublicKeyTrait};
use moonblokz_storage::StorageTrait;
use moonblokz_vote::{VoteEngine, VoteEngineError};

use crate::blocks::{BlockEntry, BlockTable, NONE_REF};
use crate::chain_config::{ChainConfigError, ChainConfigTrait};
use crate::chain_heads::ChainHeadsTable;
use crate::intake::classify_block;
use crate::lifecycle::is_legal_transition;
use crate::node_info::NodeInfoState;
use crate::prng::Prng;
use crate::spent_bits::resolve_utxo_bit;
use crate::staged_validation::{BlockStatus, Tier1Failure, tier1_gate, verify_signature_bytes};

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
/// Ready-state-only). The ready-state classification set (`AcceptedToMempool`,
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

/// Why a block-retrieval query ([`Blockchain::query_block_by_hash`] /
/// [`Blockchain::query_block_by_sequence`]) returned no block.
///
/// A `Result` (not `Option`) so `NotReady` (FR42: block-retrieval is Ready-state-only)
/// stays distinct from the domain "absent" case: **Epic 10** adds `NotFound`
/// when it builds the ready-state body.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum BlockQueryError {
    /// FR1/FR42 — the module is not in `Ready`; block-retrieval is not served.
    NotReady,
}

/// Why the active-chain snake-chain window is unavailable — the `Err` side of
/// [`Blockchain::active_snake_chain_window`]. A `Result` rather than `Option`
/// so the *reason* there is no FR60 window is explicit, never a bare `None`.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub(crate) enum SnakeChainWindowError {
    /// Not in `Ready` (Collecting / Processing): no active chain, so no window —
    /// the FR60 check stays inactive and every admitted block is `Stored`.
    NotReady,
    /// `Ready`, but the `(S_tail, S_head)` derivation is Epic 9 (`snake_chain.rs`)
    /// and not yet available, so FR60 stays inactive even in `Ready`. Epic 9
    /// removes this arm when it supplies the real window (Ready branch → `Ok`).
    NotYetDerived,
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
// `BlockEntry.len` stores the exact stored block length as a `u16`; the FR6
// byte-exact trim (`e.len() as usize`) and the admit-time `set_len(len as u16)`
// rely on `MAX_BLOCK_SIZE` fitting a `u16`. Guard it at compile time so a future
// larger block size cannot silently truncate the trim length.
const _: () = assert!(MAX_BLOCK_SIZE <= u16::MAX as usize);

/// Failure modes of the FR3 processing pass (Story 5.3).
///
/// Derive-only: an `Err` routes to the minimal FR5 phase-revert in
/// [`Blockchain::receive_block`] (Processing→Collecting); the durable deletion
/// of the offending block is Story 5.5. Derives are test-only per the crate's
/// embedded-minimalism discipline (every trait impl costs binary size).
///
/// The `Vote` payload is diagnostic — read by tests now and by the Story 5.5
/// atomic recovery later; `allow(dead_code)` in non-test builds until then.
#[cfg_attr(test, derive(Debug, PartialEq))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ProcessingError {
    /// The marked candidate segment exceeded `MAX_BLOCKS` (corrupt ancestry).
    MarkOverflow,
    /// A marked block index was absent from the in-memory block-tree.
    MissingBlock,
    /// A candidate block's payload could not be read from durable storage.
    StorageRead,
    /// The vote engine rejected a block (FR37 checked-arithmetic over/underflow).
    Vote(VoteEngineError),
    /// FR6 full-chain validation (Story 5.4) found an invariant violation. The
    /// FR5 recovery (Story 5.5) reads `block_idx` — the **earliest** offending
    /// block on the forward pass — as its deletion target; `reason` records the
    /// violated invariant class for diagnostics / the FR64 log.
    Invalid {
        block_idx: u32,
        reason: ValidationReason,
    },
}

/// Which FR6 invariant a candidate block violated (Story 5.4). Diagnostic /
/// forward-log detail carried by [`ProcessingError::Invalid`]; the FR5 recovery
/// only needs the offending `block_idx`, so this is test-visible only.
#[cfg_attr(test, derive(Debug, PartialEq, Clone, Copy))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ValidationReason {
    /// Block bytes exceed the durable-locked chain-config `block_size_limit`.
    BlockTooLarge,
    /// A `payload_type=1` block whose payload does not parse as transactions.
    MalformedPayload,
    /// `previous_hash` does not link to the immediately-preceding candidate block.
    PreviousHashMismatch,
    /// A `payload_type=1` block carries both a registration and a complex tx.
    RegistrationComplexMutualExclusion,
    /// Block-creator signature invalid against the creator's derived key.
    CreatorSignatureInvalid,
    /// A node-transfer / registration transaction signature is invalid.
    TransactionSignatureInvalid,
    /// A node-transfer / balance-input `anchor_sequence` is not before the block.
    AnchorNotBeforeBlock,
    /// A debit (transfer amount+fee, registration price+fee, balance input)
    /// exceeds the initializer's derived balance (negative-balance outcome).
    InsufficientBalance,
    /// A registration `new_node_id` is not `pre-block max_known_node_id + 1`
    /// (out of the stride-1 sequence).
    RegistrationWatermark,
    /// A transaction's `vote` names a node absent from the candidate roster at
    /// its inclusion point.
    VoteTargetUnknown,
    /// A transaction's `initializer` equals its `vote` (outside the node-#0 /
    /// block-#0 exceptions).
    SelfVote,
    /// A complex tx UTXO input does not resolve against the candidate window
    /// (no matching transaction, or `output_index` out of bounds).
    UtxoUnresolvable,
    /// A complex tx UTXO input references an output whose spent-bit is already 1.
    UtxoAlreadySpent,
    /// A `payload_type=3` block's config content is not byte-identical to the
    /// durable-locked configuration.
    ChainConfigMismatch,
    /// A balance block after the earliest carries a `max_node_id` that diverges
    /// from the forward-tracked watermark at its sequence (FR3/FR6).
    BalanceMaxNodeIdMismatch,
    /// On a **genesis-anchored** candidate (the whole chain is re-derivable from
    /// block #0), a non-genesis block's creator or a transaction's initializer is
    /// not present on the derived roster — i.e. it acts before it exists. There is
    /// no pre-seed trust zone on a genesis-anchored candidate, so this is exact
    /// evidence of invalidity (FR6). (On a window-anchored candidate the same
    /// unseeded state is legitimately trusted pre-window history, AC4.)
    UnseededActor,
    /// A registration's `new_public_key` is not globally unique within the
    /// candidate — an earlier accepted registration (or balance-block seed) on the
    /// candidate already carries the same key (FR6 registration uniqueness).
    DuplicatePublicKey,
    /// A balance-only complex transaction's total balance inputs are less than its
    /// total balance outputs (money creation). The UTXO-value side of this
    /// invariant is validated with the Story-7.1 UTXO cache (see Dev Notes).
    InsufficientInputs,
}

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

    // FR6/FR34/FR50 per-node derived projection (SoA), introduced by Story 5.3
    // (FR3 reconstruction substrate). Story 7.1 adds the FR34 queryable surface
    // + block-navigation/UTXO cache on top; FR50 `seed_source_sequence`
    // two-trigger machinery lands in Story 9.3. Accumulated vote is owned by
    // `vote_engine` below, not duplicated here.
    node_info: NodeInfoState<MAX_NODES>,

    // FR37/FR38 accumulated-vote registry + creator-order projection, owned by
    // the Epic-3 `moonblokz-vote` crate. First driven by Story 5.3's FR3 pass
    // (`VoteEngine::apply_block` / `seed_from_balance_block`); reused by the
    // FR23 chain-switch walk (Epic 6) and the FR59 restart (Story 5.7).
    vote_engine: VoteEngine<MAX_NODES>,

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
        // Read the FR37 vote parameters from the config before it is moved into
        // `dst` (the config is still owned here; no field is read before write).
        let vote_scale = chain_config.vote_scale();
        let vote_interest = chain_config.vote_interest();
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
            // SoA + vote registry init in place (never a MAX_NODES-scaled stack
            // temporary — Epic-4-retro §8 RAM watch-item).
            NodeInfoState::init_in_place(core::ptr::addr_of_mut!((*dst).node_info));
            VoteEngine::init_in_place(
                core::ptr::addr_of_mut!((*dst).vote_engine),
                vote_scale,
                vote_interest,
            );
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
        entry_0.set_len(block_0.len() as u16);
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
        entry_1.set_len(block_1.len() as u16);
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

    /// FR2 dominant-chain acquisition: evaluate the collecting-phase stopping
    /// condition over the current block-tree and return the selected candidate
    /// tip's block-table index, or `None` if no candidate yet qualifies. The
    /// returned `u32` is this node's **local** handle to the chosen tip (indices
    /// are assigned by local admission order); the cross-node-deterministic
    /// quantity is the tip's identity (hash), which the tie-break orders on.
    ///
    /// Pure and side-effect-free (reads `chain_heads` + `blocks`; no `now`, no
    /// PRNG, no mutation — FR63/NFR5 determinism). A candidate is an occupied
    /// `chain_heads` tip whose continuous segment is either **genesis-anchored**
    /// (earliest block has `sequence == 0`, FR54) or **active-length-satisfying**
    /// (segment length `≥ SNAKE_CHAIN_LENGTH`). The earliest block is the head's
    /// cached `tail_or_connection_idx` (the tail for a Stored head; the
    /// connection-point for a head Connected to the bootstrap-anchored genesis —
    /// which while collecting is the genesis, `sequence 0`), so no ancestry
    /// re-walk is needed; continuity implies consecutive sequences, so segment
    /// length is exact sequence arithmetic.
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
            if !(genesis_anchored || segment_len >= SNAKE_CHAIN_LENGTH) {
                continue;
            }
            let tip_hash = *tip.hash();
            let better = match best {
                None => true,
                Some((_, best_seq, best_hash)) => {
                    tip_seq > best_seq || (tip_seq == best_seq && tip_hash < best_hash)
                }
            };
            if better {
                best = Some((head_idx, tip_seq, tip_hash));
            }
        }
        best.map(|(head_idx, _, _)| head_idx)
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
        let block_size_limit = self.chain_config.block_size_limit();
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
        entry.set_len(block.len() as u16); // exact length for the FR6 byte-exact checks (Story 5.4)
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
        // FR60 window if Ready+available (Epic 9); any `Err` → no window → FR60 skipped.
        let window = self.active_snake_chain_window().ok();
        let outcome = classify_block(self, &block, window, now);
        // FR2 dominant-chain acquisition (Story 5.2): a successful collecting-phase
        // admission may complete a candidate segment. Evaluate the stopping
        // condition and, on success, transition Collecting→Processing. Runs only
        // after a real admission (not on duplicate/reject) and only while
        // Collecting (Processing/Ready never re-trigger). `AcceptedSilently` is
        // currently the sole accept outcome; when Epic 6/8 add `AcceptedAndSend*`
        // accept variants they must be included in this gate (else a block admitted
        // under them would miss the transition).
        if outcome == ReceiveBlockOutcome::AcceptedSilently
            && self.lifecycle_phase == LifecyclePhase::Collecting
            && let Some(candidate_tip_idx) = self.evaluate_stopping_condition()
        {
            self.set_lifecycle_phase(LifecyclePhase::Processing);
            // Story 5.3 (FR3) + Story 5.4 (FR6/FR4): reconstruct AND validate the
            // derived projection for the FR2 candidate in one forward pass. A
            // bootstrap-anchored genesis's `active_chain_head_idx` is a placeholder
            // the Ready transition below overwrites; it does not pre-empt selection.
            match self.run_processing_pass(candidate_tip_idx) {
                Ok(()) => {
                    // FR6 passed over the full candidate → FR4 Ready transition:
                    // atomically promote every candidate block Stored→Active
                    // (the Epic-4-deferred FR9 Tier-3 driver), establish the active
                    // head, and move Processing→Ready. The FR40-series ready-only
                    // surface becomes live (its query bodies remain Epic 7/10
                    // `todo!()` — reachable, but this story wires no caller).
                    self.promote_candidate_active(candidate_tip_idx);
                    self.set_lifecycle_phase(LifecyclePhase::Ready);
                }
                Err(_) => {
                    // FR6 failed (or FR3 could not derive). Discard the partial
                    // working set and take the minimal FR5 phase-revert
                    // (Processing→Collecting) so the node retries against the tree
                    // on the next admission. `run_processing_pass` already rolled
                    // back any spent-bit it flipped; reset the rest of the working
                    // set here. The **durable deletion** of the offending block
                    // (captured in the `Err`'s `block_idx`) + its transitive
                    // descendants + the chain_heads mutation event (iv) is the
                    // Story 5.5 (FR5) atomic recovery.
                    self.node_info.reset();
                    self.reset_vote_engine();
                    self.set_lifecycle_phase(LifecyclePhase::Collecting);
                }
            }
        }
        (outcome, self.next_parent_recovery_call())
    }

    /// Re-initializes the vote registry to its empty seeded baseline in place
    /// (FR3 "not resumable — clean working set on re-entry", AC5). Re-running
    /// `init_in_place` over the already-initialized POD field is sound: every
    /// field is a plain integer / array with no `Drop`, and `.write` does not
    /// read the prior value.
    fn reset_vote_engine(&mut self) {
        let vote_scale = self.chain_config.vote_scale();
        let vote_interest = self.chain_config.vote_interest();
        // SAFETY: `self.vote_engine` is a live, initialized POD value; re-init
        // overwrites it field-by-field with no drop and no read-before-write.
        unsafe {
            VoteEngine::init_in_place(
                core::ptr::addr_of_mut!(self.vote_engine),
                vote_scale,
                vote_interest,
            );
        }
    }

    /// FR3 processing-pass forward state reconstruction (Story 5.3).
    ///
    /// Backward-marks the candidate segment from `candidate_tip_idx`, then walks
    /// it strictly forward from the anchor, deriving the complete active-chain
    /// projection into `node_info` (roster, public keys, balances, seed sources,
    /// `max_known_node_id`) and `vote_engine` (accumulated vote + creator order,
    /// FR37/FR38). `pub(crate)` and self-contained so the FR59 restart (Story 5.7)
    /// and the FR23 deep-zone reconstruction (Epic 6) reuse the same primitive.
    ///
    /// **Derive-only** (Decision #2): it does not validate FR6 invariants, promote
    /// Stored→Active, or transition to Ready (Story 5.4), nor perform the FR5
    /// atomic recovery (Story 5.5). Reads no wall-clock (`now`-independent —
    /// FR63/NFR5); the only PRNG use is whatever `VoteEngine` performs internally
    /// (none for accumulation).
    pub(crate) fn run_processing_pass(
        &mut self,
        candidate_tip_idx: u32,
    ) -> Result<(), ProcessingError> {
        // AC5: clean working set on (re-)entry — no partial projection persists.
        self.node_info.reset();
        self.reset_vote_engine();

        // AC1: backward mark tip → anchor along `parent_ref`, bounded by
        // MAX_BLOCKS. `marked[0] = tip … marked[count-1] = anchor`; the forward
        // traversal iterates the buffer in reverse (anchor → tip). Termination:
        // the anchor is either genesis (block #0, `parent_ref == NONE_REF`) or a
        // retained-window tail whose `previous_hash` is unresolved locally (also
        // `parent_ref == NONE_REF`, set at admission) — both stop the walk.
        let mut marked = [NONE_REF; MAX_BLOCKS];
        let mut count = 0usize;
        let mut cur = candidate_tip_idx;
        loop {
            if count >= MAX_BLOCKS {
                return Err(ProcessingError::MarkOverflow);
            }
            marked[count] = cur;
            count += 1;
            let entry = self.blocks.get(cur).ok_or(ProcessingError::MissingBlock)?;
            let parent = entry.parent_ref();
            if parent == NONE_REF {
                break;
            }
            cur = parent;
        }

        // AC5 (spent-bit lifecycle): establish the clean all-zero baseline for the
        // marked segment's spent-bits at entry — matching the `node_info` /
        // `vote_engine` reset above — so the pass is idempotent on re-entry and the
        // failure rollback below restores exactly this baseline (not the whole
        // vector against an unknown prior state). For the MVP join/reconstruct flow
        // the marked blocks are freshly-admitted `Stored` blocks (spent-bits already
        // 0); the reset makes the reusable primitive self-consistent for the
        // Story-5.7 restart and Epic-6 deep-zone re-derivation.
        for slot in marked.iter().take(count) {
            self.blocks.clear_spent_bits(*slot);
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

        // AC1/AC2-AC7 (Story 5.4): forward traversal anchor → tip, validating
        // each block against the FR6 invariant set at the point it becomes
        // checkable — interleaved with the FR3 derivation, so every check reads
        // the state derived from the *preceding* candidate blocks. The earliest
        // offending block aborts with `ProcessingError::Invalid { block_idx, .. }`
        // (the FR5 recovery, Story 5.5, reads `block_idx` as its deletion target).
        // Spent-bits flipped mid-pass are rolled back below on any abort (the FR5
        // working-set rollback's UTXO half); on success they persist as the active
        // chain's UTXO-consumption state.
        let mut saw_balance_block = false;
        let mut prev_hash: Option<[u8; 32]> = None;
        let mut result = Ok(());
        for i in (0..count).rev() {
            let idx = marked[i];
            let block = match self.storage.read_block(idx) {
                Ok(b) => b,
                Err(_) => {
                    result = Err(ProcessingError::StorageRead);
                    break;
                }
            };
            // Trim the zero-padded read-back block to its exact stored length so
            // the byte-exact FR6 checks (block-creator signature, chain-config
            // content-identity, hash linkage) see the bytes originally signed —
            // durable backends store blocks in fixed-size slots and read them
            // back padded (Story 5.4).
            let full = block.serialized_bytes();
            let n = match self.blocks.get(idx).map(|e| e.len() as usize) {
                Some(len) if len > 0 && len <= full.len() => len,
                _ => full.len(),
            };
            let view = match BlockView::from_bytes(&full[..n]) {
                Ok(v) => v,
                Err(_) => {
                    result = Err(ProcessingError::StorageRead);
                    break;
                }
            };
            let this_hash = view.hash();
            if let Err(e) = self.validate_and_derive_block(
                view,
                idx,
                prev_hash,
                &mut saw_balance_block,
                &marked,
                genesis_anchored,
            ) {
                result = Err(e);
                break;
            }
            prev_hash = Some(this_hash);
        }
        if result.is_err() {
            for slot in marked.iter().take(count) {
                self.blocks.clear_spent_bits(*slot);
            }
        }
        result
    }

    /// Validates one candidate block against the FR6 invariant set **and**
    /// applies its effects to the derived projection (Story 5.4, interleaved with
    /// the Story-5.3 FR3 derivation). Every check reads the state derived from the
    /// preceding candidate blocks; per-node state-dependent checks (balance,
    /// signature, vote-target) are **gated on the initializer being seeded** —
    /// the FR3 pre-seed-zone trust rule (AC4): a window-anchored candidate trusts
    /// history it cannot yet re-derive, so full FR6 re-proof is complete only for
    /// a genesis-anchored candidate. Returns the earliest offending block's
    /// `ProcessingError::Invalid { block_idx, reason }` on violation.
    ///
    /// `marked` is the candidate segment (tip..anchor); the UTXO-input resolution
    /// (AC4) scans it to locate a referenced output's containing block.
    fn validate_and_derive_block(
        &mut self,
        view: BlockView<'_>,
        idx: u32,
        prev_hash: Option<[u8; 32]>,
        saw_balance_block: &mut bool,
        marked: &[u32; MAX_BLOCKS],
        genesis_anchored: bool,
    ) -> Result<(), ProcessingError> {
        // `view` is the block trimmed to its exact stored length. `bytes` re-views
        // it for the by-value `VoteEngine` calls (`BlockView` is not `Copy`).
        let bytes = view.serialized_bytes();
        let seq = view.sequence();
        // FR54 genesis exceptions: block #0 waives no-self-vote / anchor /
        // watermark-`+1` and mints currency (FR54(d)); blocks #0/#1 are
        // FR36-exempt.
        let is_genesis_zero = seq == 0;
        let is_genesis = is_genesis_zero || seq == 1;
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };

        // --- FR6 block-level invariants (AC2) ---------------------------------
        // (a) size ≤ durable-locked chain-config limit.
        if view.len() > self.chain_config.block_size_limit() as usize {
            return Err(invalid(ValidationReason::BlockTooLarge));
        }
        // (b) previous_hash links to the immediately-preceding candidate block
        //     (the anchor has no in-segment predecessor → `prev_hash == None`).
        if let Some(ph) = prev_hash
            && view.previous_hash() != &ph[..]
        {
            return Err(invalid(ValidationReason::PreviousHashMismatch));
        }
        // (c) block-creator signature (first signature check anywhere in the
        //     crate). Skipped when the creator's key is not yet derivable
        //     (pre-seed zone → trusted); node #0 always resolves to the FR69
        //     trust anchor, so a genesis-anchored candidate's block #0 is checked.
        match self.verify_block_creator_signature(&view) {
            Some(false) => return Err(invalid(ValidationReason::CreatorSignatureInvalid)),
            // On a genesis-anchored candidate the creator's key must be derivable
            // (it registered earlier in the same fully-re-derived chain); a
            // non-derivable creator on a non-genesis block is exact evidence of
            // invalidity, not a trusted pre-seed block (AC2/AC4 genesis-anchored).
            None if genesis_anchored && !is_genesis => {
                return Err(invalid(ValidationReason::UnseededActor));
            }
            _ => {}
        }

        // FR36 (b) transaction-fee total; consumed by the shared creator tail.
        let mut total_fees: u64 = 0;

        match view.payload_type() {
            PAYLOAD_TYPE_BALANCE => {
                let payload = view
                    .balances()
                    .ok_or(invalid(ValidationReason::MalformedPayload))?;
                if !*saw_balance_block {
                    // Earliest balance block: initialize the watermark from its
                    // `max_node_id` (FR3/FR54(h)).
                    let advanced = self
                        .node_info
                        .max_known_node_id()
                        .max(payload.max_node_id());
                    self.node_info.set_max_known_node_id(advanced);
                    *saw_balance_block = true;
                } else if payload.max_node_id() != self.node_info.max_known_node_id() {
                    // AC7 (deferred from 5.3): every balance block after the
                    // earliest must carry `max_node_id` == the forward-tracked
                    // watermark at its sequence.
                    return Err(invalid(ValidationReason::BalanceMaxNodeIdMismatch));
                }
                for info in payload.iter() {
                    self.node_info
                        .seed_node(info.owner(), info.public_key(), info.balance(), idx);
                }
                if let Ok(v) = BlockView::from_bytes(bytes) {
                    self.vote_engine.seed_from_balance_block(v);
                }
            }
            PAYLOAD_TYPE_TRANSACTION => {
                let txs = view
                    .transactions()
                    .ok_or(invalid(ValidationReason::MalformedPayload))?;
                let mut has_registration = false;
                let mut has_complex = false;

                for tx in txs.iter() {
                    let vote = tx.vote();
                    if let Some(nt) = tx.as_node_transfer() {
                        let init = nt.initializer();
                        // [A] Genesis-anchored: an unseeded initializer means the
                        // node transacts before it exists — invalid (no pre-seed
                        // trust zone). Window-anchored: trusted pre-window history.
                        if genesis_anchored && !is_genesis_zero && !self.node_info.is_seeded(init) {
                            return Err(invalid(ValidationReason::UnseededActor));
                        }
                        // State-dependent FR6 checks apply once the initializer is
                        // derivable (past its pre-seed zone).
                        if !is_genesis_zero && self.node_info.is_seeded(init) {
                            self.check_self_vote(init, vote).map_err(&invalid)?;
                            self.check_vote_target(vote).map_err(&invalid)?;
                            if seq <= nt.anchor_sequence() {
                                return Err(invalid(ValidationReason::AnchorNotBeforeBlock));
                            }
                            if !self.verify_tx_signature(tx.as_bytes(), init) {
                                return Err(invalid(ValidationReason::TransactionSignatureInvalid));
                            }
                        }
                        let fee = nt.fee() as u64;
                        let debit = nt.amount().saturating_add(fee);
                        if is_genesis_zero {
                            // FR54(d): the genesis self-transfer *creates* currency
                            // — credit the receiver, no debit (bypass the balance
                            // check), so node #0's balance becomes the initial
                            // total network currency explicitly.
                            if self.node_info.is_seeded(nt.receiver()) {
                                self.node_info.credit(nt.receiver(), nt.amount());
                            }
                        } else if self.node_info.is_seeded(init) {
                            if self.node_info.balance_of(init) < debit {
                                return Err(invalid(ValidationReason::InsufficientBalance));
                            }
                            self.node_info.debit(init, debit);
                            if self.node_info.is_seeded(nt.receiver()) {
                                self.node_info.credit(nt.receiver(), nt.amount());
                            }
                        } else if self.node_info.is_seeded(nt.receiver()) {
                            // Pre-seed initializer: still credit a seeded receiver
                            // (its own state is derivable) — trust the debit side.
                            self.node_info.credit(nt.receiver(), nt.amount());
                        }
                        total_fees = total_fees.saturating_add(fee);
                    } else if let Some(reg) = tx.as_registration() {
                        has_registration = true;
                        let node_id = reg.new_node_id();
                        let init = reg.initializer();
                        // [A] Genesis-anchored: the registering initializer must be
                        // an existing (seeded) node; unseeded ⇒ invalid (block #0's
                        // node-#0 self-registration is the FR54 bootstrap exception).
                        if genesis_anchored && !is_genesis_zero && !self.node_info.is_seeded(init) {
                            return Err(invalid(ValidationReason::UnseededActor));
                        }
                        // FR6 registration monotonicity: `new_node_id ==
                        // pre-block-position watermark + 1`, checked against the
                        // running watermark so within-block registrations form a
                        // stride-1 sequence. Waived for genesis block #0
                        // (`new_node_id == 0`, FR54(h)).
                        if !is_genesis_zero {
                            let expected = self.node_info.max_known_node_id().wrapping_add(1);
                            if node_id != expected {
                                return Err(invalid(ValidationReason::RegistrationWatermark));
                            }
                            if self.node_info.is_seeded(init) {
                                self.check_self_vote(init, vote).map_err(&invalid)?;
                                self.check_vote_target(vote).map_err(&invalid)?;
                                if !self.verify_tx_signature(tx.as_bytes(), init) {
                                    return Err(invalid(
                                        ValidationReason::TransactionSignatureInvalid,
                                    ));
                                }
                                let debit = reg.registration_price().saturating_add(reg.fee());
                                if self.node_info.balance_of(init) < debit {
                                    return Err(invalid(ValidationReason::InsufficientBalance));
                                }
                                // `registration_price` is absorbed (debited, credited
                                // to no node); the fee goes to the creator (FR36).
                                self.node_info.debit(init, debit);
                                total_fees = total_fees.saturating_add(reg.fee());
                            }
                        }
                        // Advance the watermark for an in-range id (genesis #0 does
                        // not advance it — FR54(h)); then register the roster entry.
                        if !is_genesis_zero && (node_id as usize) < MAX_NODES {
                            let advanced = self.node_info.max_known_node_id().max(node_id);
                            self.node_info.set_max_known_node_id(advanced);
                        }
                        // [E] FR6 registration uniqueness: `new_public_key` must not
                        // already be held by a seeded/registered node on the
                        // candidate (within-block earlier registrations are seeded
                        // in tx order, so a same-block collision is caught too).
                        if self.node_info.key_is_registered(reg.new_public_key()) {
                            return Err(invalid(ValidationReason::DuplicatePublicKey));
                        }
                        self.node_info
                            .register_node(node_id, reg.new_public_key(), idx);
                    } else if let Some(cx) = tx.as_complex() {
                        has_complex = true;
                        let mut in_sum: u64 = 0;
                        let mut out_sum: u64 = 0;
                        let mut has_utxo_input = false;
                        for input in cx.inputs() {
                            if let Some(bi) = input.as_balance() {
                                let binit = bi.initializer();
                                // [A] Genesis-anchored: a balance-input initializer
                                // must be seeded (it spends a derived balance).
                                if genesis_anchored
                                    && !is_genesis_zero
                                    && !self.node_info.is_seeded(binit)
                                {
                                    return Err(invalid(ValidationReason::UnseededActor));
                                }
                                if !is_genesis_zero && self.node_info.is_seeded(binit) {
                                    self.check_self_vote(binit, vote).map_err(&invalid)?;
                                    self.check_vote_target(vote).map_err(&invalid)?;
                                    if seq <= bi.anchor_sequence() {
                                        return Err(invalid(
                                            ValidationReason::AnchorNotBeforeBlock,
                                        ));
                                    }
                                    if self.node_info.balance_of(binit) < bi.amount() {
                                        return Err(invalid(ValidationReason::InsufficientBalance));
                                    }
                                    self.node_info.debit(binit, bi.amount());
                                }
                                in_sum = in_sum.saturating_add(bi.amount());
                            } else if let Some(ui) = input.as_utxo() {
                                // [H] AC4: resolve the UTXO input against the
                                // candidate segment (only blocks *earlier* than this
                                // one — a causal reference), require its spent-bit ==
                                // 0, then flip it. The UTXO input's value (for the
                                // inputs≥outputs sum) and its signature are validated
                                // with the Story-7.1 UTXO cache (Decision: the UTXO
                                // value space is Story 7.1).
                                has_utxo_input = true;
                                let oi = ui.output_index();
                                let mut tr = [0u8; 32];
                                tr.copy_from_slice(&ui.tr_hash()[..32]);
                                self.resolve_and_spend_utxo(marked, seq, &tr, oi)
                                    .map_err(&invalid)?;
                            }
                        }
                        for output in cx.outputs() {
                            if let Some(bo) = output.as_balance() {
                                if self.node_info.is_seeded(bo.receiver()) {
                                    self.node_info.credit(bo.receiver(), bo.amount());
                                }
                                out_sum = out_sum.saturating_add(bo.amount());
                            }
                        }
                        // [D] FR6 total-inputs ≥ total-outputs, enforced for a
                        // balance-only complex tx with ≥1 input (a zero-input
                        // carry-forward is exempt per FR6). When the tx has a UTXO
                        // input, `in_sum` omits the UTXO-side value (Story 7.1), so
                        // the full inputs≥outputs check lands with that value cache.
                        if !has_utxo_input && cx.input_count() > 0 && out_sum > in_sum {
                            return Err(invalid(ValidationReason::InsufficientInputs));
                        }
                        total_fees = total_fees.saturating_add(in_sum.saturating_sub(out_sum));
                    } else {
                        return Err(invalid(ValidationReason::MalformedPayload));
                    }
                }
                // FR6 registration/complex mutual-exclusivity (also gated at Tier 1
                // intake; re-affirmed here over the candidate).
                if has_registration && has_complex {
                    return Err(invalid(
                        ValidationReason::RegistrationComplexMutualExclusion,
                    ));
                }
            }
            PAYLOAD_TYPE_CHAIN_CONFIG => {
                // AC6: every chain-config block must carry config content
                // byte-identical to the durable-locked configuration, when one is
                // present. Establishing the lock from the candidate (no lock yet)
                // and the FR7 content-signature are Story 5.6.
                if let Some(locked) = self.chain_config.initial_chain_config_bytes()
                    && view.payload() != locked
                {
                    return Err(invalid(ValidationReason::ChainConfigMismatch));
                }
            }
            _ => {
                // Approval-evidence (payload_type=4): full validation is deferred
                // to Epic 6 (the deterministic supporting-subgroup primitive it
                // needs, ADR-015 / FR27/FR28, is unbuilt). The shared tail still
                // applies this block's FR37 vote effects.
            }
        }

        // Shared FR37 + FR36 tail (every payload type): apply this block's vote
        // effects once (anti-capture interest + creator reset), then credit the
        // creator with (a) mined_amount + (b) transaction fees. Gated on
        // `is_seeded` so a pre-seed-zone creator is auto-accepted; genesis blocks
        // #0/#1 are FR36-exempt. FR36(c) replay-block reward is deferred (Epic 9).
        if let Ok(v) = BlockView::from_bytes(bytes) {
            self.vote_engine
                .apply_block(v)
                .map_err(ProcessingError::Vote)?;
        }
        if !is_genesis && self.node_info.is_seeded(view.creator()) {
            self.node_info.credit(
                view.creator(),
                (view.mined_amount() as u64).saturating_add(total_fees),
            );
        }
        Ok(())
    }

    /// FR6 no-self-vote (AC5): a transaction's `initializer` must not equal its
    /// `vote`, with the permanent node-#0 self-vote exception. (Also enforced at
    /// Tier 1 intake; re-affirmed here over the candidate.)
    fn check_self_vote(&self, initializer: u32, vote: u32) -> Result<(), ValidationReason> {
        if initializer == 0 && vote == 0 {
            return Ok(());
        }
        if initializer == vote {
            return Err(ValidationReason::SelfVote);
        }
        Ok(())
    }

    /// FR6 vote-target existence (AC5): the `vote` node id must be present on the
    /// candidate roster at the transaction's inclusion point (a node is on the
    /// roster once seeded/registered during the forward pass). Node #0 is the
    /// permanent exception — it is established at genesis and exists on every
    /// chain, so `vote == 0` is always a valid target (FR37/FR54 node-#0
    /// vote-target exception), even for a window-anchored candidate that does not
    /// itself contain block #0.
    fn check_vote_target(&self, vote: u32) -> Result<(), ValidationReason> {
        if vote == 0 || self.node_info.is_seeded(vote) {
            Ok(())
        } else {
            Err(ValidationReason::VoteTargetUnknown)
        }
    }

    /// Verifies the FR6 block-creator signature (AC2b) over the canonical signing
    /// preimage (the full block bytes with the trailing-64 header signature field
    /// zero-filled — exactly what `BlockBuilder::build_signed` signs; the
    /// signature is the last 64 bytes of the fixed `HEADER_SIZE` header). Returns
    /// `Some(valid)`, or `None` when the creator's public key is not yet derivable
    /// (pre-seed zone → the block is trusted, not re-proved). Node #0 resolves to
    /// the FR69 trust anchor (`node_zero_public_key`), available from construction.
    fn verify_block_creator_signature(&self, view: &BlockView) -> Option<bool> {
        let creator = view.creator();
        let key: [u8; PUBLIC_KEY_SIZE] = if creator == 0 {
            self.node_zero_public_key
        } else {
            *self.node_info.public_key_of(creator)?
        };
        const SIG_LEN: usize = 64;
        let sig_off = HEADER_SIZE - SIG_LEN;
        let bytes = view.serialized_bytes();
        let len = bytes.len();
        let mut preimage = [0u8; MAX_BLOCK_SIZE];
        preimage[..len].copy_from_slice(bytes);
        for b in preimage[sig_off..HEADER_SIZE].iter_mut() {
            *b = 0;
        }
        Some(verify_signature_bytes(
            &self.crypto,
            &preimage[..len],
            view.signature(),
            &key,
        ))
    }

    /// Verifies a node-transfer / registration transaction signature (AC3): the
    /// signer (the `signer_node_id`, resolved to its derived key) signs the full
    /// transaction bytes with the trailing-64 signature field zero-filled (the
    /// `*::new_signed` convention — the signature is the last 64 bytes of the
    /// fixed-size transaction). Returns `false` on an unresolvable signer key or a
    /// bad signature. Only node-transfer / registration transactions have this
    /// fixed trailing-64 layout; balance/UTXO input signatures (embedded, no
    /// `new_signed` convention) are a deferred seam.
    fn verify_tx_signature(&self, tx_bytes: &[u8], signer_node_id: u32) -> bool {
        let Some(key) = self.node_info.public_key_of(signer_node_id) else {
            return false;
        };
        let key = *key;
        let len = tx_bytes.len();
        if !(64..=REGISTRATION_SIZE).contains(&len) {
            return false;
        }
        let mut preimage = [0u8; REGISTRATION_SIZE];
        preimage[..len].copy_from_slice(tx_bytes);
        for b in preimage[len - 64..len].iter_mut() {
            *b = 0;
        }
        verify_signature_bytes(
            &self.crypto,
            &preimage[..len],
            &tx_bytes[len - 64..len],
            &key,
        )
    }

    /// AC4: resolves a UTXO input reference `(tr_hash, output_index)` against the
    /// candidate segment `marked`, requires the referenced output's spent-bit to
    /// be 0 (unspent), then flips it to 1. Returns [`ValidationReason::UtxoUnresolvable`]
    /// if no candidate block holds a matching transaction / the index is out of
    /// bounds, or [`ValidationReason::UtxoAlreadySpent`] on a double-spend. Scans
    /// the marked set re-reading each block from storage — O(segment) per input;
    /// the FR34 block-navigation/UTXO cache that makes this O(1) is Story 7.1.
    fn resolve_and_spend_utxo(
        &mut self,
        marked: &[u32; MAX_BLOCKS],
        consuming_seq: u32,
        tr_hash: &[u8; 32],
        output_index: u8,
    ) -> Result<(), ValidationReason> {
        for &m_idx in marked.iter() {
            if m_idx == NONE_REF {
                continue;
            }
            // [H] Causality: a UTXO output can only be consumed by a block that
            // comes *after* the block that created it. Skip any candidate block at
            // or after the consuming block's sequence — resolving against a
            // same/later block would let a tx spend an output that does not exist
            // yet at its own point in the chain.
            if self
                .blocks
                .get(m_idx)
                .is_none_or(|e| e.sequence() >= consuming_seq)
            {
                continue;
            }
            let Ok(candidate) = self.storage.read_block(m_idx) else {
                continue;
            };
            if let Some(bit) = resolve_utxo_bit(&candidate.view(), tr_hash, output_index) {
                return match self.blocks.spent_bit(m_idx, bit) {
                    Some(false) => {
                        self.blocks.set_spent_bit(m_idx, bit, true);
                        Ok(())
                    }
                    Some(true) => Err(ValidationReason::UtxoAlreadySpent),
                    None => Err(ValidationReason::UtxoUnresolvable),
                };
            }
        }
        Err(ValidationReason::UtxoUnresolvable)
    }

    /// FR4 / FR9 Tier-3 Active-promotion driver (AC9): on a clean FR6 pass, walk
    /// the validated candidate tip → anchor and atomically flip every block
    /// `Stored → Active` with `is_on_active_chain = true`, then establish
    /// `active_chain_head_idx = tip` (overwriting any Story-5.2 bootstrap
    /// placeholder). A pure `parent_ref` walk (no storage reads), bounded by
    /// `MAX_BLOCKS`.
    fn promote_candidate_active(&mut self, candidate_tip_idx: u32) {
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

    // --- State-changing Ready-state-only intake entry points (FR14 / FR55) ---------
    // Not-ready-gated in Story 5.1 (FR1). These are **state-changing** (`&mut
    // self`) and carry a `NextCall` (AR4) — grouped here with the other
    // state-changing methods (`receive_block`, `on_tick`), NOT with the read-only
    // queries below. While not `Ready` each returns its `Outcome::NotReady` with
    // `NextCall::Idle`; the ready-state body is built by the owning epic
    // (`todo!()` forward-tag, reachable only by a genesis(Ready) node in tests).

    /// FR14/FR10 transaction intake (Ready-state-only). While not `Ready` the module
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

    /// FR55 local transaction-creation surface (Ready-state-only). While not `Ready`
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

    // --- Read-only queries, served only in Ready (FR40-FR44) -----------------
    // Not-ready-gated in Story 5.1 (FR1). Read-only (no `NextCall`, AR4) and
    // served only in `Ready`: while Collecting/Processing each returns
    // `Err(E::NotReady)`. `Result<T, E>` (not `Option`) so `NotReady` ≠ the
    // domain "absent" case. Ready-state lookup is built by the owning epic
    // (`todo!()` forward-tag, reachable only by a genesis(Ready) node in tests).
    // (The state-changing intake entry points `receive_transaction` /
    // `submit_local_transaction` are grouped above with the state-changing
    // methods, not here — they carry a `NextCall`.)

    /// FR41 node-balance query (Ready-state-only). `Err(BalanceQueryError::NotReady)`
    /// while not `Ready`; the ready-state lookup (and the `UnknownNode` arm) is
    /// **Epic 10**. A `Result`, not `Option`, so not-ready stays distinct from a
    /// missing node and from a legitimate zero balance.
    pub fn query_balance(&self, _node_id: u32) -> Result<u64, BalanceQueryError> {
        if !self.is_ready() {
            return Err(BalanceQueryError::NotReady);
        }
        todo!("FR41 ready-state balance lookup — Epic 10")
    }

    /// FR42 block-retrieval by hash (Ready-state-only). `Err(BlockQueryError::NotReady)`
    /// while not `Ready` — a collecting node does not serve blocks, including
    /// radio-forwarded peer requests (FR1). Ready-state lookup (and the
    /// `NotFound` arm) is **Epic 10**.
    pub fn query_block_by_hash(&self, _hash: &[u8; 32]) -> Result<BlockView<'_>, BlockQueryError> {
        if !self.is_ready() {
            return Err(BlockQueryError::NotReady);
        }
        todo!("FR42 ready-state block retrieval by hash — Epic 10")
    }

    /// FR42 block-retrieval by sequence (Ready-state-only). `Err(BlockQueryError::NotReady)`
    /// while not `Ready`. Ready-state lookup is **Epic 10**.
    pub fn query_block_by_sequence(&self, _seq: u32) -> Result<BlockView<'_>, BlockQueryError> {
        if !self.is_ready() {
            return Err(BlockQueryError::NotReady);
        }
        todo!("FR42 ready-state block retrieval by sequence — Epic 10")
    }

    /// FR40 transaction-state query (Ready-state-only). `Err(TxStateQueryError::NotReady)`
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

    // FR44 creator-role determination is deliberately NOT a public query here.
    // It is an Epic-8-internal input to FR45 block creation (phase-gated inside
    // the scheduler — the determination is simply not made while collecting); any
    // external visibility is feature-gated introspection (architecture §3.5),
    // never a first-class public API method. See the Story-5.1 review record.

    /// The active-chain `(S_tail, S_head)` sequence bounds for the FR60 window
    /// check, or an [`SnakeChainWindowError`] explaining why there is none.
    ///
    /// `Result` (not `Option`) so the *reason* is explicit: `Err(NotReady)` while
    /// not `Ready` (Collecting / Processing — no active chain) and
    /// `Err(NotYetDerived)` in `Ready` until Epic 9 (`snake_chain.rs`) supplies
    /// the real window from the `_snake_chain_tail_idx` / `active_chain_head_idx`
    /// indices. Either `Err` leaves the FR60 window inactive, so every admitted
    /// block stays `Stored` (FR9/AC6). The intake caller only needs "window or
    /// not", so it maps this with `.ok()`.
    fn active_snake_chain_window(&self) -> Result<(u32, u32), SnakeChainWindowError> {
        if !self.is_ready() {
            return Err(SnakeChainWindowError::NotReady);
        }
        // Epic 9 returns `Ok((s_tail, s_head))` here; until then the window is not
        // derivable, so FR60 stays inactive even in Ready.
        Err(SnakeChainWindowError::NotYetDerived)
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
    use moonblokz_crypto::{Crypto, PRIVATE_KEY_SIZE, SignatureTrait};
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
        assert_eq!(
            bc.active_snake_chain_window(),
            Err(SnakeChainWindowError::NotReady)
        );
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

    /// AC4 — the read-only queries return `Err(NotReady)` while Collecting (a
    /// `Result`, so not-ready is a distinct signal, not `None`).
    #[test]
    fn collecting_gates_ready_only_queries() {
        let bc = new_test_chain();
        assert_eq!(bc.query_balance(1), Err(BalanceQueryError::NotReady));
        assert!(matches!(
            bc.query_block_by_hash(&[0u8; 32]),
            Err(BlockQueryError::NotReady)
        ));
        assert!(matches!(
            bc.query_block_by_sequence(0),
            Err(BlockQueryError::NotReady)
        ));
        assert_eq!(
            bc.query_transaction_state(&[0u8; 32]),
            Err(TxStateQueryError::NotReady)
        );
    }

    /// AC4 — state-changing Ready-state-only intake surfaces return `NotReady` with
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

    // --- Story 5.2: FR2 dominant-chain acquisition (stopping conditions + selection) ---

    /// A linked child block with a tweakable `vote` salt, so two blocks at the same
    /// `(sequence, previous_hash)` get distinct hashes — for the tie-break test.
    fn salted_linked_block(seq: u32, prev: [u8; 32], vote: u32) -> Block {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let nt = NodeTransfer::new_signed(vote, seq.saturating_sub(1), 7, 9, 100, 1, 0, &signer);
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

    /// AC4/AC7 — an orphan block whose short segment neither reaches genesis nor
    /// spans `W` leaves the node Collecting (no candidate); parent recovery still
    /// schedules (the FR2 evaluation is side-effect-free w.r.t. the tick cadence).
    #[test]
    fn fr2_no_candidate_stays_collecting() {
        let mut bc = new_test_chain();
        let orphan = node_transfer_block(5, 3, 4, 7); // tail seq 5, len 1, not genesis
        let (outcome, next) = bc.receive_block(orphan.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert!(bc.evaluate_stopping_condition().is_none());
        assert!(bc.current_phase() == LifecyclePhase::Collecting);
        assert!(
            matches!(next, NextCall::At(_)),
            "parent recovery still scheduled while collecting"
        );
    }

    /// AC2/AC5/AC6 + Story 5.4 — receiving the genesis (a length-1
    /// genesis-anchored segment) satisfies FR2 at once and, since block #0 passes
    /// the (genesis-waived) FR6 invariant set, the node runs the full
    /// Collecting→Processing→Ready transition in the one `receive_block` call. The
    /// bootstrap-anchored genesis is recognized as the candidate (no intake
    /// change, per the `:142` resolution) and stays the active head after the FR4
    /// promotion.
    #[test]
    fn fr2_genesis_anchored_triggers_processing() {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 7, 0, 7);
        let (outcome, _) = bc.receive_block(genesis.view(), 100);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(
            bc.current_active_head(),
            Some(0),
            "genesis is the active head after the FR4 promotion (AC9)"
        );
        assert!(
            bc.is_ready(),
            "genesis-anchored candidate validates → Ready (FR6/FR4, Story 5.4)"
        );
    }

    /// A test chain with a small active-chain window (`SNAKE_CHAIN_LENGTH = 4`) so
    /// an active-length segment fits the test harness's block storage. Same shape
    /// as `new_test_chain` otherwise (local_node_id 5, join/Collecting).
    fn new_w4_chain() -> Blockchain<
        Crypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        FixedChainConfig,
        16,
        4,
        4,
        16,
        4,
        16,
    > {
        let (crypto, storage, chain_config) = test_backends();
        let node_zero = *crypto.public_key().serialize();
        let mut slot = core::mem::MaybeUninit::uninit();
        unsafe {
            Blockchain::init_in_place(
                slot.as_mut_ptr(),
                crypto,
                storage,
                chain_config,
                5,
                node_zero,
                0,
            );
            slot.assume_init()
        }
    }

    /// AC2 — an active-length segment (`>= W = 4`) that does NOT reach genesis
    /// triggers Processing; one block short (len 3) it stays Collecting.
    #[test]
    fn fr2_active_length_triggers_at_w() {
        let mut bc = new_w4_chain();
        // Tail orphan at seq 100 (unresolved parent), then children up to len 3.
        let tail = node_transfer_block(100, 3, 99, 7);
        bc.receive_block(tail.view(), 0);
        let mut prev = tail.view().hash();
        for seq in 101..=102 {
            let blk = linked_transfer_block(seq, prev);
            prev = blk.view().hash();
            bc.receive_block(blk.view(), 0);
        }
        assert_eq!(bc.block_tree_len(), 3);
        assert!(
            bc.evaluate_stopping_condition().is_none(),
            "segment length 3 < W = 4"
        );
        assert!(bc.current_phase() == LifecyclePhase::Collecting);
        // The 4th block brings the continuous segment to length W = 4 → FR2
        // qualifies, and the window-anchored candidate (unseeded initializers, so
        // the per-node FR6 checks are pre-seed-skipped, and every block is
        // node-#0-signed against the trust anchor) validates → Ready (Story 5.4).
        let last = linked_transfer_block(103, prev);
        bc.receive_block(last.view(), 0);
        assert!(
            bc.is_ready(),
            "segment length 4 >= W → FR2 qualifies, FR6 validates → Ready"
        );
    }

    /// AC3 — selection takes the highest tip sequence; a same-sequence tie is
    /// broken by the lowest tip hash (hash-only, in-memory). Built via
    /// `tier1_admit` (which does not run the FR2 hook), so the multi-head tree can
    /// be assembled before evaluating.
    #[test]
    fn fr2_selection_highest_sequence_then_lowest_hash() {
        let mut bc = new_test_chain();
        let g = node_transfer_block(0, 7, 0, 7);
        bc.tier1_admit(&g.view(), &g.view().hash(), 0)
            .expect("genesis admitted");
        let gh = g.view().hash();
        // Two distinct seq-1 children of genesis (a fork) → both genesis-anchored,
        // both tip seq 1 → tie broken by lower tip hash.
        let a = salted_linked_block(1, gh, 3);
        let b = salted_linked_block(1, gh, 4);
        let a_idx = bc
            .tier1_admit(&a.view(), &a.view().hash(), 0)
            .expect("A admitted");
        let b_idx = bc
            .tier1_admit(&b.view(), &b.view().hash(), 0)
            .expect("B admitted");
        let a_hash = a.view().hash();
        let b_hash = b.view().hash();
        let lower = if a_hash < b_hash { a_idx } else { b_idx };
        assert_eq!(
            bc.evaluate_stopping_condition(),
            Some(lower),
            "same-sequence tie → lower tip hash wins"
        );
        // Extend branch A to seq 2 → the higher sequence now outranks the tie.
        let c = salted_linked_block(2, a_hash, 3);
        let c_idx = bc
            .tier1_admit(&c.view(), &c.view().hash(), 0)
            .expect("C admitted");
        assert_eq!(
            bc.evaluate_stopping_condition(),
            Some(c_idx),
            "highest tip sequence wins over the lower-sequence tie"
        );
    }

    /// AC8 — the selected candidate is independent of admission order (FR63/NFR5):
    /// building the same fork in two admission orders yields the same winning tip
    /// hash (the block-table index differs by order, the chosen tip does not).
    #[test]
    fn fr2_selection_is_order_independent() {
        fn winner_hash(order: &[u32; 2], now: u64) -> [u8; 32] {
            let mut bc = new_test_chain();
            let g = node_transfer_block(0, 7, 0, 7);
            bc.tier1_admit(&g.view(), &g.view().hash(), now)
                .expect("genesis");
            let gh = g.view().hash();
            let blocks = [
                salted_linked_block(1, gh, order[0]),
                salted_linked_block(1, gh, order[1]),
            ];
            for blk in &blocks {
                bc.tier1_admit(&blk.view(), &blk.view().hash(), now)
                    .expect("child admitted");
            }
            let win = bc
                .evaluate_stopping_condition()
                .expect("a genesis-anchored candidate qualifies");
            *bc.blocks.get(win).expect("winner is in the tree").hash()
        }
        // Order- AND now-independent (FR63/NFR5): the evaluator reads no clock/PRNG.
        assert_eq!(
            winner_hash(&[3, 4], 1_000),
            winner_hash(&[4, 3], 9_999_999),
            "same winning tip regardless of admission order or wall-clock base"
        );
    }

    /// AC6 — the bootstrap-anchored genesis does not pre-empt selection: a longer
    /// non-genesis active-length branch at a higher tip sequence is chosen over
    /// the anchored genesis's short branch (the evaluator never reads
    /// `active_chain_head_idx`).
    #[test]
    fn fr2_anchored_genesis_does_not_preempt_higher_branch() {
        let mut bc = new_w4_chain();
        // Anchored genesis (a short genesis-anchored candidate).
        let g = node_transfer_block(0, 7, 0, 7);
        bc.tier1_admit(&g.view(), &g.view().hash(), 0)
            .expect("genesis admitted");
        assert_eq!(
            bc.current_active_head(),
            Some(0),
            "genesis is the placeholder anchor"
        );
        // A separate non-genesis branch of length W = 4 (tail seq 100 → tip 103).
        let tail = node_transfer_block(100, 3, 99, 7);
        bc.tier1_admit(&tail.view(), &tail.view().hash(), 0)
            .expect("tail admitted");
        let mut prev = tail.view().hash();
        let mut tip_idx = 0;
        for seq in 101..=103 {
            let blk = linked_transfer_block(seq, prev);
            prev = blk.view().hash();
            tip_idx = bc
                .tier1_admit(&blk.view(), &blk.view().hash(), 0)
                .expect("child admitted");
        }
        // Highest tip sequence (103) wins over the anchored genesis (seq 0).
        assert_eq!(
            bc.evaluate_stopping_condition(),
            Some(tip_idx),
            "the longer non-genesis branch is selected despite the genesis anchor"
        );
    }

    /// AC2 — a genesis-anchored segment longer than 1 but shorter than W still
    /// qualifies (the genesis rule is length-independent — distinct from the
    /// active-length rule).
    #[test]
    fn fr2_genesis_anchored_multiblock_below_w_qualifies() {
        let mut bc = new_test_chain(); // W = 16
        let g = node_transfer_block(0, 7, 0, 7);
        bc.tier1_admit(&g.view(), &g.view().hash(), 0)
            .expect("genesis admitted");
        // A child of genesis at seq 1 → a 2-block genesis-anchored segment (< W).
        let c = linked_transfer_block(1, g.view().hash());
        let c_idx = bc
            .tier1_admit(&c.view(), &c.view().hash(), 0)
            .expect("child admitted");
        assert_eq!(
            bc.evaluate_stopping_condition(),
            Some(c_idx),
            "genesis-anchored qualifies at length 2, well below W = 16"
        );
    }

    // --- Story 5.3: FR3 processing-pass forward state reconstruction ---------

    /// A `payload_type=1` block carrying a single registration transaction,
    /// linked to `prev`. Signatures are placeholders — FR3 derivation does not
    /// verify them (FR6 signature validation is Story 5.4).
    fn registration_block(
        seq: u32,
        prev: [u8; 32],
        initializer: u32,
        new_node_id: u32,
        pk_byte: u8,
    ) -> Block {
        // Story 5.4 verifies BOTH signatures of a registration against DIFFERENT
        // keys, and enforces `new_public_key` uniqueness — so a valid registration
        // needs two signers: the **initializer** ([1u8], the universal seeded key —
        // see `balance_block`) signs the transaction, and the **new node key**
        // ([pk_byte], a distinct key giving a unique `new_public_key`) signs the
        // proof-of-possession. `Registration::new_signed` uses one signer for both,
        // which cannot express a cross-key registration, so build it via
        // `Registration::new` with the two signatures computed separately.
        let init_signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("init key");
        let new_signer = Crypto::new([pk_byte; PRIVATE_KEY_SIZE])
            .ok()
            .expect("new key");
        let new_pk = *new_signer.public_key().serialize();
        let mut new_key_sig = [0u8; 64];
        new_key_sig.copy_from_slice(&new_signer.sign(&new_pk).serialize()[..64]);
        // The transaction signature signs the tx bytes with its signature field
        // zeroed and the new-key signature already present (the `new_signed`
        // convention), produced here by the initializer's key.
        let zero = [0u8; 64];
        let unsigned = Registration::new(
            0,
            initializer,
            new_node_id,
            50,
            1,
            &new_pk,
            &new_key_sig,
            &zero,
        );
        let mut tx_sig = [0u8; 64];
        tx_sig.copy_from_slice(&init_signer.sign(unsigned.as_bytes()).serialize()[..64]);
        let reg = Registration::new(
            0,
            initializer,
            new_node_id,
            50,
            1,
            &new_pk,
            &new_key_sig,
            &tx_sig,
        );
        let signer = init_signer;
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
            .add_registration(&reg)
            .ok()
            .expect("add registration");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// A `payload_type=2` balance block with one `NodeInfo` entry per
    /// `(owner, balance, vote_count, pk_byte)` tuple, and the given `max_node_id`.
    fn balance_block(
        seq: u32,
        prev: [u8; 32],
        entries: &[(u32, u64, u32, u8)],
        max_node_id: u32,
    ) -> Block {
        use moonblokz_chain_types::NodeInfo;
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        // Seed every node with the *real* universal test public key (node zero's,
        // = `pubkey([1u8])`), not a raw `[pk_byte; 32]` pattern: Story 5.4 verifies
        // block-creator + transaction signatures against the derived key, and all
        // test blocks/txs are `[1u8]`-signed — so a seeded node's key must be a
        // genuine key that key produces. `pk_byte` is retained in the tuple API
        // for call-site readability but no longer distinguishes the stored key.
        let real_key = *signer.public_key().serialize();
        let header = BlockHeader {
            version: 1,
            sequence: seq,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_BALANCE,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: prev,
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        for &(owner, balance, vote_count, _pk_byte) in entries {
            let ni = NodeInfo::new(owner, balance, vote_count, &real_key);
            builder.add_node_info(&ni).ok().expect("add node info");
        }
        builder
            .set_max_node_id(max_node_id)
            .ok()
            .expect("set max node id");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// A `payload_type=1` block with a single node transfer of `amount` (+`fee`)
    /// from `initializer` to `receiver`, linked to `prev`.
    fn transfer_block(
        seq: u32,
        prev: [u8; 32],
        initializer: u32,
        receiver: u32,
        amount: u64,
        fee: u32,
        vote: u32,
    ) -> Block {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let nt = NodeTransfer::new_signed(
            vote,
            seq.saturating_sub(1),
            initializer,
            receiver,
            amount,
            fee,
            0,
            &signer,
        );
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
        builder.add_node_transfer(&nt).ok().expect("add transfer");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// AC2/AC3 — the earliest balance block seeds per-node balance + public key
    /// and initializes the `max_known_node_id` watermark from its `max_node_id`;
    /// `VoteEngine` is seeded from the entries' `vote_count`.
    #[test]
    fn fr3_derives_balance_block_seed_and_watermark() {
        let mut bc = new_test_chain();
        let anchor = balance_block(
            100,
            [0xAB; 32],
            &[(1, 500, 10, 0xB1), (2, 300, 20, 0xB2)],
            2,
        );
        let ai = bc
            .tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("balance anchor admitted");

        bc.run_processing_pass(ai).expect("pass succeeds");

        assert_eq!(bc.node_info.balance_of(1), 500);
        assert_eq!(bc.node_info.balance_of(2), 300);
        assert!(bc.node_info.public_key_of(1).is_some());
        assert!(bc.node_info.public_key_of(2).is_some());
        assert_eq!(
            bc.node_info.max_known_node_id(),
            2,
            "watermark from max_node_id"
        );
        // vote_count seeds accumulated vote; the balance block's own acceptance
        // applies FR37 interest (0 on values < vote_scale) + creator(0) reset.
        assert_eq!(bc.vote_engine.accumulated_vote_of(1), 10);
        assert_eq!(bc.vote_engine.accumulated_vote_of(2), 20);
        // FR38 creator-order is a read-through of the vote registry: node 2
        // (vote 20) outranks node 1 (vote 10); the zero-vote tail follows by
        // ascending node id.
        assert_eq!(bc.vote_engine.top_creator(), Some(2));
        assert_eq!(bc.vote_engine.creator_at_rank(1), Some(1));
    }

    /// AC3 — a (non-genesis) registration seeds the new node (balance 0, public
    /// key) and advances the watermark; the initializer is debited
    /// `registration_price + fee`.
    #[test]
    fn fr3_derives_registration_and_watermark() {
        let mut bc = new_test_chain();
        let anchor = balance_block(100, [0xAB; 32], &[(1, 100, 0, 0xB1)], 1);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        // FR6 registration monotonicity: `new_node_id` must be the pre-block
        // watermark + 1 (watermark is 1 from the balance block's max_node_id → 2).
        let reg = registration_block(101, anchor.view().hash(), 1, 2, 0xC5);
        let ri = bc
            .tier1_admit(&reg.view(), &reg.view().hash(), 0)
            .expect("registration admitted");

        bc.run_processing_pass(ri).expect("pass succeeds");

        assert!(
            bc.node_info.public_key_of(2).is_some(),
            "new node registered"
        );
        assert_eq!(
            bc.node_info.balance_of(2),
            0,
            "new node balance is 0 (FR50)"
        );
        assert_eq!(bc.node_info.max_known_node_id(), 2, "watermark advanced");
        assert_eq!(
            bc.node_info.balance_of(1),
            49,
            "initializer debited registration_price(50) + fee(1)"
        );
    }

    /// AC2 — a node transfer between two seeded nodes moves the derived balances
    /// (initializer debited amount + fee; receiver credited amount).
    #[test]
    fn fr3_derives_node_transfer_between_seeded_nodes() {
        let mut bc = new_test_chain();
        let anchor = balance_block(100, [0xAB; 32], &[(1, 500, 0, 0xB1), (2, 300, 0, 0xB2)], 2);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        // vote 0 — the permanent node-#0 vote-target exception (FR37/FR54), so the
        // FR6 vote-target check passes without seeding a dedicated target node.
        let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 0);
        let ti = bc
            .tier1_admit(&tx.view(), &tx.view().hash(), 0)
            .expect("transfer admitted");

        bc.run_processing_pass(ti).expect("pass succeeds");

        assert_eq!(bc.node_info.balance_of(1), 399, "500 - (100 + 1)");
        assert_eq!(bc.node_info.balance_of(2), 400, "300 + 100");
    }

    /// AC4 — pre-seed-zone auto-acceptance: transactions involving nodes with no
    /// in-segment seed source are auto-accepted (their per-node balance effects
    /// are skipped), and the pass neither panics nor invents balances.
    #[test]
    fn fr3_preseed_zone_auto_accepts() {
        let mut bc = new_test_chain();
        // Orphan anchor: a transfer from node 7 to node 9, neither ever seeded.
        let anchor = node_transfer_block(100, 3, 99, 7);
        let ai = bc
            .tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");

        bc.run_processing_pass(ai)
            .expect("pass does not fail on unseeded nodes");

        assert!(!bc.node_info.is_seeded(7));
        assert_eq!(bc.node_info.balance_of(7), 0, "debit skipped (pre-seed)");
        assert_eq!(bc.node_info.balance_of(9), 0, "credit skipped (pre-seed)");
        // The vote credit still lands (vote accounting is roster-independent).
        assert_eq!(bc.vote_engine.accumulated_vote_of(3), 1000);
    }

    /// AC3 — a genesis-anchored segment with no balance block initializes the
    /// watermark to 0 (FR54(h) bootstrap exception).
    #[test]
    fn fr3_genesis_anchored_watermark_zero() {
        let mut bc = new_test_chain();
        let g = node_transfer_block(0, 3, 0, 7);
        let gi = bc
            .tier1_admit(&g.view(), &g.view().hash(), 0)
            .expect("genesis admitted");

        bc.run_processing_pass(gi).expect("pass succeeds");

        assert_eq!(
            bc.node_info.max_known_node_id(),
            0,
            "genesis-anchored, no balance block → watermark 0 (FR54(h))"
        );
    }

    /// AC1 — the backward mark follows only the selected branch: applying one
    /// fork child's tip must not apply the sibling's effects.
    #[test]
    fn fr3_backward_mark_follows_selected_branch_only() {
        let mut bc = new_test_chain();
        let anchor = balance_block(
            100,
            [0xAB; 32],
            &[(1, 1000, 0, 0xB1), (2, 0, 0, 0xB2), (3, 0, 0, 0xB3)],
            3,
        );
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        let ah = anchor.view().hash();
        let left = transfer_block(101, ah, 1, 2, 100, 0, 0); // 1 → 2 (vote node #0)
        let right = transfer_block(101, ah, 1, 3, 200, 0, 0); // 1 → 3 (sibling; vote node #0)
        let li = bc
            .tier1_admit(&left.view(), &left.view().hash(), 0)
            .expect("left admitted");
        let _ri = bc
            .tier1_admit(&right.view(), &right.view().hash(), 0)
            .expect("right admitted");

        bc.run_processing_pass(li).expect("pass over left tip");

        assert_eq!(bc.node_info.balance_of(2), 100, "left branch applied");
        assert_eq!(bc.node_info.balance_of(3), 0, "sibling NOT applied");
        assert_eq!(bc.node_info.balance_of(1), 900, "only left's 100 debited");
    }

    /// AC5 — the pass is not resumable: re-running it on the same candidate
    /// re-derives from a clean working set to an identical projection.
    #[test]
    fn fr3_not_resumable_clean_reentry() {
        let mut bc = new_test_chain();
        let anchor = balance_block(100, [0xAB; 32], &[(1, 500, 10, 0xB1)], 1);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        let tx = transfer_block(101, anchor.view().hash(), 1, 1, 0, 3, 0);
        let ti = bc
            .tier1_admit(&tx.view(), &tx.view().hash(), 0)
            .expect("tx admitted");

        bc.run_processing_pass(ti).expect("first pass");
        let b1 = bc.node_info.balance_of(1);
        let v1 = bc.vote_engine.accumulated_vote_of(1);

        bc.run_processing_pass(ti).expect("second pass (re-entry)");
        assert_eq!(
            bc.node_info.balance_of(1),
            b1,
            "balance identical after re-entry"
        );
        assert_eq!(
            bc.vote_engine.accumulated_vote_of(1),
            v1,
            "vote identical after re-entry (clean working set)"
        );
    }

    /// AC8 — the derived projection is `now`-independent and reproducible: the
    /// same candidate admitted under two different `now` bases yields a
    /// byte-identical projection.
    #[test]
    fn fr3_projection_is_clock_independent_and_reproducible() {
        fn run(now_base: u64) -> (u64, u64, u32, u32) {
            let mut bc = new_test_chain();
            let anchor = balance_block(100, [0xAB; 32], &[(1, 500, 0, 0xB1), (2, 300, 0, 0xB2)], 2);
            let _ai = bc
                .tier1_admit(&anchor.view(), &anchor.view().hash(), now_base)
                .expect("anchor admitted");
            let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 0);
            let ti = bc
                .tier1_admit(&tx.view(), &tx.view().hash(), now_base + 5_000)
                .expect("tx admitted");
            bc.run_processing_pass(ti).expect("pass");
            (
                bc.node_info.balance_of(1),
                bc.node_info.balance_of(2),
                bc.vote_engine.accumulated_vote_of(0),
                bc.node_info.max_known_node_id(),
            )
        }
        assert_eq!(run(0), run(1_000_000), "projection independent of `now`");
    }

    /// AC9 (Story 5.4) — the FR4 Ready transition + FR9 Tier-3 Active-promotion
    /// driver: a qualifying genesis-anchored candidate that passes FR6 moves
    /// Collecting→Processing→Ready in one `receive_block`, every candidate block is
    /// atomically promoted `Stored→Active` with `is_on_active_chain`, and
    /// `active_chain_head_idx` is established at the tip.
    #[test]
    fn fr4_seam_reaches_ready_and_promotes_active() {
        let mut bc = new_test_chain();
        let (outcome, _next) = bc.receive_block(node_transfer_block(0, 3, 0, 7).view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert!(
            bc.is_ready(),
            "valid genesis-anchored candidate → Ready (FR4)"
        );
        let tip = bc.active_chain_head_idx;
        assert_ne!(tip, NONE_REF, "active head established");
        let entry = bc.blocks.get(tip).expect("tip present");
        assert_eq!(
            entry.status(),
            BlockStatus::Active,
            "candidate tip promoted Stored→Active (FR9 Tier 3)"
        );
        assert!(entry.is_on_active_chain(), "tip is on the active chain");
    }

    /// AC10 (Story 5.4) — the FR6-failure path: a qualifying candidate that
    /// violates an FR6 invariant reverts `Processing→Collecting` (never Ready),
    /// with the derived working set reset. The candidate `[#0 genesis, #1
    /// registration]` is continuous genesis-anchored (so FR2 qualifies on the
    /// genesis admission) but block #1's `new_node_id = 5 ≠ watermark + 1 = 1`
    /// violates the FR6 registration-monotonicity rule.
    #[test]
    fn fr5_seam_reverts_to_collecting_on_invalid_candidate() {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        // Out-of-sequence registration child (new_node_id 5, expected 1).
        let child = registration_block(1, genesis.view().hash(), 1, 5, 0xC5);
        // Admit the child first as an orphan (Stored, no FR2 — not yet anchored),
        // then the genesis so the continuous genesis-anchored candidate qualifies.
        bc.receive_block(child.view(), 0);
        assert!(bc.current_phase() == LifecyclePhase::Collecting);
        bc.receive_block(genesis.view(), 0);
        assert!(
            bc.current_phase() == LifecyclePhase::Collecting,
            "invalid candidate reverts Processing→Collecting (FR5 phase-revert)"
        );
        assert!(!bc.is_ready(), "an invalid candidate never reaches Ready");
        assert!(
            !bc.node_info.is_seeded(5),
            "the derived working set is reset after the failed pass"
        );
    }

    /// A `payload_type=1` block with an explicit `creator` + `mined_amount`
    /// header and a single node transfer (used to exercise the FR36 creator
    /// credit — the other builders hard-code `mined_amount: 0`, which would mask
    /// a creator-credit bug).
    fn credit_block(
        seq: u32,
        prev: [u8; 32],
        creator: u32,
        mined_amount: u32,
        initializer: u32,
        receiver: u32,
        amount: u64,
    ) -> Block {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let nt = NodeTransfer::new_signed(
            3,
            seq.saturating_sub(1),
            initializer,
            receiver,
            amount,
            0,
            0,
            &signer,
        );
        let header = BlockHeader {
            version: 1,
            sequence: seq,
            creator,
            mined_amount,
            payload_type: PAYLOAD_TYPE_TRANSACTION,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: prev,
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        builder.add_node_transfer(&nt).ok().expect("add transfer");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// AC4 / FR36 — the creator credit is auto-accepted (skipped) for an unseeded
    /// creator (pre-seed zone): no phantom balance is written to an unknown
    /// baseline. Uses a non-zero `mined_amount` so the credit is observable.
    #[test]
    fn fr3_creator_credit_skipped_for_unseeded_creator() {
        let mut bc = new_test_chain();
        let blk = credit_block(100, [0xAB; 32], 8, 500, 7, 9, 0);
        let bi = bc
            .tier1_admit(&blk.view(), &blk.view().hash(), 0)
            .expect("block admitted");

        bc.run_processing_pass(bi).expect("pass succeeds");

        assert!(
            !bc.node_info.is_seeded(8),
            "unseeded creator is not seeded by its own credit"
        );
        assert_eq!(
            bc.node_info.balance_of(8),
            0,
            "FR36 creator credit skipped for a pre-seed-zone creator (AC4)"
        );
    }

    /// FR36 — a seeded creator IS credited its `mined_amount` (+ fees).
    #[test]
    fn fr3_creator_credit_applied_to_seeded_creator() {
        let mut bc = new_test_chain();
        let anchor = balance_block(100, [0xAB; 32], &[(3, 100, 0, 0xB3)], 3);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        let blk = credit_block(101, anchor.view().hash(), 3, 500, 7, 9, 0);
        let bi = bc
            .tier1_admit(&blk.view(), &blk.view().hash(), 0)
            .expect("credit block admitted");

        bc.run_processing_pass(bi).expect("pass succeeds");

        assert_eq!(
            bc.node_info.balance_of(3),
            600,
            "seeded creator credited mined_amount (100 seed + 500 mined)"
        );
    }

    /// AC3 (Story 5.4) — FR6 registration monotonicity: a registration whose
    /// `new_node_id` is not `pre-block watermark + 1` is exact evidence of
    /// invalidity. (In Story 5.3 the derive-only pass merely absorbed the id
    /// monotonically; FR6 now *rejects* an out-of-sequence registration, routing
    /// to the FR5 recovery via the earliest-offending-block error.)
    #[test]
    fn fr6_rejects_out_of_sequence_registration() {
        let mut bc = new_test_chain();
        // Balance block declares max_node_id 5 → watermark 5; the next valid
        // registration id is 6. A registration for id 3 violates the stride-1 rule.
        let anchor = balance_block(100, [0xAB; 32], &[(1, 100, 0, 0xB1)], 5);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        let reg = registration_block(101, anchor.view().hash(), 1, 3, 0xC3);
        let ri = bc
            .tier1_admit(&reg.view(), &reg.view().hash(), 0)
            .expect("registration admitted (Tier 1 does not check the watermark)");

        let result = bc.run_processing_pass(ri);
        assert_eq!(
            result,
            Err(ProcessingError::Invalid {
                block_idx: ri,
                reason: ValidationReason::RegistrationWatermark,
            }),
            "FR6 rejects a non-(watermark+1) registration as the earliest offender"
        );
    }

    // Note: the FR6 no-self-vote rule is a *structural* invariant checkable from
    // block bytes alone, so it is enforced at Tier 1 intake (`staged_validation`,
    // `Rejected(SelfVote)`) before a block can ever reach the Tier-3 processing
    // pass — the FR6 re-affirmation in `validate_and_derive_block` is
    // defense-in-depth. Self-vote rejection is therefore covered by the Tier-1
    // tests; only the roster-dependent vote-target check below is Tier-3-only.

    /// AC5 (Story 5.4) — FR6 vote-target existence: a `vote` that names a node
    /// absent from the candidate roster at inclusion is exact evidence of
    /// invalidity. (Node #0 and `vote == 0` remain the permanent exception.)
    #[test]
    fn fr6_rejects_unknown_vote_target() {
        let mut bc = new_test_chain();
        let anchor = balance_block(100, [0xAB; 32], &[(1, 500, 0, 0xB1)], 1);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        // Vote target 9 is never seeded/registered on the candidate.
        let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 9);
        let ti = bc
            .tier1_admit(&tx.view(), &tx.view().hash(), 0)
            .expect("tx admitted");
        assert_eq!(
            bc.run_processing_pass(ti),
            Err(ProcessingError::Invalid {
                block_idx: ti,
                reason: ValidationReason::VoteTargetUnknown,
            }),
            "FR6 rejects an unknown vote target"
        );
    }

    /// AC2 (Story 5.4) — FR6 block-creator signature: a block whose creator key
    /// is derivable (node #0 → the FR69 trust anchor) but whose signature was
    /// produced by a different key is rejected (the first block-creator-signature
    /// check in the crate).
    #[test]
    fn fr6_rejects_wrong_block_creator_signature() {
        let mut bc = new_test_chain();
        // A genesis (#0) block, creator = node #0, but signed by the WRONG key
        // ([9u8] ≠ the trust anchor pubkey([1u8])).
        let wrong = Crypto::new([9u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("wrong test key");
        let nt = NodeTransfer::new_signed(0, 0, 0, 9, 100, 1, 0, &wrong);
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
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        builder.add_node_transfer(&nt).ok().expect("add transfer");
        let block = builder.build_signed(&wrong).ok().expect("build signed");
        let idx = bc
            .tier1_admit(&block.view(), &block.view().hash(), 0)
            .expect("admitted (creator signature is not a Tier 1 gate)");
        assert_eq!(
            bc.run_processing_pass(idx),
            Err(ProcessingError::Invalid {
                block_idx: idx,
                reason: ValidationReason::CreatorSignatureInvalid,
            }),
            "FR6 rejects a block-creator signature that fails against the derived key"
        );
    }

    /// AC7 (Story 5.4) — FR6 requires every balance block *after the earliest* to
    /// carry `max_node_id` equal to the forward-traversal-tracked watermark at its
    /// sequence; a divergence is exact evidence of invalidity. (Deferred from
    /// Story 5.3, which only initialized the watermark from the earliest block.)
    #[test]
    fn fr6_rejects_later_balance_block_max_node_id_mismatch() {
        let mut bc = new_test_chain();
        // Earliest balance block → watermark initialized to 1.
        let b0 = balance_block(100, [0xAB; 32], &[(1, 500, 0, 0xB1)], 1);
        bc.tier1_admit(&b0.view(), &b0.view().hash(), 0)
            .expect("earliest balance block admitted");
        // A later balance block claims max_node_id 5 ≠ the tracked watermark 1.
        let b1 = balance_block(101, b0.view().hash(), &[(1, 400, 0, 0xB1)], 5);
        let i1 = bc
            .tier1_admit(&b1.view(), &b1.view().hash(), 0)
            .expect("later balance block admitted");
        assert_eq!(
            bc.run_processing_pass(i1),
            Err(ProcessingError::Invalid {
                block_idx: i1,
                reason: ValidationReason::BalanceMaxNodeIdMismatch,
            }),
            "FR6 rejects a later balance block whose max_node_id diverges from the watermark"
        );
    }

    /// AC6 (Story 5.4) — FR6 chain-config compliance: a chain-config block
    /// (`payload_type=3`) whose content is not byte-identical to the durable-locked
    /// configuration is exact evidence of invalidity. (The FR7 content-signature
    /// gate and establishing the lock from the candidate are Story 5.6.)
    #[test]
    fn fr6_rejects_divergent_chain_config() {
        let mut bc = new_test_chain();
        bc.chain_config
            .store_initial_chain_config_bytes(&[0x01, 0x02, 0x03])
            .expect("retain durable-locked config");
        // A chain-config block whose payload diverges from the retained config.
        let header = BlockHeader {
            version: 1,
            sequence: 5,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: [0u8; 32],
            signature: [0u8; 64],
        };
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let mut builder = BlockBuilder::new().header(header);
        builder
            .set_chain_config_payload(&[0x09, 0x09, 0x09])
            .ok()
            .expect("set chain-config payload");
        let block = builder.build_signed(&signer).ok().expect("build signed");
        let idx = bc
            .tier1_admit(&block.view(), &block.view().hash(), 0)
            .expect("admitted (content-signature gate is Story 5.6)");
        assert_eq!(
            bc.run_processing_pass(idx),
            Err(ProcessingError::Invalid {
                block_idx: idx,
                reason: ValidationReason::ChainConfigMismatch,
            }),
            "FR6 rejects a chain-config block diverging from the durable-locked config"
        );
    }

    /// AC3 (Story 5.4) — FR6 registration `new_public_key` global uniqueness: a
    /// registration whose new key collides with an already-seeded node's key is
    /// exact evidence of invalidity.
    #[test]
    fn fr6_rejects_duplicate_public_key() {
        let mut bc = new_test_chain();
        let anchor = balance_block(100, [0xAB; 32], &[(1, 500, 0, 0xB1)], 1);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        // pk_byte == 1 ⇒ new_public_key == pubkey([1u8]) == node 1's seeded key.
        let reg = registration_block(101, anchor.view().hash(), 1, 2, 1);
        let ri = bc
            .tier1_admit(&reg.view(), &reg.view().hash(), 0)
            .expect("registration admitted");
        assert_eq!(
            bc.run_processing_pass(ri),
            Err(ProcessingError::Invalid {
                block_idx: ri,
                reason: ValidationReason::DuplicatePublicKey,
            }),
            "FR6 rejects a registration whose new_public_key duplicates a seeded node's key"
        );
    }

    /// AC2/AC4 (Story 5.4) — on a GENESIS-anchored candidate (re-derivable in full
    /// from block #0) there is no pre-seed trust zone: a transaction whose
    /// initializer was never registered/seeded acts before it exists and is exact
    /// evidence of invalidity (`UnseededActor`) — unlike a window-anchored
    /// candidate, which legitimately trusts such pre-window history.
    #[test]
    fn fr6_rejects_unseeded_actor_on_genesis_anchored_candidate() {
        let mut bc = new_test_chain();
        // Genesis block #0 seeds no node (a bare transfer, not a node-#0 registration).
        let genesis = node_transfer_block(0, 0, 0, 0);
        bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("genesis admitted");
        // Block #1: a transfer whose initializer (node 1) never registered.
        let child = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
        let ci = bc
            .tier1_admit(&child.view(), &child.view().hash(), 0)
            .expect("child admitted");
        assert_eq!(
            bc.run_processing_pass(ci),
            Err(ProcessingError::Invalid {
                block_idx: ci,
                reason: ValidationReason::UnseededActor,
            }),
            "genesis-anchored: an unseeded initializer is invalid (no pre-seed trust)"
        );
    }
}
