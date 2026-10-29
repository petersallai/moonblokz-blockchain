//! Primary public API surface for `moonblokz-blockchain` (FR66). All
//! blockchain-facing state is reachable only through types defined or
//! re-exported here; internal modules stay crate-private. The
//! chain-configuration seam is `moonblokz_configuration::ChainConfigTrait`:
//! this crate is generic over it and never names a concrete implementation
//! (FR56).
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
    Block, BlockBuilder, BlockHeader, BlockView, ComplexTransactionView, HEADER_SIZE,
    MAX_BLOCK_SIZE, MAX_PAYLOAD_SIZE, NODE_INFO_SIZE, NodeTransfer, PAYLOAD_TYPE_BALANCE,
    PAYLOAD_TYPE_CHAIN_CONFIG, PAYLOAD_TYPE_TRANSACTION, REGISTRATION_SIZE, Registration,
    TransactionView,
};
use moonblokz_configuration::{
    BuildLimits, ChainConfigTrait, ChainInfoSource, chain_info, limits_are_expressible,
};
use moonblokz_crypto::{
    CryptoTrait, PUBLIC_KEY_SIZE, PublicKeyTrait, SIGNATURE_SIZE, SignatureTrait,
};
use moonblokz_storage::{StorageError, StorageTrait};
use moonblokz_vote::{VoteEngine, VoteEngineError};

use crate::available_utxo::utxo_output_at;
use crate::blocks::{AVAILABLE_UTXO_BYTES, BlockEntry, BlockTable, NONE_REF};
use crate::branch_value::{Rank, block_value};
use crate::chain_heads::ChainHeadsTable;
use crate::intake::classify_block;
use crate::lifecycle::is_legal_transition;
use crate::node_info::{NodeInfoState, SEED_SOURCE_RELEASED};
use crate::prng::Prng;
use crate::snake_chain::{TailBinding, classify_tail_drop, tail_drop_binding};
use crate::staged_validation::{
    BlockStatus, Tier1Failure, tier1_chain_config_block, tier1_gate, verify_signature_bytes,
};
use crate::uninit::field_slot;

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
    /// `initial_chain_config_bytes` plus its content-signature trailer would
    /// not fit in the Block #1 chain-config payload.
    InitialChainConfigTooLarge,
    /// The configuration module refused the genesis content (FR8 acceptance:
    /// malformed framing, an unknown identifier, a width mismatch, a bytecode
    /// value under a literal-only parameter, or a bound violation). The chain
    /// is not bootstrapped; nothing is written.
    InitialChainConfigRejected,
    /// Block #0 or Block #1 could not be persisted through the storage seam,
    /// so genesis must not report success.
    StorageSaveFailed,
    /// The storage control plane is not initialized, so the FR54 durable
    /// configuration could not be committed. Checked **before** any write,
    /// because `save_block` does not need the control plane and
    /// `set_chain_configuration` does: without the check the two genesis
    /// blocks would persist and the configuration would not, leaving a chain
    /// no retry can complete.
    StorageNotInitialized,
    /// A genesis block is larger than the block-size limit the genesis
    /// configuration itself declares, so every peer would reject it at Tier 1
    /// and the chain would be unusable from its first block.
    GenesisBlockExceedsBlockSizeLimit,
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
/// A node is constructed once via the single in-place constructor
/// [`Blockchain::init`] (which lands it in `Collecting` with an empty tree) and
/// then reads durable storage through this follow-up — the split keeps the
/// raw-pointer construction isolated from the storage-reading business
/// logic (architecture §3.6 "in-place constructor + role-specific follow-up").
///
/// Story 5.1 realized the empty-storage (fresh-join) outcome; Story 5.10 (FR59)
/// added the restart-from-durable-blocks arms below.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum InitOutcome {
    /// Storage held no blocks (fresh join): the node stays in `Collecting` as a
    /// pure receiver and acquires the chain from the mesh (FR1).
    StartedCollecting,
    /// FR59 restart: the tree was rebuilt from durable blocks and the FR2/FR3/FR6
    /// spine carried it to `Ready`.
    ResumedReady,
    /// FR59 restart: the tree was rebuilt, but no candidate segment satisfied the
    /// FR2 stopping condition (or no configuration is held), so the node stays in
    /// `Collecting` and continues ordinary intake until one does.
    ///
    /// Named for the phase the node is actually in. The epics text called this
    /// `ResumedProcessing`, inherited from a superseded design in which the
    /// lifecycle phase was persisted; FR59 persists no phase marker and enters
    /// `Collecting` unconditionally, so that name would contradict the state it
    /// reports (Story 5.10, ratified 2026-09-20).
    ResumedCollecting,
    /// FR59 restart: the durable footprint cannot be used to rebuild.
    Rejected(RestartRejectReason),
}

/// What an FR59 rebuild sweep found: how many blocks entered the tree, and how
/// many slots held something that could not be turned into one. `unusable` is
/// what separates a damaged store from an empty one.
struct RebuildStats {
    admitted: usize,
    unusable: usize,
}

/// Why an FR59 restart refused the durable store (architecture §3.6: a failed
/// precondition is a `Rejected` outcome, never a panic).
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum RestartRejectReason {
    /// Durable blocks are present but the control plane could not be read, so the
    /// configuration those blocks were validated under cannot be established.
    ControlPlaneUnreadable,
    /// The control plane holds a chain-config block that cannot be used — its
    /// envelope does not frame, its node-#0 content signature does not verify,
    /// or the configuration module refused its content. Continuing would run the
    /// chain under a configuration nobody committed to.
    ChainConfigUnusable,
    /// Durable blocks are present but not one of them could be rebuilt — every
    /// slot was unreadable or unmeasurable. Reported rather than silently
    /// answering `StartedCollecting`, which would discard the whole chain and
    /// present a damaged node as a fresh one.
    NoUsableTree,
    /// The node has already been initialized. `initialize_from_storage` is a
    /// one-shot boot step; a second call would rebuild over live state.
    AlreadyInitialized,
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
    /// A Ready-state direct extension of the active head failed its Tier 2 /
    /// Tier 3 checks or the FR48 binding (Story 6.0 D2), or a block whose
    /// parent is Connected or Active but not the head failed Tier 2 (Story 6.1
    /// D4) — exact evidence; the block is not stored. One residual (DEC-138): a vote-arithmetic refusal
    /// comes after the durable write, so the block is written and then
    /// deleted before anything links to it, its bytes left in the freed slot.
    InvalidExtension,
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
///   `moonblokz_configuration`'s trait, read through the `ActiveConfig` handle
///   at the moment each value is needed (FR56); this crate never names a
///   concrete implementation.
///
/// Defaults (architecture §5): `MAX_NODES = 1000`,
/// `SNAKE_CHAIN_LENGTH_MAX = 500`, `MAX_BLOCKS = 600`,
/// `MAX_BRANCH_COUNT = 40`, `MAX_BLOCK_UTXO_OUTPUT = 256`.
///
/// `SNAKE_CHAIN_LENGTH_MAX` is this build's **capacity** for the active-chain
/// window, not the window: the length in force, `W`, is chain configuration
/// (FR56), identical on every node of a chain, and acceptance refuses a chain
/// whose `W` exceeds the capacity (FR8). Every site that means "the window"
/// reads `W` through the configuration handle.
// `BlockEntry.len` stores the exact stored block length as a `u16`; the FR6
// byte-exact trim (`e.len() as usize`) and the admit-time `set_len(len as u16)`
// rely on `MAX_BLOCK_SIZE` fitting a `u16`. Guard it at compile time so a future
// larger block size cannot silently truncate the trim length.
const _: () = assert!(MAX_BLOCK_SIZE <= u16::MAX as usize);

/// The available-UTXO bitfield width in bits: this build's capacity for a
/// block's UTXO outputs, stated to the configuration module in `BUILD_LIMITS`
/// and enforced at Tier 1 before the durable lock (DEC-132).
const UTXO_BITFIELD_WIDTH: u16 = (AVAILABLE_UTXO_BYTES * 8) as u16;
const _: () = assert!(AVAILABLE_UTXO_BYTES * 8 <= u16::MAX as usize);

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

/// Why [`Blockchain::resolve_and_spend_utxo`] could not spend a UTXO input
/// (Story 6.8). Only `Invalid` is evidence against the consuming block; the
/// other two are local faults, which FR16 never charges against a block. The
/// caller maps it into its own error type, adding the consuming block's index.
pub(crate) enum UtxoSpendError {
    /// The input names no spendable output (exact evidence).
    Invalid(ValidationReason),
    /// The referenced block could not be read back, no longer parses, or lacks
    /// an output its available-UTXO bit says exists (storage and RAM disagree).
    StorageRead,
    /// The in-memory ancestry is inconsistent: a `parent_ref` into a freed
    /// slot, or a walk longer than `MAX_BLOCKS`.
    MissingBlock,
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
    /// Block-creator signature invalid against the creator's derived key.
    CreatorSignatureInvalid,
    /// I-09 (FR9 Tier 3, FR37, FR45): `consumed_votes`, `first_voted_node` or
    /// `consumed_votes_from_first_voted_node` disagrees with the parent-state
    /// vote snapshots (Story 6.2 D5, DEC-156).
    VoteHeaderMismatch,
    /// A node-transfer / registration transaction signature is invalid.
    TransactionSignatureInvalid,
    /// A debit (transfer amount+fee, registration price+fee, balance input)
    /// exceeds the initializer's derived balance (negative-balance outcome).
    InsufficientBalance,
    /// A registration `new_node_id` is not `pre-block max_known_node_id + 1`
    /// (out of the stride-1 sequence).
    RegistrationWatermark,
    /// A transaction's `vote` names a node absent from the candidate roster at
    /// its inclusion point.
    VoteTargetUnknown,
    /// A transaction references a node id (initializer / receiver) beyond
    /// `max_known_node_id`. Node ids are contiguous, so such an id cannot name any
    /// node that exists — exact evidence of invalidity even for a not-yet-seeded
    /// (pre-window) actor, whose *existence* is thereby still bounded-checkable.
    NodeIdOutOfRange,
    /// A complex tx UTXO input does not resolve (ADR-016): `block_sequence` is
    /// not a retained strict ancestor of the consuming block within `W`.
    UtxoUnresolvable,
    /// A complex tx UTXO input names an output that is not available on the
    /// referenced block: already spent, or beyond its UTXO-output stream (its
    /// bit is 0, DEC-132).
    UtxoUnavailable,
    /// A block carries more UTXO outputs than the held configuration's
    /// `max_block_utxo_output` (I-07; checked against the candidate's own
    /// preloaded value in the FR3 pass, DEC-133).
    TooManyUtxoOutputs,
    /// A `payload_type=3` block's config content is not byte-identical to the
    /// configuration this node holds — the durable-locked one when the FR8 lock
    /// is engaged, otherwise the tentatively-loaded one (Story 5.9).
    ChainConfigMismatch,
    /// FR8/AC3: the candidate segment carries **no** chain-config block in scope.
    /// Not evidence against any single block — a segment that names no
    /// configuration cannot satisfy FR6 chain-config compliance at all — so the
    /// FR5 deletion target is the candidate head, the same fallback the
    /// no-`block_idx` variants take.
    ///
    /// Unreachable from the acquisition loop since Story 5.13: FR2 no longer
    /// selects a segment that names no configuration, so no valid head is
    /// deleted for it. It remains the pass's own guard for callers that hand it
    /// a tip directly.
    MissingChainConfigBlock,
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
    /// A UTXO input's declared amount differs from the referenced output's
    /// amount (DEC-131).
    UtxoAmountMismatch,
    /// The block's fee total overflows `u64`. Every transaction's own sums are
    /// bounded at Tier 1.
    ValueOverflow,
    /// A credit (receiver, balance output, creator) would overflow the
    /// receiving node's `u64` balance (Story 6.0 D1: credits are checked).
    BalanceOverflow,
    /// A balance-block entry for a seeded node disagrees with the derived
    /// pre-state `(balance, vote_count, public_key)` (FR50, Story 6.0 D9).
    BalanceSnapshotMismatch,
}

/// The projection context of the per-block step (Story 6.0 D3). The FR3 pass
/// passes its pass-local flags; the Ready forward extension and the genesis
/// node pass [`Projection::COMPLETE`]. Nothing of it is persisted.
struct Projection {
    /// Every registered node is seeded: an unseeded actor is invalid, with no
    /// pre-seed trust zone (genesis-anchored FR3 pass, Ready, genesis).
    complete: bool,
    /// The watermark is an authoritative node-existence bound for the range
    /// checks.
    roster_bounded: bool,
    /// A non-complete FR3 pass has met its first balance block, which
    /// initialized the watermark.
    saw_balance_block: bool,
    /// The highest sequence at which a non-complete FR3 pass floor-seeded a
    /// node; 0 while none (Story 6.3 D2, DEC-167).
    last_floor_seed: u32,
}

impl Projection {
    /// A Ready projection is always complete (D3, FR50 coverage).
    const COMPLETE: Self = Self {
        complete: true,
        roster_bounded: true,
        saw_balance_block: true,
        last_floor_seed: 0,
    };
}

/// The verdict on a prospective extension of the active head (Story 6.0 D2).
enum Extension {
    /// The window gate and the fallible half of the step passed. `advance`
    /// is `Some(value)` when promoting it moves the tail: the FR21 value of
    /// the block that becomes the new `S_tail`, read before any mutation
    /// (Story 6.1 D1).
    Valid {
        advance: Option<u64>,
        derivation: BlockDerivation,
    },
    /// Exact evidence of invalidity (Tier 2 / Tier 3, or the FR48 binding).
    Invalid,
    /// A local failure — no evidence against the block (FR16, AC6).
    Local,
}

/// What the continuation does with a stored child of the head after the
/// whole per-block step ran on it (Story 6.0 AC4).
enum ChildStep {
    /// Applied: promote it. `value` is its FR21 value; `advance` moves the
    /// tail, carrying the new `S_tail` block's value.
    Applied { advance: Option<u64>, value: u64 },
    /// Exact evidence: delete it with its descendants.
    Invalid,
    /// A local failure: leave it Stored for a later retry.
    Local,
}

/// What an FR23 chain switch did (Story 6.3 AC6). Story 9.7's retry over an
/// admission's next-ranked heads (DEC-193) reads it.
#[cfg_attr(test, derive(Debug, PartialEq))]
enum SwitchOutcome {
    /// The new branch is active.
    Switched,
    /// Not attempted: outside FR58's bound, below the completeness horizon,
    /// or a dropped or referenced block not retained (DEC-159, DEC-167,
    /// DEC-204). Nothing changed.
    NotAdmitted,
    /// A local failure: the original chain stands, nothing was deleted.
    Kept,
    /// Exact evidence: the original chain stands and the offending block was
    /// deleted with its descendants.
    Deleted,
    /// A fault while re-applying the original chain: the active head stopped
    /// at the highest block re-applied, with its state exact (AC6).
    RestoreFailed,
}

/// The chain-switch signature pre-pass verdict (Story 6.3 D5, DEC-170).
enum PrePass {
    /// Every fork-independent creator's signature verified.
    Clean,
    /// The lowest new-branch block with a bad signature, and the summed FR21
    /// value from the switch target down to it, inclusive.
    Invalid { block: u32, through: u64 },
    /// A read failed: no switch, no evidence.
    Local,
}

/// The upper bound of a balance block's entries: the owner list a
/// committed-block undo copies before its seed-source scan (Story 6.3 AC2).
const MAX_BALANCE_ENTRIES: usize = MAX_PAYLOAD_SIZE / NODE_INFO_SIZE;

/// FR36(b): the transaction-fee total the per-block step credited to the
/// block's creator, recomputed from the payload for the committed-block undo
/// (Story 6.3 AC2) — the sums of `apply_transaction` / `apply_complex`, whose
/// checks made them exact.
fn block_fees(view: &BlockView<'_>) -> u64 {
    let Some(txs) = view.transactions() else {
        return 0;
    };
    let is_genesis_zero = view.sequence() == 0;
    let mut total = 0u64;
    for tx in txs.iter() {
        if let Some(nt) = tx.as_node_transfer() {
            total = total.wrapping_add(nt.fee() as u64);
        } else if let Some(reg) = tx.as_registration() {
            if !is_genesis_zero {
                total = total.wrapping_add(reg.fee());
            }
        } else if let Some(cx) = tx.as_complex()
            && cx.input_count() > 0
        {
            let mut in_sum: u64 = 0;
            for input in cx.inputs() {
                if let Some(bi) = input.as_balance() {
                    in_sum = in_sum.saturating_add(bi.amount());
                } else if let Some(ui) = input.as_utxo() {
                    in_sum = in_sum.saturating_add(ui.amount());
                }
            }
            let mut out_sum: u64 = 0;
            for output in cx.outputs() {
                if let Some(uo) = output.as_utxo() {
                    out_sum = out_sum.saturating_add(uo.amount());
                } else if let Some(bo) = output.as_balance() {
                    out_sum = out_sum.saturating_add(bo.amount());
                }
            }
            total = total.wrapping_add(in_sum.saturating_sub(out_sum));
        }
    }
    total
}

/// What [`Blockchain::walk_side_branch`] found on one side branch (Story 6.1
/// AC6): the FR21 sums it read and the lowest block whose Tier 2 failed.
struct SideWalk {
    /// The values of the active-chain blocks strictly above the connection
    /// point.
    active: u64,
    /// The values of the side blocks from the connection point (exclusive)
    /// up to the head.
    branch: u64,
    /// The lowest-sequence block whose Tier 2 failed, and the sum of the
    /// values from the head down to it, inclusive.
    failing: Option<(u32, u64)>,
}

/// Whether a per-block step error is evidence against the block (Story 6.0
/// AC3/AC6, DEC-037). A failed read, an inconsistent in-memory ancestry and
/// an unparameterized vote engine are the node's own faults.
fn is_evidence(err: &ProcessingError) -> bool {
    match err {
        ProcessingError::Invalid { .. } => true,
        ProcessingError::Vote(e) => *e != VoteEngineError::NotParameterized,
        ProcessingError::StorageRead
        | ProcessingError::MissingBlock
        | ProcessingError::MarkOverflow => false,
    }
}

/// What [`Blockchain::derive_block`] hands the commit tail.
struct BlockDerivation {
    /// FR36(b) transaction-fee total.
    total_fees: u64,
    /// The block's UTXO-output count: its available-UTXO bits to set.
    utxo_outputs: usize,
}

/// The FR3 candidate chain-config preload verdict — see
/// [`Blockchain::candidate_chain_config_readable_match`].
#[cfg_attr(test, derive(Debug, PartialEq))]
enum ConfigPreload {
    /// The candidate's configuration is the one this node holds.
    Matches,
    /// The candidate declares a different configuration (exact evidence, FR16).
    Differs,
    /// The block could not be read back or no longer frames (local I/O fault).
    Unreadable,
}

// Fields are consumed by the state-changing methods landing in Story 1.4+;
// silencing dead_code here keeps the scaffold clean.
#[allow(dead_code)]
pub struct Blockchain<
    Crypto: CryptoTrait,
    Storage: StorageTrait,
    Config: ChainConfigTrait,
    const MAX_NODES: usize,
    const SNAKE_CHAIN_LENGTH_MAX: u32,
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
    /// FR59 — set when [`Self::initialize_from_storage`] refused a durable
    /// store it could not rebuild, and never cleared.
    ///
    /// A refused restart leaves the node looking exactly like a fresh one: empty
    /// tree, `Collecting`, no configuration. The durable store, meanwhile, still
    /// holds the chain. Admitting a block into that state would take
    /// `next_free_index() == 0` and `save_block(0, ..)` would overwrite a
    /// durable block — the node would silently begin destroying the chain
    /// it failed to load. The refusal only protects anything if the module stops
    /// accepting work, so it stops here rather than trusting every caller to act
    /// on the outcome.
    ///
    /// Checking durable occupancy per admission instead is not an option: FR5,
    /// FR19 and FR8 deletion are all slot *release*, so a freed slot still reads
    /// back as an occupied one and a legitimate admission would be refused.
    restart_refused: bool,

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
    // FR23 chain-switch walk (Epic 6) and the FR59 restart (Story 5.10).
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

    // FR8 (Story 5.9): the block-table index of the chain-config block whose
    // content supplied the currently **tentatively**-loaded configuration, or
    // `NONE_REF` when none is held tentatively.
    //
    // Four bytes for one question the FR5 recovery cannot otherwise answer:
    // *did the delete-set contain the block my tentative configuration came
    // from?* (AC8). The configuration module holds the content, not its
    // provenance — and it must not, since a block index is block-tree
    // bookkeeping, not configuration. Re-deriving the provenance by scanning
    // the tree for a config block whose content matches would be both O(tree)
    // with a storage read per candidate and *wrong*: two blocks can legitimately
    // carry identical content, and the answer must name the one that loaded.
    //
    // A freed slot is reused, so a stale index could later name an unrelated
    // block. It cannot go stale: every path that drops the tentative clears this
    // in the same step, and every path that deletes the block drops the
    // tentative (AC8).
    tentative_config_block_idx: u32,

    // FR48 snake-chain tail as a block-table index (Story 9.1); `NONE_REF` =
    // no window, which is every phase but Ready. The window is this and
    // `active_chain_head_idx` — two indices, not a W-sized structure, so
    // nothing is sized by `SNAKE_CHAIN_LENGTH_MAX` and nothing restricts itself
    // to its first `W` entries. The tail is established wherever the node
    // enters Ready and advanced by the release step, over the chain-configured
    // `W`, never over the capacity (`snake_chain.rs`). It is always the active
    // chain's root (`parent_ref == NONE_REF`). The capacity stays a `u32` const
    // generic; `BUILD_LIMITS` asserts it fits the module's `u16`.
    snake_chain_tail_idx: u32,

    // FR21 value of the active branch: the sum of the per-block values over
    // `(S_tail, S_head]` (Story 6.1 D3). It lives here, not in a `chain_heads`
    // entry, because the active head is not always a tip: a Stored child
    // makes it interior and FR19 event (i) moves its entry to the child. Side
    // heads keep theirs in their entries. Seeded at Ready entry by the FR3
    // forward walk (D5) — 0 on the genesis node, whose block #1 carries no
    // value — grown on every head extension, reduced by the new `S_tail`
    // block's value on every tail advance (D1), 0 without a window.
    active_branch_value: u64,
    // FR23 completeness horizon `C` (Story 6.3 D2, DEC-167): the highest
    // sequence at which the Ready-entry FR3 pass floor-seeded a node — 0 on a
    // genesis-anchored chain. Floor seeding has no inverse, and below it the
    // projection was partial, so a chain switch never walks back across it.
    // Set at every FR3 promotion, 0 without an active chain; once the tail
    // passes it, it constrains nothing.
    complete_from_sequence: u32,
    //
    // Deliberately no standalone placeholder for:
    // - `MAX_BLOCK_UTXO_OUTPUT`: NOT wired into `BlockEntry.available_utxo`
    //   sizing (Story 4.1 fixes that field at a 32-byte constant — see
    //   `blocks::AVAILABLE_UTXO_BYTES` — because deriving an array length from a
    //   generic const parameter via division requires the unstable
    //   `generic_const_exprs` feature). Story 5.8 settled the ownership instead
    //   of the sizing: the *chain's* value is a configuration parameter read
    //   through the handle, and the *build's* capacity is stated once to the
    //   configuration module in `BUILD_LIMITS` (`AVAILABLE_UTXO_BYTES * 8`), which
    //   is where the two are now reconciled.
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
    /// This build's capacities, stated for the configuration module's §6
    /// acceptance checks — the two bounds that crate cannot derive because the
    /// capacities live here (specification §6, `BuildLimits`).
    ///
    /// Hand this to `ChainConfiguration::new` rather than restating the numbers
    /// at the construction site: the module keeps no copy of them, so the two §6
    /// checks read exactly what this constant says, and drift between the
    /// blockchain's arrays and the module's bounds stays unrepresentable.
    ///
    /// - `utxo_unspent_bits` — `UTXO_BITFIELD_WIDTH`, the per-block
    ///   available-UTXO bitfield width of `BlockEntry` (Story 4.1 fixes the
    ///   field at 32 bytes).
    /// - `snake_chain_length_max` — `SNAKE_CHAIN_LENGTH_MAX`, the active-chain
    ///   capacity. The chain's own window `W` must fit inside it, whether the
    ///   content declares `W` or leaves it at its default.
    pub const BUILD_LIMITS: BuildLimits = BuildLimits {
        utxo_unspent_bits: UTXO_BITFIELD_WIDTH,
        snake_chain_length_max: {
            assert!(
                SNAKE_CHAIN_LENGTH_MAX <= u16::MAX as u32,
                "SNAKE_CHAIN_LENGTH_MAX must fit the configuration module's u16 capacity"
            );
            // Every chain declares `W >= 1` (configuration §6 check 7), so a
            // zero capacity would compile into a node that refuses every chain.
            assert!(
                SNAKE_CHAIN_LENGTH_MAX >= 1,
                "SNAKE_CHAIN_LENGTH_MAX must hold a window of at least one block"
            );
            // Acceptance admits any `W` up to this capacity, and FR2 needs a
            // `W`-long segment in the block table to leave Collecting. A
            // capacity above the table would accept chains this node can never
            // acquire.
            assert!(
                SNAKE_CHAIN_LENGTH_MAX as usize <= MAX_BLOCKS,
                "SNAKE_CHAIN_LENGTH_MAX must fit the block table (MAX_BLOCKS)"
            );
            SNAKE_CHAIN_LENGTH_MAX as u16
        },
    };

    /// Constructs the node in place, inside caller-provided storage, and
    /// hands back a `&mut` to the initialized value. This is the type's
    /// **only** constructor.
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
            (&raw mut (*p).complete_from_sequence).write(0);
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
            complete_from_sequence: 0,
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

        let node_zero_public_key = *self.crypto.public_key().serialize();

        // FR54 framing: Block #1's payload is the content region followed by the
        // node-#0 content signature (the Story 5.7 envelope). Framed here rather
        // than taken framed, because the signature is node #0's and this is the
        // one place that key is the local one.
        let content_len = initial_chain_config_bytes.len();
        let Some(payload_len) = content_len
            .checked_add(SIGNATURE_SIZE)
            .filter(|len| *len <= MAX_PAYLOAD_SIZE)
        else {
            return Err(GenesisRejectReason::InitialChainConfigTooLarge);
        };
        let mut payload = [0u8; MAX_PAYLOAD_SIZE];
        payload[..content_len].copy_from_slice(initial_chain_config_bytes);
        payload[content_len..payload_len]
            .copy_from_slice(self.crypto.sign(initial_chain_config_bytes).serialize());
        let chain_config_payload = &payload[..payload_len];

        // Tentative first: acceptance runs inside the load and before anything
        // is retained, so a content refusal leaves the module exactly as it was
        // and this call writes nothing. The **durable** lock is engaged only
        // after the last storage write succeeds (below) — FR54's lock is
        // set-once, and a module locked by a call that then failed on storage
        // would refuse every retry, with `StorageNotEmpty`, for the life of the
        // process. A tentative left behind by a failed genesis is harmless: the
        // next attempt replaces it.
        self.chain_config
            .load_tentative(chain_config_payload)
            .map_err(|_| GenesisRejectReason::InitialChainConfigRejected)?;

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
        // The framed payload was bounded by `MAX_PAYLOAD_SIZE` above, so it fits
        // Block #1.
        if cfg_builder
            .set_chain_config_payload(chain_config_payload)
            .is_err()
        {
            unreachable!("the framed chain-config payload was capacity-checked");
        }
        let block_1 = match cfg_builder.build_signed(&self.crypto) {
            Ok(b) => b,
            Err(_) => unreachable!("Block #1 header.version = 1 and payload fits MAX_BLOCK_SIZE"),
        };

        // Both blocks must fit the block-size limit **the genesis configuration
        // itself declares**, which is a chain value now rather than the framing
        // constant it was while the stub answered. The registry admits anything
        // above `HEADER_SIZE`, so a founder can legally declare a limit smaller
        // than the blocks this bootstrap produces — and then every peer refuses
        // Block #1 at Tier 1 (`BlockTooLarge`) and the founder's own restart
        // refuses it again at FR6. Checked before any write: a chain that cannot
        // carry its own genesis must not be created.
        let block_size_limit = self.block_size_limit() as usize;
        if block_0.len() > block_size_limit || block_1.len() > block_size_limit {
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
            .validate_and_derive_block(&block_0.view(), 0, None, &mut projection)
            .and_then(|()| {
                self.validate_and_derive_block(
                    &block_1.view(),
                    1,
                    Some(block_0.hash()),
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
            .save_block(0, &block_0)
            .map_err(|_| self.abandon_genesis(GenesisRejectReason::StorageSaveFailed))?;
        let mut entry_0 = BlockEntry::new(block_0.hash(), NONE_REF, 0);
        entry_0.set_status(BlockStatus::Active);
        entry_0.set_on_active_chain(true);
        entry_0.set_len(block_0.len() as u16);
        entry_0.set_payload_type(block_0.payload_type());
        self.blocks.insert_at(0, entry_0);
        self.active_chain_head_idx = 0;
        let active_head = self.active_chain_head_idx;
        self.chain_heads
            .on_block_admitted(&mut self.blocks, 0, None, [0u8; 32], 0, active_head);

        // Block #1 — chain-config, chained to Block #0; becomes the active tip.
        self.storage
            .save_block(1, &block_1)
            .map_err(|_| self.abandon_genesis(GenesisRejectReason::StorageSaveFailed))?;
        // The durable chain-configuration seam (FR54): the blockchain owns the
        // storage handle, so the durable commit is made here rather than by the
        // configuration module (configuration specification §8.2).
        self.storage
            .set_chain_configuration(&block_1)
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
        let block_1_prev_hash = block_0.hash();
        let mut entry_1 = BlockEntry::new(block_1.hash(), 0, 1);
        entry_1.set_status(BlockStatus::Active);
        entry_1.set_on_active_chain(true);
        entry_1.set_len(block_1.len() as u16);
        entry_1.set_payload_type(block_1.payload_type());
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

        Ok(GenesisBlocks {
            block_zero: block_0,
            block_one: block_1,
        })
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
    /// **active-length-satisfying** (segment length `≥ W`), and which carries at
    /// least one chain-config block. The last condition is the FR8 final check's
    /// precondition applied *before* the pass rather than as its failure: a
    /// segment naming no configuration stays a non-candidate, with nothing
    /// deleted, until a chain-config block on it arrives (Story 5.13).
    ///
    /// `W` is the window the held configuration — tentative or durable — declares,
    /// never the build's capacity `SNAKE_CHAIN_LENGTH_MAX`, which would make the
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
        // The chain's window, once for the whole evaluation. With no
        // configuration held the active-length condition is not evaluated.
        let window = self.active_chain_length();
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
            let active_length = window.is_some_and(|w| segment_len >= w);
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
            if let Some(head) = self.switch_target([None, driver_best]) {
                self.switch_toward(head);
            }
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
    fn exact_view(bytes: &[u8]) -> Option<BlockView<'_>> {
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
    fn rebuild_block_tree_from_storage(&mut self, now: u64) -> RebuildStats {
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
            entry.set_len(view.len() as u16);
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
        self.complete_from_sequence = 0;
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
    fn seed_missing_parent_hashes(&mut self) {
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
    fn unlink_dangling_parents(&mut self) {
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

        // FR9 Tier 1 case (2) (Story 6.2 D6, DEC-157): in Ready, the creator
        // signature is exact evidence, before anything is written, whenever the
        // creator's key is the same on every branch that can connect. A pass
        // marks the entry, so the per-block step never verifies it again.
        let signature_verified = self.lifecycle_phase == LifecyclePhase::Ready
            && self
                .blocks
                .get(self.snake_chain_tail_idx)
                .is_some_and(|tail| {
                    self.key_is_branch_independent(block.creator(), tail.sequence())
                })
            && match self.verify_block_creator_signature(block) {
                Some(false) => {
                    return Err(AdmitError::Rejected(Tier1Failure::CreatorSignatureInvalid));
                }
                Some(true) => true,
                // No key verdict: nothing is judged or marked here.
                None => false,
            };

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
            self.promote_head_extension(idx, block_value(block), advance);
        }
        if side_judged && let Some(p) = parent {
            self.connect_judged_side_block(idx, p, block_value(block), parent_value);
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
        let (outcome, admitted) = classify_block(self, &block, window, now);
        // FR2 dominant-chain acquisition (Story 5.2): a successful collecting-phase
        // admission may complete a candidate segment. Evaluate the stopping
        // condition and, on success, transition Collecting→Processing. Runs only
        // after a real admission (not on duplicate/reject) and only while
        // Collecting (Processing/Ready never re-trigger). `AcceptedSilently` is
        // currently the sole accept outcome; when Epic 6/8 add `AcceptedAndSend*`
        // accept variants they must be included in this gate (else a block admitted
        // under them would miss the transition).
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
        if outcome == ReceiveBlockOutcome::AcceptedSilently && was_ready {
            self.drive_forward_extension();
        }
        // Story 6.1 AC6: after the continuation, whose promotion turns a
        // sibling into a side block, and at the end of a Ready entry, after
        // the FR8 lock-time cleanups (a cleanup retarget onto a Connected block
        // must not keep a value the driver computed before it).
        let mut driver_best = None;
        if outcome == ReceiveBlockOutcome::AcceptedSilently && self.is_ready() {
            driver_best = self.connect_side_branches();
        }
        // Story 6.2 D1 (DEC-152): FR22 — one comparison at the end of the
        // admission, after the continuation and the driver, between the active
        // branch and the higher-ranked admissible of the block judged at intake
        // and the driver's best. Never inside the loops: a switch (6.3) rewrites
        // `chain_heads` and the active chain under them.
        if outcome == ReceiveBlockOutcome::AcceptedSilently
            && self.is_ready()
            && let Some(head) = self.switch_target([admitted, driver_best])
        {
            self.switch_toward(head);
        }
        (outcome, self.next_parent_recovery_call())
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
                Ok((window_value, complete_from)) => {
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
                        self.promote_candidate_active(
                            candidate_tip_idx,
                            window_value,
                            complete_from,
                        );
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
                        self.promote_candidate_active(
                            candidate_tip_idx,
                            window_value,
                            complete_from,
                        );
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
                            // adopted content declares a larger `W` than the one
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
    fn reset_vote_engine(&mut self) {
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
    /// whose blocks are **not shared** with an already-active chain (fresh join,
    /// the Story-5.10 restart, an Epic-6 deep zone of a *new* branch). A
    /// chain-switch that re-derives over shared blocks must work on a copy — a
    /// failed re-derivation there would zero a shared block's *committed*
    /// available-UTXO bits instead of restoring them.
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
        // on the 6 KB blockchain-task stack. It does not coexist with
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
        self.complete_from_sequence = 0;
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
    /// establish and the completeness horizon `C` (Story 6.3 D2, DEC-167).
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
    ) -> Result<(u64, u32), ProcessingError> {
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
        // NOT shared with an already-active chain (fresh join, the Story-5.10
        // restart, and the Epic-6 deep-zone reconstruction of a *new* branch). A
        // chain-switch that re-derives over blocks shared with the active chain
        // must operate on a working copy instead (owned by Epic 6): a failed
        // re-derivation here would zero a shared block's committed bits rather
        // than restore them.
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
        let mut projection = Projection {
            complete: genesis_anchored,
            roster_bounded,
            saw_balance_block: false,
            last_floor_seed: 0,
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
            let this_hash = view.hash();
            if let Err(e) = self.validate_and_derive_block(&view, idx, prev_hash, &mut projection) {
                result = Err(e);
                break;
            }
            if view.sequence() > window_tail {
                window_value += block_value(&view);
            }
            prev_hash = Some(this_hash);
        }

        if result.is_err() {
            for slot in marked.iter().take(count) {
                self.blocks.clear_available_utxo(*slot);
            }
        }
        // Story 6.3 D2 (DEC-167): the completeness horizon `C` — 0 on a
        // genesis-anchored candidate, else the highest floor-seeding sequence,
        // or the tip when the pass seeded nothing (conservative; FR50 coverage
        // is Story 9.3's).
        let complete_from = if genesis_anchored {
            0
        } else if projection.last_floor_seed != 0 {
            projection.last_floor_seed
        } else {
            self.blocks.get(marked[0]).map_or(0, |e| e.sequence())
        };
        result.map(|()| (window_value, complete_from))
    }

    /// The FR6 per-block step (Story 6.0 AC1): validates one block against the
    /// FR6 invariant set **and** applies its effects to the derived projection.
    /// Shared by the FR3 forward walk, the Ready forward extension and the
    /// genesis node (D6), so there is one implementation of both.
    ///
    /// Two halves, so the direct head extension can persist the block between
    /// them (AC3): [`Self::derive_block`] runs every check and every invertible
    /// effect, and [`Self::commit_block`] the vote apply and the commit tail.
    /// Either half leaves `node_info`, the vote engine, every available-UTXO
    /// bit and the watermark exactly as it found them when it returns `Err`
    /// (D1); the one exception is the floor seeding of a non-complete FR3
    /// pass, whose failure resets the whole pass.
    fn validate_and_derive_block(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        prev_hash: Option<[u8; 32]>,
        projection: &mut Projection,
    ) -> Result<(), ProcessingError> {
        let derivation = self.derive_block(view, idx, prev_hash, projection)?;
        self.commit_block(view, idx, derivation)
    }

    /// The fallible half of the per-block step, in the D1 order: block-level
    /// checks; per transaction, its checks and then its invertible effects;
    /// the balance-block checks (D9); the creator-credit overflow check. On
    /// `Err` the effects already applied are inverted, newest first.
    ///
    /// Every check reads the state derived from the preceding blocks and from
    /// the earlier transactions of this block, so a balance spent by tx 1
    /// limits tx 2, and a key registered by tx 1 is a duplicate in tx 2. In a
    /// non-complete FR3 projection (D3) the per-node state-dependent checks
    /// are gated on the actor being seeded: a window-anchored candidate trusts
    /// history it cannot re-derive.
    fn derive_block(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        prev_hash: Option<[u8; 32]>,
        projection: &mut Projection,
    ) -> Result<BlockDerivation, ProcessingError> {
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
        // (a) size ≤ chain-config limit — but only once that limit is durably
        // locked (FR9). While the configuration is merely tentative this yields
        // the structural ceiling, so the check cannot produce `Invalid` and
        // cannot delete; the enforcement is re-run against the real limit at the
        // durable lock, which is one of the two moments FR9 names.
        if view.len() > self.enforceable_block_size_limit() as usize {
            return Err(invalid(ValidationReason::BlockTooLarge));
        }
        // (b) previous_hash links to the immediately-preceding block (the FR3
        //     anchor has no in-segment predecessor → `prev_hash == None`).
        if let Some(ph) = prev_hash
            && view.previous_hash() != &ph[..]
        {
            return Err(invalid(ValidationReason::PreviousHashMismatch));
        }
        // (c) block-creator signature. Skipped when the creator's key is not
        //     yet derivable (pre-seed zone → trusted); node #0 always resolves
        //     to the FR69 trust anchor. In a complete projection a non-derivable
        //     creator past block #0 is exact evidence of invalidity (D3).
        //     A block whose signature already verified against its own
        //     ancestry key is not verified again (Story 6.2 D6, DEC-157).
        if !self
            .blocks
            .get(idx)
            .is_some_and(|entry| entry.is_signature_verified())
        {
            match self.verify_block_creator_signature(view) {
                Some(false) => return Err(invalid(ValidationReason::CreatorSignatureInvalid)),
                Some(true) => {
                    self.blocks.mark_signature_verified(idx);
                }
                None if projection.complete && !is_genesis_zero => {
                    return Err(invalid(ValidationReason::UnseededActor));
                }
                None => {}
            }
        }

        let mut derivation = BlockDerivation {
            total_fees: 0,
            utxo_outputs: 0,
        };
        // How many transactions have applied their effects, for the prefix
        // inversion on a later failure.
        let mut applied = 0usize;

        match view.payload_type() {
            PAYLOAD_TYPE_BALANCE => {
                let payload = view
                    .balances()
                    .ok_or(invalid(ValidationReason::MalformedPayload))?;
                if projection.complete || projection.saw_balance_block {
                    // Every balance block carries `max_node_id` == the
                    // forward-tracked watermark at its sequence (FR50).
                    if payload.max_node_id() != self.node_info.max_known_node_id() {
                        return Err(invalid(ValidationReason::BalanceMaxNodeIdMismatch));
                    }
                } else {
                    // The earliest balance block of a non-complete FR3 pass
                    // initializes the watermark (FR3/FR54(h)).
                    let advanced = self
                        .node_info
                        .max_known_node_id()
                        .max(payload.max_node_id());
                    self.node_info.set_max_known_node_id(advanced);
                    projection.saw_balance_block = true;
                }
                // D9: the payload repeats the pre-state; it seeds only what a
                // non-complete projection does not know yet.
                let mut floor_seeded = false;
                for info in payload.iter() {
                    let owner = info.owner();
                    // Node ids are contiguous: an entry beyond the watermark
                    // names no node (and would occupy a slot a later
                    // registration needs empty, D1 precondition 2).
                    if owner > payload.max_node_id() {
                        return Err(invalid(ValidationReason::NodeIdOutOfRange));
                    }
                    if self.node_info.is_seeded(owner) {
                        let matches = self.node_info.balance_of(owner) == info.balance()
                            && self.vote_engine.accumulated_vote_of(owner) == info.vote_count()
                            && self
                                .node_info
                                .public_key_of(owner)
                                .is_some_and(|key| key[..] == *info.public_key());
                        if !matches {
                            return Err(invalid(ValidationReason::BalanceSnapshotMismatch));
                        }
                    } else if projection.complete {
                        // Defensive: unreachable while stride-1 registration
                        // and the owner bound hold. FR50 coverage: every
                        // registered node is seeded in a
                        // complete projection (D3).
                        return Err(invalid(ValidationReason::UnseededActor));
                    } else {
                        self.node_info
                            .seed_node(owner, info.public_key(), info.balance(), idx);
                        floor_seeded = true;
                    }
                }
                // The vote half of the floor seeding. A seeded entry's
                // `vote_count` was just shown equal, so re-seeding it is a no-op.
                if floor_seeded && let Ok(v) = BlockView::from_bytes(view.serialized_bytes()) {
                    self.vote_engine.seed_from_balance_block(v);
                }
                // Floor seeding has no inverse: a chain switch never walks
                // back across it (Story 6.3 D2, DEC-167).
                if floor_seeded {
                    projection.last_floor_seed = projection.last_floor_seed.max(seq);
                }
            }
            PAYLOAD_TYPE_TRANSACTION => {
                let txs = view
                    .transactions()
                    .ok_or(invalid(ValidationReason::MalformedPayload))?;
                for tx in txs.iter() {
                    if let Err(e) =
                        self.apply_transaction(&tx, idx, seq, projection, &mut derivation)
                    {
                        self.invert_transactions(view, idx, applied);
                        return Err(e);
                    }
                    applied += 1;
                }
                // FR6 registration/complex mutual-exclusivity is intrinsic (decided
                // from block bytes) and owned by the Tier-1 intake gate, which every
                // admitted block passed — not re-checked here.
            }
            PAYLOAD_TYPE_CHAIN_CONFIG => {
                // FR6 chain-config compliance + the FR8 final check, content half
                // (Story 5.9, AC3): every chain-config block on the candidate must
                // carry content byte-identical to the configuration this node
                // holds — the durable-locked one once the FR8 lock is engaged, and
                // the tentatively-loaded one while still Collecting. One
                // comparison serves both: FR8's final check *is* FR6 compliance
                // measured against the not-yet-committed content.
                //
                // The comparison is over the **content region**, not the whole
                // payload: the payload also carries node #0's content signature,
                // which the FR7 Tier-1 gate owns. A payload whose envelope does
                // not frame carries no content region and so cannot match.
                if let Some(held) = self.held_chain_config_content()
                    && view.chain_config().map(|config| config.content()) != Some(held)
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

        // I-09 (FR9 Tier 3; Story 6.2 D5, DEC-156): the vote header snapshots
        // against the parent state, which the vote engine still holds — its
        // apply runs in `commit_block`. After the balance-block seeding above,
        // so a floor-seeded creator is judged. Genesis #0 holds as built: I(0) = 0.
        // A deviation's first-voted node must exist, as every node id a
        // transaction names must (FR6): a partial projection cannot judge its
        // snapshot, but it can bound the id.
        let first_voted = view.first_voted_node();
        if first_voted != view.creator()
            && let Err(reason) = self.check_node_id_in_range(first_voted)
        {
            self.invert_transactions(view, idx, applied);
            return Err(invalid(reason));
        }
        let header = self
            .vote_engine
            .check_header(view, projection.complete, |node| {
                self.node_info.is_seeded(node)
            });
        if header != Ok(true) {
            self.invert_transactions(view, idx, applied);
            return Err(match header {
                Err(e) => ProcessingError::Vote(e),
                _ => invalid(ValidationReason::VoteHeaderMismatch),
            });
        }

        // FR36 creator credit, checked here so the commit tail cannot fail.
        if !is_genesis && self.node_info.is_seeded(view.creator()) {
            let fits = (view.mined_amount() as u64)
                .checked_add(derivation.total_fees)
                .and_then(|credit| {
                    self.node_info
                        .balance_of(view.creator())
                        .checked_add(credit)
                });
            if fits.is_none() {
                self.invert_transactions(view, idx, applied);
                return Err(invalid(ValidationReason::BalanceOverflow));
            }
        }
        Ok(derivation)
    }

    /// The second half of the per-block step: the FR37 vote apply — the last
    /// fallible operation, and atomic — then the commit tail (D1 precondition
    /// 5), the effects no later check of the block reads: the FR36 creator
    /// credit (`mined_amount` + fees; FR36(c) is Epic 9), the D9 seed-source
    /// moves and the block's own available-UTXO bits. On a vote failure the
    /// effects of [`Self::derive_block`] are inverted.
    fn commit_block(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        derivation: BlockDerivation,
    ) -> Result<(), ProcessingError> {
        if let Ok(v) = BlockView::from_bytes(view.serialized_bytes())
            && let Err(e) = self.vote_engine.apply_block(v)
        {
            self.invert_transactions(view, idx, usize::MAX);
            return Err(ProcessingError::Vote(e));
        }
        let seq = view.sequence();
        if seq > 1 && self.node_info.is_seeded(view.creator()) {
            self.node_info.credit(
                view.creator(),
                view.mined_amount() as u64 + derivation.total_fees,
            );
        }
        if let Some(payload) = view.balances() {
            for info in payload.iter() {
                self.node_info.move_seed_source(info.owner(), idx);
            }
        }
        // A block never spends its own outputs (Tier-1 causality), so its
        // bits become spendable only by descendants.
        for bit in 0..derivation.utxo_outputs {
            self.blocks.set_utxo_available(idx, bit, true);
        }
        Ok(())
    }

    /// Checks one transaction and applies its effects, atomically: on `Err`
    /// nothing of this transaction remains applied.
    fn apply_transaction(
        &mut self,
        tx: &TransactionView<'_>,
        idx: u32,
        seq: u32,
        projection: &Projection,
        derivation: &mut BlockDerivation,
    ) -> Result<(), ProcessingError> {
        let is_genesis_zero = seq == 0;
        let complete = projection.complete;
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };
        let vote = tx.vote();
        if let Some(nt) = tx.as_node_transfer() {
            let init = nt.initializer();
            let receiver = nt.receiver();
            // [A] Complete projection: an unseeded initializer transacts
            // before it exists (D3). Non-complete: trusted pre-window history.
            if complete && !is_genesis_zero && !self.node_info.is_seeded(init) {
                return Err(invalid(ValidationReason::UnseededActor));
            }
            // FR6 node-existence bound: the initializer (input) and the
            // receiver (output) must name nodes that can exist
            // (`id <= max_known_node_id`) — checkable even when unseeded.
            if projection.roster_bounded && !is_genesis_zero {
                self.check_node_id_in_range(init).map_err(&invalid)?;
                self.check_node_id_in_range(receiver).map_err(&invalid)?;
            }
            // State-dependent FR6 checks apply once the initializer is
            // derivable. The intrinsic invariants (no-self-vote,
            // anchor-before-block) are owned by the Tier-1 gate.
            if !is_genesis_zero && self.node_info.is_seeded(init) {
                self.check_vote_target(vote).map_err(&invalid)?;
                if !self.verify_tx_signature(tx.as_bytes(), init) {
                    return Err(invalid(ValidationReason::TransactionSignatureInvalid));
                }
            }
            let fee = nt.fee() as u64;
            let debit = nt
                .amount()
                .checked_add(fee)
                .ok_or(invalid(ValidationReason::ValueOverflow))?;
            // FR54(d): the genesis self-transfer *creates* currency — no debit.
            let debits = !is_genesis_zero && self.node_info.is_seeded(init);
            let credits = self.node_info.is_seeded(receiver);
            if debits && self.node_info.balance_of(init) < debit {
                return Err(invalid(ValidationReason::InsufficientBalance));
            }
            // A self-transfer credits back less than it debited.
            if credits
                && !(debits && receiver == init)
                && self
                    .node_info
                    .balance_of(receiver)
                    .checked_add(nt.amount())
                    .is_none()
            {
                return Err(invalid(ValidationReason::BalanceOverflow));
            }
            let total_fees = derivation
                .total_fees
                .checked_add(fee)
                .ok_or(invalid(ValidationReason::ValueOverflow))?;
            if debits {
                self.node_info.debit(init, debit);
            }
            if credits {
                self.node_info.credit(receiver, nt.amount());
            }
            derivation.total_fees = total_fees;
        } else if let Some(reg) = tx.as_registration() {
            let node_id = reg.new_node_id();
            let init = reg.initializer();
            // [A] Complete projection: the registering initializer must be an
            // existing (seeded) node (block #0's node-#0 self-registration is
            // the FR54 bootstrap exception).
            if complete && !is_genesis_zero && !self.node_info.is_seeded(init) {
                return Err(invalid(ValidationReason::UnseededActor));
            }
            // FR6 node-existence bound on the initializer. (`new_node_id` is
            // bounded by the monotonicity check, not this range check.)
            if projection.roster_bounded && !is_genesis_zero {
                self.check_node_id_in_range(init).map_err(&invalid)?;
            }
            let debits = !is_genesis_zero && self.node_info.is_seeded(init);
            let debit = reg
                .registration_price()
                .checked_add(reg.fee())
                .ok_or(invalid(ValidationReason::ValueOverflow))?;
            if !is_genesis_zero {
                // FR6 registration monotonicity: `new_node_id == running
                // watermark + 1`, authoritative once the watermark is
                // established (a complete projection, or after the first
                // balance block of a window-anchored one).
                if complete || projection.saw_balance_block {
                    let expected = self.node_info.max_known_node_id().wrapping_add(1);
                    if node_id != expected {
                        return Err(invalid(ValidationReason::RegistrationWatermark));
                    }
                }
                if debits {
                    self.check_vote_target(vote).map_err(&invalid)?;
                    if !self.verify_tx_signature(tx.as_bytes(), init) {
                        return Err(invalid(ValidationReason::TransactionSignatureInvalid));
                    }
                    if self.node_info.balance_of(init) < debit {
                        return Err(invalid(ValidationReason::InsufficientBalance));
                    }
                }
            }
            // [E] FR6 registration uniqueness, against the seeded roster —
            // earlier registrations of this block included.
            if self.node_info.key_is_registered(reg.new_public_key()) {
                return Err(invalid(ValidationReason::DuplicatePublicKey));
            }
            // The fee goes to the creator whether or not the initializer is
            // derivable yet, as for every other transaction kind: a seeded
            // creator's balance must stay exact, or a later balance block
            // listing it fails the D9 equality.
            let total_fees = if is_genesis_zero {
                derivation.total_fees
            } else {
                derivation
                    .total_fees
                    .checked_add(reg.fee())
                    .ok_or(invalid(ValidationReason::ValueOverflow))?
            };
            // Effects, after every check. `registration_price` is absorbed
            // (debited, credited to no node); the fee goes to the creator.
            if debits {
                self.node_info.debit(init, debit);
            }
            // Genesis #0 does not advance the watermark (FR54(h)).
            if !is_genesis_zero && (node_id as usize) < MAX_NODES {
                let advanced = self.node_info.max_known_node_id().max(node_id);
                self.node_info.set_max_known_node_id(advanced);
            }
            self.node_info
                .register_node(node_id, reg.new_public_key(), idx);
            derivation.total_fees = total_fees;
        } else if let Some(cx) = tx.as_complex() {
            // How many inputs and outputs applied, for the partial inversion.
            let mut applied = (0usize, 0usize);
            let result = self.apply_complex(tx, idx, seq, projection, derivation, &mut applied);
            if result.is_err() {
                self.invert_complex(&cx, idx, applied.0, applied.1, is_genesis_zero);
            }
            result?;
        } else {
            return Err(invalid(ValidationReason::MalformedPayload));
        }
        Ok(())
    }

    /// The complex-transaction arm of [`Self::apply_transaction`]: FR6 value
    /// accounting over every input and output (Story 6.8). Effects apply in
    /// order — a later input of the same initializer sees the earlier debit —
    /// and `applied` counts how many inputs and outputs applied, for the
    /// caller's partial inversion.
    fn apply_complex(
        &mut self,
        tx: &TransactionView<'_>,
        idx: u32,
        seq: u32,
        projection: &Projection,
        derivation: &mut BlockDerivation,
        applied: &mut (usize, usize),
    ) -> Result<(), ProcessingError> {
        let is_genesis_zero = seq == 0;
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };
        let vote = tx.vote();
        let cx = tx
            .as_complex()
            .ok_or(invalid(ValidationReason::MalformedPayload))?;
        // Every input declares its amount (DEC-131) and Tier 1 has checked
        // both sums against `u64` and `Σ inputs ≥ Σ outputs` (DEC-011).
        let mut in_sum: u64 = 0;
        let mut out_sum: u64 = 0;
        for input in cx.inputs() {
            if let Some(bi) = input.as_balance() {
                let binit = bi.initializer();
                if projection.complete && !is_genesis_zero && !self.node_info.is_seeded(binit) {
                    return Err(invalid(ValidationReason::UnseededActor));
                }
                if projection.roster_bounded && !is_genesis_zero {
                    self.check_node_id_in_range(binit).map_err(&invalid)?;
                }
                if !is_genesis_zero && self.node_info.is_seeded(binit) {
                    self.check_vote_target(vote).map_err(&invalid)?;
                    if self.node_info.balance_of(binit) < bi.amount() {
                        return Err(invalid(ValidationReason::InsufficientBalance));
                    }
                    self.node_info.debit(binit, bi.amount());
                }
                in_sum = in_sum.saturating_add(bi.amount());
            } else if let Some(ui) = input.as_utxo() {
                // [H] ADR-016: resolve along this block's own ancestry and
                // spend. A non-complete candidate trusts a reference below its
                // anchor (DEC-129), declared amount included. The input's
                // signature is Story 7.1 (I-21).
                let parent = self
                    .blocks
                    .get(idx)
                    .ok_or(ProcessingError::MissingBlock)?
                    .parent_ref();
                self.resolve_and_spend_utxo(
                    parent,
                    seq,
                    ui.block_sequence(),
                    ui.output_index(),
                    ui.amount(),
                    !projection.complete,
                )
                .map_err(|e| match e {
                    UtxoSpendError::Invalid(reason) => invalid(reason),
                    UtxoSpendError::StorageRead => ProcessingError::StorageRead,
                    UtxoSpendError::MissingBlock => ProcessingError::MissingBlock,
                })?;
                in_sum = in_sum.saturating_add(ui.amount());
            }
            applied.0 += 1;
        }
        // Outputs after the inputs. A UTXO output's bit is set in the commit
        // tail; here it only takes its stream position, held within the
        // configuration's cap (I-07, DEC-133).
        let max_utxo_outputs = self.held_max_utxo_outputs() as usize;
        for output in cx.outputs() {
            if let Some(uo) = output.as_utxo() {
                if derivation.utxo_outputs >= max_utxo_outputs {
                    return Err(invalid(ValidationReason::TooManyUtxoOutputs));
                }
                derivation.utxo_outputs += 1;
                out_sum = out_sum.saturating_add(uo.amount());
            } else if let Some(bo) = output.as_balance() {
                if projection.roster_bounded && !is_genesis_zero {
                    self.check_node_id_in_range(bo.receiver())
                        .map_err(&invalid)?;
                }
                if self.node_info.is_seeded(bo.receiver()) {
                    if self
                        .node_info
                        .balance_of(bo.receiver())
                        .checked_add(bo.amount())
                        .is_none()
                    {
                        return Err(invalid(ValidationReason::BalanceOverflow));
                    }
                    self.node_info.credit(bo.receiver(), bo.amount());
                }
                out_sum = out_sum.saturating_add(bo.amount());
            }
            applied.1 += 1;
        }
        // [D] The fee is the surplus over all inputs and outputs; a zero-input
        // carry-forward pays none (FR6).
        if cx.input_count() > 0 {
            let fee = in_sum.saturating_sub(out_sum);
            derivation.total_fees = derivation
                .total_fees
                .checked_add(fee)
                .ok_or(invalid(ValidationReason::ValueOverflow))?;
        }
        Ok(())
    }

    /// Inverts the effects of the first `count` transactions of `view` (all of
    /// them for `usize::MAX`), newest first — the D1 prefix inversion of
    /// [`Self::derive_block`]'s transaction effects. Undoing a *committed*
    /// block (Story 6.3) also needs the inverse of [`Self::commit_block`]'s
    /// effects, which this does not cover: `VoteEngine::undo_block`, the
    /// creator credit, the block's own output bits, and the seed-source moves
    /// (the D1 backward scan handed to 6.3). Each inverse is computed
    /// from the transaction bytes plus the current state, which, in reverse
    /// order, is the state right after that transaction applied. O(`count`²)
    /// transaction parses, on failure paths only.
    fn invert_transactions(&mut self, view: &BlockView<'_>, idx: u32, count: usize) {
        let Some(txs) = view.transactions() else {
            return;
        };
        let is_genesis_zero = view.sequence() == 0;
        let count = count.min(txs.iter().count());
        for k in (0..count).rev() {
            let Some(tx) = txs.iter().nth(k) else {
                continue;
            };
            if let Some(nt) = tx.as_node_transfer() {
                if self.node_info.is_seeded(nt.receiver()) {
                    self.node_info.debit(nt.receiver(), nt.amount());
                }
                if !is_genesis_zero && self.node_info.is_seeded(nt.initializer()) {
                    let debit = nt.amount().wrapping_add(nt.fee() as u64);
                    self.node_info.credit(nt.initializer(), debit);
                }
            } else if let Some(reg) = tx.as_registration() {
                // Stride-1 on a bounded roster: the slot was empty and the
                // watermark one below the new id (D1 precondition 2).
                let node_id = reg.new_node_id();
                self.node_info.clear_node(node_id);
                if !is_genesis_zero && (node_id as usize) < MAX_NODES {
                    self.node_info
                        .set_max_known_node_id(node_id.saturating_sub(1));
                }
                if !is_genesis_zero && self.node_info.is_seeded(reg.initializer()) {
                    let debit = reg.registration_price().wrapping_add(reg.fee());
                    self.node_info.credit(reg.initializer(), debit);
                }
            } else if let Some(cx) = tx.as_complex() {
                self.invert_complex(&cx, idx, usize::MAX, usize::MAX, is_genesis_zero);
            }
        }
    }

    /// Inverts the first `inputs` inputs and `outputs` outputs of a complex
    /// transaction. The balance inverses wrap, so they are exact in any order,
    /// and every spent UTXO bit is a distinct bit; a spend is re-resolved by
    /// the same ancestor walk, and a trusted below-anchor input (nothing was
    /// spent) re-resolves to nothing.
    fn invert_complex(
        &mut self,
        cx: &ComplexTransactionView<'_>,
        idx: u32,
        inputs: usize,
        outputs: usize,
        is_genesis_zero: bool,
    ) {
        for output in cx.outputs().take(outputs) {
            if let Some(bo) = output.as_balance()
                && self.node_info.is_seeded(bo.receiver())
            {
                self.node_info.debit(bo.receiver(), bo.amount());
            }
        }
        let parent = self
            .blocks
            .get(idx)
            .map_or(NONE_REF, |entry| entry.parent_ref());
        for input in cx.inputs().take(inputs) {
            if let Some(bi) = input.as_balance() {
                if !is_genesis_zero && self.node_info.is_seeded(bi.initializer()) {
                    self.node_info.credit(bi.initializer(), bi.amount());
                }
            } else if let Some(ui) = input.as_utxo()
                && let Ok(Some(slot)) = self.ancestor_at(parent, ui.block_sequence())
            {
                self.blocks
                    .set_utxo_available(slot, ui.output_index() as usize, true);
            }
        }
    }

    /// FR6 vote-target existence (AC5): the `vote` node id must name a node that
    /// exists on the candidate. Node ids are contiguous — registration is stride-1
    /// (`new_node_id == max_known_node_id + 1`) and ids are never renumbered — so a
    /// node exists iff its id is within `[0, max_known_node_id]`. This is a **range
    /// check against the watermark**, not a per-node `is_seeded` lookup, and that
    /// distinction is what keeps a **window-anchored** candidate correct: the
    /// watermark is set to the full node count (including pre-window nodes) by the
    /// window's first balance block (`max_node_id`, api.rs `saw_balance_block`
    /// branch), whereas a *specific* pre-window node's in-window balance-block
    /// coverage (`is_seeded`) can fall later in the window than a transaction that
    /// legitimately votes for it (FR50 seed-source replays are emitted head-ward),
    /// which would produce a spurious `VoteTargetUnknown`. `vote == 0` is subsumed
    /// (`0 <= max`), kept explicit as the permanent FR37/FR54 node-#0 target that is
    /// valid even for a window-anchored candidate not containing block #0.
    ///
    /// The residual edge — a transaction validated *before* the window's first
    /// balance block, when the watermark is still 0 — is the same ordering
    /// assumption the FR6 registration-monotonicity check already relies on (it too
    /// reads `max_known_node_id`), so this introduces no new dependency.
    fn check_vote_target(&self, vote: u32) -> Result<(), ValidationReason> {
        if vote == 0 || vote <= self.node_info.max_known_node_id() {
            Ok(())
        } else {
            Err(ValidationReason::VoteTargetUnknown)
        }
    }

    /// FR6 node-existence bound (AC5) for a transaction-referenced node id (an
    /// initializer/spender on the input side, or a receiver on the output side).
    /// Contiguous ids ⇒ a node exists iff `id <= max_known_node_id`; an id beyond
    /// the watermark cannot name any node. Unlike the balance/signature checks this
    /// needs no per-node derived state, so it applies **even to a not-yet-seeded
    /// (pre-window) node** — the existence of an unseeded actor/receiver is still
    /// range-checkable. Callers gate it on the watermark being authoritative
    /// (`roster_bounded`): a window-anchored candidate with no balance block in the
    /// segment has no reliable bound and trusts the reference (AC4).
    fn check_node_id_in_range(&self, node_id: u32) -> Result<(), ValidationReason> {
        if node_id <= self.node_info.max_known_node_id() {
            Ok(())
        } else {
            Err(ValidationReason::NodeIdOutOfRange)
        }
    }

    /// Verifies the FR6 block-creator signature (AC2b) over the canonical signing
    /// preimage (the full block bytes with the trailing-64 header signature field
    /// zero-filled — exactly what `BlockBuilder::build_signed` signs; the
    /// signature is the last 64 bytes of the fixed `HEADER_SIZE` header). Returns
    /// `Some(valid)`, or `None` when the creator's public key is not yet derivable
    /// (pre-seed zone → the block is trusted, not re-proved). Node #0 resolves to
    /// the FR69 trust anchor (`node_zero_public_key`), available from construction.
    // Its own frame (stack budget, DEC-136): the 2 KB preimage is live only
    // here, never alongside the UTXO resolver's read buffer.
    #[inline(never)]
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

    /// Whether `creator`'s key is the same on every branch that forks at or
    /// above the block at sequence `bound` (FR9 Tier 1 case (2); Story 6.2 D6,
    /// DEC-157; Story 6.3 D5, DEC-170): node #0 (the FR69 trust anchor), or a
    /// node seeded at or below `bound`, or whose seed source was released. Its
    /// registration then lies on the shared chain, and a key never changes
    /// after registration. Intake passes `S_tail` — every branch that can
    /// connect contains the chain up to it (DEC-125) — and the chain-switch
    /// pre-pass passes the common ancestor. RAM only.
    fn key_is_branch_independent(&self, creator: u32, bound: u32) -> bool {
        if creator == 0 {
            return true;
        }
        match self.node_info.seed_source_of(creator) {
            None => false,
            Some(SEED_SOURCE_RELEASED) => true,
            Some(source) => self
                .blocks
                .get(source)
                .is_some_and(|source| source.sequence() <= bound),
        }
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

    /// ADR-016 UTXO-input resolver (Story 6.8; Story 6.0 reuses it in Ready).
    ///
    /// Resolves `(block_sequence, output_index)` for a block at
    /// `consuming_seq` whose parent is `parent_idx`, checks the input's
    /// `declared_amount`, spends the output and returns its address (the key
    /// the input's signature verifies against, Story 7.1):
    /// 1. causality: `block_sequence` must be below `consuming_seq` (Tier 1
    ///    owns this check; here it is a guard);
    /// 2. distance: `consuming_seq - block_sequence` must not exceed the
    ///    window `W` (FR14 freshness: the output was at or above `S_tail` when
    ///    the consuming block was made);
    /// 3. a RAM-only walk up `parent_ref` to the ancestor at `block_sequence`.
    ///    Only ancestors are visited, so a block on a side branch is never
    ///    found (FR39). Reaching `NONE_REF` first means the output lies below
    ///    the anchor: with `trust_below_anchor` (a window-anchored FR3
    ///    candidate) that is trusted pre-window history and returns `Ok(None)`,
    ///    with no bit to clear and the declared amount trusted (DEC-129);
    ///    otherwise (a genesis-anchored candidate, or the released tail in
    ///    Ready) it is `UtxoUnresolvable`;
    /// 4. the available-UTXO bit, before any read: a bit that is not 1 (the
    ///    output is spent, or lies beyond the block's outputs or the bitfield)
    ///    is `UtxoUnavailable` (DEC-132);
    /// 5. exactly one storage read of the referenced block, for the amount and
    ///    the address. A failed read is a local fault (`StorageRead`), never
    ///    `Invalid`, and so is a set bit whose output the bytes do not hold
    ///    (storage and RAM disagree); a `declared_amount` other than the
    ///    output's is `UtxoAmountMismatch`;
    /// 6. the bit is cleared.
    pub(crate) fn resolve_and_spend_utxo(
        &mut self,
        parent_idx: u32,
        consuming_seq: u32,
        block_sequence: u32,
        output_index: u8,
        declared_amount: u64,
        trust_below_anchor: bool,
    ) -> Result<Option<[u8; 32]>, UtxoSpendError> {
        let ref_idx = match self.locate_utxo_source(parent_idx, consuming_seq, block_sequence)? {
            Some(ref_idx) => ref_idx,
            None if trust_below_anchor => return Ok(None),
            None => {
                return Err(UtxoSpendError::Invalid(ValidationReason::UtxoUnresolvable));
            }
        };
        let bit = output_index as usize;
        if self.blocks.utxo_available(ref_idx, bit) != Some(true) {
            return Err(UtxoSpendError::Invalid(ValidationReason::UtxoUnavailable));
        }

        // The bit said the output exists; bytes that lack it are the node's own
        // fault, not evidence against the spending block.
        let (address, amount) = self
            .utxo_output_of(ref_idx, output_index)?
            .ok_or(UtxoSpendError::StorageRead)?;
        if amount != declared_amount {
            return Err(UtxoSpendError::Invalid(
                ValidationReason::UtxoAmountMismatch,
            ));
        }

        self.blocks.set_utxo_available(ref_idx, bit, false);
        Ok(Some(address))
    }

    /// Steps 1–3 of [`Self::resolve_and_spend_utxo`], shared with the Tier 2
    /// structural check (Story 6.1 D6): causality, the `W` distance bound and
    /// the ancestor walk. `Ok(None)` when the walk reaches the anchor first —
    /// the output lies below it; each caller decides whether that is trusted.
    fn locate_utxo_source(
        &self,
        parent_idx: u32,
        consuming_seq: u32,
        block_sequence: u32,
    ) -> Result<Option<u32>, UtxoSpendError> {
        let unresolvable = UtxoSpendError::Invalid(ValidationReason::UtxoUnresolvable);
        if block_sequence >= consuming_seq {
            return Err(unresolvable);
        }
        // The held configuration's `W`. In the FR3 pass the preload has already
        // made it the candidate's own, tentative or durable (DEC-129).
        if self
            .active_chain_length()
            .is_some_and(|w| consuming_seq - block_sequence > w)
        {
            return Err(unresolvable);
        }
        self.ancestor_at(parent_idx, block_sequence)
    }

    /// Reads the referenced block once for the output at `output_index`:
    /// `Ok(None)` when its bytes hold no such output, `StorageRead` on a
    /// failed read. Its own frame (stack budget, DEC-136): the read buffer
    /// must not merge into the per-block step's frame with the signature
    /// preimage.
    #[inline(never)]
    fn utxo_output_of(
        &self,
        ref_idx: u32,
        output_index: u8,
    ) -> Result<Option<([u8; 32], u64)>, UtxoSpendError> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self
            .view_retained(ref_idx, &mut buf)
            .ok_or(UtxoSpendError::StorageRead)?;
        Ok(utxo_output_at(&view, output_index))
    }

    /// FR9 Tier 2 of a side block in Ready (Story 6.1 D6): the UTXO-input
    /// structural completion of every complex transaction, along the block's
    /// own ancestry from `parent_idx`. A reference within `W` resolves to its
    /// block, whose bytes must hold the output with the declared amount; one
    /// below `S_tail` is trusted pre-window history, as in the FR3 pass
    /// (DEC-129, DEC-131). No available-UTXO bit is read: the bits follow the
    /// active chain, so whether the output is unspent on this branch is Tier 3.
    ///
    /// The other FR9 Tier 2 items join here and in the shared head step
    /// together: `mined_amount`, fee and price rules (7.2 / 7.3), the approval
    /// threshold (6.7), the structural `snake_chain` checks (9.2 / 9.3 / 9.5 /
    /// 6.6). Registration-key uniqueness is Tier 3 on a side branch (D6).
    fn tier2_check(
        &self,
        view: &BlockView<'_>,
        idx: u32,
        parent_idx: u32,
    ) -> Result<(), ProcessingError> {
        let Some(txs) = view.transactions() else {
            return Ok(());
        };
        for tx in txs.iter() {
            let Some(cx) = tx.as_complex() else {
                continue;
            };
            for input in cx.inputs() {
                let Some(ui) = input.as_utxo() else {
                    continue;
                };
                let reason =
                    match self.locate_utxo_source(parent_idx, view.sequence(), ui.block_sequence())
                    {
                        Ok(None) => continue,
                        Ok(Some(ref_idx)) => {
                            match self.utxo_output_of(ref_idx, ui.output_index()) {
                                Ok(Some((_, amount))) if amount == ui.amount() => continue,
                                Ok(Some(_)) => ValidationReason::UtxoAmountMismatch,
                                Ok(None) => ValidationReason::UtxoUnresolvable,
                                Err(_) => return Err(ProcessingError::StorageRead),
                            }
                        }
                        Err(UtxoSpendError::Invalid(reason)) => reason,
                        Err(_) => return Err(ProcessingError::MissingBlock),
                    };
                return Err(ProcessingError::Invalid {
                    block_idx: idx,
                    reason,
                });
            }
        }
        Ok(())
    }

    /// Judges a prospective extension of the active head — a direct one at
    /// intake (AC3, before it is stored) or a stored child (AC4) — in the
    /// complete context (D3): first the FR48 window gate, then the fallible
    /// half of the per-block step. On `Valid` its invertible effects are
    /// applied; otherwise the derived state is as it was (D1). `idx` is the
    /// block's slot, already holding its entry.
    fn judge_head_extension(&mut self, view: &BlockView<'_>, idx: u32, tail: u32) -> Extension {
        let head = self.active_chain_head_idx;
        let Some(head_hash) = self.blocks.get(head).map(|entry| *entry.hash()) else {
            return Extension::Local;
        };
        // FR48 window gate (9.1): an extension that would make the active
        // chain longer than `W`, measured from `tail`, drops `tail`, which its
        // binding must allow. `tail` is the physical tail, or a chain-switch
        // replay's virtual one (Story 6.3 D3). `W` is read now (FR56), never
        // the capacity.
        let mut advance = None;
        if let Some(w) = self.active_chain_length() {
            let (Some(tail_entry), Some(head_entry)) =
                (self.blocks.get(tail), self.blocks.get(head))
            else {
                return Extension::Local;
            };
            let sequence = head_entry.sequence() + 1;
            // New length `S_head + 1 − S_tail + 1` exceeds `W`.
            let full = sequence.saturating_sub(tail_entry.sequence()) >= w;
            // DEC-204: a block at `sequence ≥ W` drops block `sequence − W`
            // wherever the walk stands, and its binding is evaluated against
            // that retained block — the tail when the window is full, a block
            // below a window a chain-switch backward walk shortened otherwise
            // (Story 6.14's horizon). A dropped block that is not retained
            // cannot be evaluated: a local failure, never trust.
            if sequence >= w {
                let dropped = if full {
                    tail
                } else {
                    match self.ancestor_at(head, sequence - w) {
                        Ok(Some(dropped)) => dropped,
                        _ => return Extension::Local,
                    }
                };
                let Ok(obligation) = classify_tail_drop(&self.blocks, &self.node_info, dropped)
                else {
                    return Extension::Local;
                };
                if tail_drop_binding(obligation, view) == TailBinding::Invalid {
                    return Extension::Invalid;
                }
            }
            if full {
                // FR21 (iii): the block that becomes `S_tail` leaves every
                // sum; its value is read now, before anything is mutated, so
                // a failed read is a local failure (Story 6.1 D1).
                let Some(tail_value) = self.new_tail_value(tail) else {
                    return Extension::Local;
                };
                advance = Some(tail_value);
            }
        }
        let mut projection = Projection::COMPLETE;
        match self.derive_block(view, idx, Some(head_hash), &mut projection) {
            Ok(derivation) => Extension::Valid {
                advance,
                derivation,
            },
            Err(err) if is_evidence(&err) => Extension::Invalid,
            Err(_) => Extension::Local,
        }
    }

    /// The FR21 value of the block that becomes `S_tail` when the window
    /// advances past `tail`: its active-chain child. `None` on a failed read —
    /// a local failure. The tail is never the head here: that needs `W = 1`,
    /// where FR60 refuses every extension (`s_new ≥ s_head + W`).
    fn new_tail_value(&self, tail: u32) -> Option<u64> {
        self.block_value_at(self.tail_successor(tail)?)
    }

    /// The active-chain child of `tail`: the block that becomes `S_tail`
    /// when the window advances past it. RAM only, O(`MAX_BLOCKS`).
    fn tail_successor(&self, tail: u32) -> Option<u32> {
        (0..MAX_BLOCKS as u32).find(|idx| {
            self.blocks
                .get(*idx)
                .is_some_and(|entry| entry.parent_ref() == tail && entry.is_on_active_chain())
        })
    }

    /// Reads a retained block and returns its FR21 value; `None` on a failed
    /// read. The read copy lives only in this frame (DEC-136).
    #[inline(never)]
    fn block_value_at(&self, idx: u32) -> Option<u64> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        self.view_retained(idx, &mut buf)
            .map(|view| block_value(&view))
    }

    /// Promotes a block that passed the whole per-block step to the active
    /// head (AC3/AC4, D7: Stored → Active directly), refreshes its
    /// `chain_heads` entry (AC7), adds its FR21 `value` to the active value
    /// (event (i)) and, when the window gate said so, advances the tail (9.1)
    /// and subtracts the new `S_tail` block's value from every value (event
    /// (iii), Story 6.1 D1).
    fn promote_head_extension(&mut self, idx: u32, value: u64, advance: Option<u64>) {
        self.blocks.set_status(idx, BlockStatus::Active);
        self.blocks.set_on_active_chain(idx, true);
        self.active_chain_head_idx = idx;
        self.chain_heads.refresh_head(&self.blocks, idx);
        self.active_branch_value += value;
        // FR64 (Epic 11 `LogSink`): emit the head-extension event carrying the
        // promoted block's hash and sequence. Deferred — see deferred-work.md.
        if let Some(tail_value) = advance
            && self.advance_snake_chain_tail()
        {
            self.active_branch_value = self.active_branch_value.saturating_sub(tail_value);
            self.chain_heads
                .subtract_branch_value(&self.blocks, tail_value);
        }
    }

    /// Story 6.0 AC4 — continues the active head over children that are
    /// already stored: orphans that became children of the head when their
    /// parent arrived and was promoted, and an earlier local-failure retry.
    /// Runs after every Ready admission and after every direct extension.
    ///
    /// Each pass picks one Stored child of the head by the FR21 rank (Story
    /// 6.1 D9, [`Self::best_stored_child`]), judges it, and either promotes it,
    /// deletes it with its descendants (its verdict is final, D2), or stops on
    /// a local failure, leaving it Stored. At most `MAX_BLOCKS` passes. Each
    /// costs O(`MAX_BLOCKS`) child scans (there is no child index), one read of
    /// the chosen child, one read per sibling when there are several (their
    /// rank), and one read of the new tail when the window advances.
    fn drive_forward_extension(&mut self) {
        for _ in 0..MAX_BLOCKS {
            let Some(child) = self.best_stored_child() else {
                return;
            };
            // The child's read copy lives in its own frame, gone before any
            // deletion or tail advance, whose delete-set buffer (2.4 KB) must
            // not share the stack with it (D4, DEC-136).
            match self.apply_stored_child(child, self.snake_chain_tail_idx) {
                ChildStep::Applied { advance, value } => {
                    self.promote_head_extension(child, value, advance);
                }
                // A local failure: the child stays Stored for a later retry.
                ChildStep::Local => return,
                // AC5: no derived state was touched (D1), the head stays, and
                // the node stays Ready — never the FR5 recovery.
                //
                // FR64 (Epic 11 `LogSink`): emit the deletion event carrying
                // the child's hash. Deferred — see deferred-work.md.
                ChildStep::Invalid => {
                    self.delete_subtree_with_followup(child);
                }
            }
        }
    }

    /// Story 6.1 AC6 — Tier 2 and Stored → Connected for side blocks in
    /// Ready, and their FR21 values. Runs after every Ready admission (after
    /// the continuation, whose promotion turns a sibling into a side block)
    /// and at every Ready entry.
    ///
    /// It handles the blocks stored before their Tier 2 could run — orphans
    /// connected later, blocks retained while Collecting, local-failure
    /// retries; a new block with a Connected or Active parent was judged before
    /// its write (D4). Each pending side head ([`Self::is_pending_side_head`])
    /// is walked once ([`Self::walk_side_branch`]):
    /// - every Stored block passes: they become Connected and the head's value
    ///   is `active − Σ_active + Σ_branch` (FR21 (ii));
    /// - exact evidence: the lowest failing block goes with its descendants;
    ///   the passed blocks below it become Connected, and the entry the
    ///   deletion retargets onto its parent takes the value the same walk
    ///   gives it (FR21 (v) in Ready, D8). The table changed, so the scan
    ///   restarts;
    /// - a local failure leaves the head pending for the next admission.
    ///
    /// Bounded: each round connects a head or deletes a block, or ends.
    ///
    /// Returns the highest-ranked admissible head it valued (FR22 (ii) and the
    /// FR21 (v) retarget; Story 6.2 D1): filtered by admissibility before the
    /// choice, so an inadmissible top cannot hide an admissible runner-up.
    /// The continuation ran before, so the window is final here.
    fn connect_side_branches(&mut self) -> Option<u32> {
        let mut best = None;
        if self.snake_chain_tail_idx == NONE_REF {
            return None;
        }
        for _ in 0..MAX_BRANCH_COUNT + MAX_BLOCKS {
            let mut progressed = false;
            for slot in 0..MAX_BRANCH_COUNT {
                let Some(head) = self.chain_heads.connected_head_at(slot) else {
                    continue;
                };
                if !self.is_pending_side_head(head) {
                    continue;
                }
                let Ok(walk) = self.walk_side_branch(head) else {
                    continue;
                };
                progressed = true;
                match walk.failing {
                    None => {
                        // FR64 (Epic 11 `LogSink`): emit the connect event.
                        // Deferred — see deferred-work.md.
                        self.mark_connected(head);
                        let value = self.side_value(walk.active, walk.branch);
                        self.chain_heads.set_branch_value(head, value);
                        self.consider(&mut best, head);
                    }
                    Some((failing, through)) => {
                        let parent = self
                            .blocks
                            .get(failing)
                            .map_or(NONE_REF, |entry| entry.parent_ref());
                        self.mark_connected(parent);
                        // FR64 (Epic 11 `LogSink`): emit the deletion event
                        // carrying the block's hash. Deferred — see
                        // deferred-work.md.
                        self.delete_subtree_with_followup(failing);
                        if self
                            .blocks
                            .get(parent)
                            .is_some_and(|entry| entry.status() == BlockStatus::Connected)
                        {
                            let value = self.side_value(walk.active, walk.branch - through);
                            self.chain_heads.set_branch_value(parent, value);
                            self.consider(&mut best, parent);
                        }
                        break;
                    }
                }
            }
            if !progressed {
                return best.map(|(head, _)| head);
            }
        }
        best.map(|(head, _)| head)
    }

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
    fn consider(&self, best: &mut Option<(u32, Rank)>, head: u32) {
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
    fn switch_target(&self, candidates: [Option<u32>; 2]) -> Option<u32> {
        let mut best = None;
        for head in candidates.into_iter().flatten() {
            self.consider(&mut best, head);
        }
        let (head, rank) = best?;
        rank.outranks(&self.active_rank()?).then_some(head)
    }

    /// The FR23 chain switch toward `head` (FR22; Story 6.3, DEC-166..171,
    /// DEC-204): an atomic, in-place walk — back from the active head to the
    /// common ancestor by exact per-block inverses, then forward to `head`
    /// through the shared Tier-3 step — that either completes or leaves the
    /// original chain exactly as it was (AC6). It runs inside this call, so no
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
    fn switch_toward(&mut self, head: u32) -> SwitchOutcome {
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
                // Nothing was mutated: delete the forgery, and give the entry
                // retargeted onto its parent the value below it.
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
                return self.restore_original(old_head, old_value, None);
            }
        }

        // AC4 — the forward replay, with the tail advances against a virtual
        // tail and released only at the commit (D3, DEC-168). Story 7.4:
        // remove each applied block's transactions from the mempool here
        // (FR32 (2)).
        let mut virtual_tail = self.snake_chain_tail_idx;
        let mut advances = 0usize;
        let mut released_value = 0u64;
        while self.active_chain_head_idx != head {
            let Some(next) = self.next_toward(head) else {
                return self.restore_original(old_head, old_value, None);
            };
            match self.apply_stored_child(next, virtual_tail) {
                ChildStep::Applied { advance, value } => {
                    self.promote_replayed(next, value);
                    if let Some(tail_value) = advance {
                        let Some(successor) = self.tail_successor(virtual_tail) else {
                            return self.restore_original(old_head, old_value, None);
                        };
                        virtual_tail = successor;
                        advances += 1;
                        released_value = released_value.saturating_add(tail_value);
                    }
                }
                ChildStep::Invalid => {
                    // `next`'s parent is the current head: its value is the
                    // active value now, before anything is undone.
                    let parent_value = self.active_branch_value;
                    return self.restore_original(old_head, old_value, Some((next, parent_value)));
                }
                ChildStep::Local => return self.restore_original(old_head, old_value, None),
            }
        }
        // The walk must land on the value the comparison ranked (FR21): a
        // mismatch means an inconsistent table — a local failure.
        if self.chain_heads.branch_value_of(head) != Some(self.active_branch_value) {
            return self.restore_original(old_head, old_value, None);
        }
        self.commit_switch(head, old_head, old_value, advances, released_value);
        SwitchOutcome::Switched
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
        let (Some(ancestor), Some(root), Some(top), Some(w)) = (
            self.blocks.get(ancestor),
            self.blocks.get(self.snake_chain_tail_idx),
            self.blocks.get(self.active_chain_head_idx),
            self.active_chain_length(),
        ) else {
            return false;
        };
        crate::reconciliation::switch_admitted(
            ancestor.sequence(),
            root.sequence(),
            top.sequence(),
            w,
            self.verification_horizon(),
            self.complete_from_sequence,
        )
    }

    /// FR58's `H` (DEC-160, DEC-166): the registry default until Story 6.14
    /// reads `verification_horizon` (ID 30) from the active configuration.
    fn verification_horizon(&self) -> u32 {
        50
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
            through = through.saturating_add(block_value(&view));
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
    fn undo_active_head(&mut self) -> Result<(), ()> {
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
        self.undo_committed_block(idx, &owners[..count], &sources[..count])?;
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
    /// registers it, walking down to the root; `SEED_SOURCE_RELEASED` when the
    /// root misses too. One scan for every owner, bounded by the window (FR50
    /// coverage); a block that can hold neither is skipped unread. Its own
    /// read buffer (DEC-136). `Err` on a failed read: a local failure.
    #[inline(never)]
    fn previous_seed_sources(&self, from: u32, owners: &[u32], out: &mut [u32]) -> Result<(), ()> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let mut remaining = owners.len();
        let mut cur = from;
        for _ in 0..MAX_BLOCKS {
            if remaining == 0 || cur == NONE_REF {
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
    /// inverse is the identity (O-009, DEC-025). Its own read buffer.
    #[inline(never)]
    fn undo_committed_block(
        &mut self,
        idx: u32,
        owners: &[u32],
        sources: &[u32],
    ) -> Result<(), ()> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf).ok_or(())?;
        let value = block_value(&view);
        let remaining_value = self.active_branch_value.checked_sub(value).ok_or(())?;
        // The vote engine refuses atomically; its errors are the node's own
        // state, never evidence against the block (AC2 step 2).
        if let Ok(v) = BlockView::from_bytes(view.serialized_bytes()) {
            self.vote_engine.undo_block(v).map_err(|_| ())?;
        }
        // Undone top-down: every descendant spend of this block's outputs is
        // undone already and side branches never touch bits, so its bits are
        // exactly its own outputs.
        self.blocks.clear_available_utxo(idx);
        for (owner, source) in owners.iter().zip(sources) {
            self.node_info.move_seed_source(*owner, *source);
        }
        if view.sequence() > 1 && self.node_info.is_seeded(view.creator()) {
            self.node_info.debit(
                view.creator(),
                view.mined_amount() as u64 + block_fees(&view),
            );
        }
        self.invert_transactions(&view, idx, usize::MAX);
        self.active_branch_value = remaining_value;
        Ok(())
    }

    /// Promotes a block the replay (or the restore) just applied: Connected →
    /// Active (FR9), on the active chain, the new head; its FR21 value joins
    /// the active value. The tail is left to the commit (D3).
    fn promote_replayed(&mut self, idx: u32, value: u64) {
        self.blocks.set_status(idx, BlockStatus::Active);
        self.blocks.set_on_active_chain(idx, true);
        self.active_chain_head_idx = idx;
        self.active_branch_value += value;
    }

    /// AC5 — the commit, after which nothing fails: FR19 event (iii) first
    /// (the release step's fragment reclamation reads current caches), the
    /// FR21 (iv) value hand-over before any release (a release may delete the
    /// old head), then the deferred tail advances and their FR21 (iii)
    /// subtraction. No comparison follows (FR22 (d)). Story 9.7 adds the
    /// switch-bound reclamation here, after the releases (DEC-159, DEC-161);
    /// Story 7.4 the mempool window expiry (FR32 (3)).
    fn commit_switch(
        &mut self,
        head: u32,
        old_head: u32,
        old_value: u64,
        advances: usize,
        released_value: u64,
    ) {
        self.chain_heads.recompute_all_caches(&self.blocks);
        // The active value is never an entry (DEC-144); the old head, if an
        // entry still names it, carries the old active value.
        self.chain_heads.set_branch_value(head, 0);
        self.chain_heads.set_branch_value(old_head, old_value);
        for _ in 0..advances {
            if !self.advance_snake_chain_tail() {
                // Unreachable by construction — the replay advanced the
                // virtual tail along the same flagged chain. FR64: log the
                // invariant breach. Deferred — see deferred-work.md.
                return;
            }
        }
        self.active_branch_value = self.active_branch_value.saturating_sub(released_value);
        self.chain_heads
            .subtract_branch_value(&self.blocks, released_value);
    }

    /// AC6 — restores the original chain after a failed walk: undoes every
    /// block above the original chain's path, re-applies the original branch
    /// up to `old_head` by the same step (its blocks are marked, so no
    /// signature is verified again), and, for exact evidence at `offender`,
    /// deletes it with its descendants. Any error while re-applying stops the
    /// restore where it is (a restore failure), whatever its kind.
    fn restore_original(
        &mut self,
        old_head: u32,
        old_value: u64,
        offender: Option<(u32, u64)>,
    ) -> SwitchOutcome {
        while !self.on_path_to(old_head) {
            if self.undo_active_head().is_err() {
                return self.stop_restore(old_head, old_value, offender);
            }
        }
        let tail = self.snake_chain_tail_idx;
        while self.active_chain_head_idx != old_head {
            let Some(next) = self.next_toward(old_head) else {
                return self.stop_restore(old_head, old_value, offender);
            };
            match self.apply_stored_child(next, tail) {
                // The original chain fit the window, so re-applying it never
                // advances the tail.
                ChildStep::Applied {
                    advance: None,
                    value,
                } => self.promote_replayed(next, value),
                _ => return self.stop_restore(old_head, old_value, offender),
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

    /// AC6 restore failure: the active head stays at the highest block the
    /// restore reached — every step is atomic, so its state is exact for that
    /// chain — the original head's entry takes the original value (in RAM),
    /// and nothing of the original chain is deleted. The offender, if any, is
    /// still exact evidence.
    fn stop_restore(
        &mut self,
        old_head: u32,
        old_value: u64,
        offender: Option<(u32, u64)>,
    ) -> SwitchOutcome {
        self.chain_heads.recompute_all_caches(&self.blocks);
        self.chain_heads.set_branch_value(old_head, old_value);
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

    /// A pending side head: Stored, and the lowest Stored block of its branch
    /// is not a child of the active head — those stay with the Story 6.0
    /// continuation (Tier 2 + 3 in one step), which only extends into Stored
    /// children. The caller has checked the `connected` cache.
    fn is_pending_side_head(&self, head: u32) -> bool {
        let mut lowest = NONE_REF;
        let mut cur = head;
        for _ in 0..MAX_BLOCKS {
            match self.blocks.get(cur) {
                Some(entry) if entry.status() == BlockStatus::Stored => {
                    lowest = cur;
                    cur = entry.parent_ref();
                }
                _ => break,
            }
        }
        lowest != NONE_REF && cur != NONE_REF && cur != self.active_chain_head_idx
    }

    /// Walks the side branch of `head` down to its connection point (the first
    /// block on the active chain), reading each block once, then the active
    /// chain from the head down to the same point: the FR21 sums of FR21 (ii).
    /// Every Stored block runs the Tier 2 check; the lowest failing one is
    /// reported. `Err` on a local failure — nothing is changed. The read copy lives only in this
    /// frame (DEC-136), gone before the caller deletes anything.
    #[inline(never)]
    fn walk_side_branch(&self, head: u32) -> Result<SideWalk, ()> {
        // Every FR21 sum adds at most `MAX_BLOCKS` `u32` values (a branch, or
        // the active window), so plain `u64` additions cannot overflow.
        const { assert!((MAX_BLOCKS as u128) * (u32::MAX as u128) <= u64::MAX as u128) };
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let mut branch = 0u64;
        let mut failing = None;
        let mut cur = head;
        let mut connection = NONE_REF;
        for _ in 0..MAX_BLOCKS {
            let entry = self.blocks.get(cur).ok_or(())?;
            if entry.is_on_active_chain() {
                connection = cur;
                break;
            }
            let (stored, parent) = (entry.status() == BlockStatus::Stored, entry.parent_ref());
            let view = self.view_retained(cur, &mut buf).ok_or(())?;
            branch += block_value(&view);
            if stored {
                match self.tier2_check(&view, cur, parent) {
                    Ok(()) => {}
                    // Walking down, a later failure is a lower one.
                    Err(err) if is_evidence(&err) => failing = Some((cur, branch)),
                    Err(_) => return Err(()),
                }
            }
            cur = parent;
        }
        if connection == NONE_REF {
            return Err(());
        }
        let mut active = 0u64;
        let mut cur = self.active_chain_head_idx;
        for _ in 0..MAX_BLOCKS {
            if cur == connection {
                return Ok(SideWalk {
                    active,
                    branch,
                    failing,
                });
            }
            let parent = self.blocks.get(cur).ok_or(())?.parent_ref();
            active += block_value(&self.view_retained(cur, &mut buf).ok_or(())?);
            cur = parent;
        }
        Err(())
    }

    /// FR21 (ii): a side head's value from the walk's sums. Exact: the active
    /// blocks above the connection point are part of the active value.
    fn side_value(&self, active: u64, branch: u64) -> u64 {
        self.active_branch_value.saturating_sub(active) + branch
    }

    /// Stored → Connected for `from` and every Stored ancestor below it — the
    /// blocks a side walk found passing Tier 2.
    fn mark_connected(&mut self, from: u32) {
        let mut cur = from;
        for _ in 0..MAX_BLOCKS {
            match self.blocks.get(cur) {
                Some(entry) if entry.status() == BlockStatus::Stored => {
                    let parent = entry.parent_ref();
                    self.blocks.set_status(cur, BlockStatus::Connected);
                    cur = parent;
                }
                _ => return,
            }
        }
    }

    /// Story 6.1 D4 — connects a side block judged at Tier 2 before its write,
    /// once `chain_heads` has seen it: interior after a merge (the surviving
    /// orphan head is the driver's); the extension of a Connected side head,
    /// valued incrementally from the parent's value read before the admission
    /// (FR21 (i)); otherwise a fork, valued by the walk from its Connected or
    /// Active `parent` plus its own `value` in hand — the block itself is never
    /// read back. A local failure there leaves it Stored, and the driver judges
    /// it again.
    fn connect_judged_side_block(
        &mut self,
        idx: u32,
        parent: u32,
        value: u64,
        parent_value: Option<u64>,
    ) {
        if self.chain_heads.branch_value_of(idx).is_none() {
            self.blocks.set_status(idx, BlockStatus::Connected);
            return;
        }
        let value = match parent_value {
            Some(parent_value) => parent_value + value,
            None => match self.walk_side_branch(parent) {
                Ok(walk) => self.side_value(walk.active, walk.branch + value),
                Err(()) => return,
            },
        };
        self.blocks.set_status(idx, BlockStatus::Connected);
        self.chain_heads.set_branch_value(idx, value);
    }

    /// The Stored child of the active head the continuation takes next: the
    /// only one without a read, else the FR21 rank winner at the child level
    /// (Story 6.1 D9). All siblings share the active value, so each one's own
    /// value decides. `None` when there is no child, or when any candidate
    /// cannot be read — a local failure, never a choice: the continuation stops
    /// and retries at a later admission (code review 2026-10-20). Greedy per
    /// level: a heavier deeper subtree is reached by the FR22 comparison at the
    /// end of the admission (Story 6.2) and the FR23 switch (6.3).
    fn best_stored_child(&self) -> Option<u32> {
        let head = self.active_chain_head_idx;
        let is_candidate = |idx: u32| {
            self.blocks.get(idx).is_some_and(|entry| {
                entry.parent_ref() == head && entry.status() == BlockStatus::Stored
            })
        };
        let mut candidates = (0..MAX_BLOCKS as u32).filter(|idx| is_candidate(*idx));
        let first = candidates.next()?;
        if candidates.next().is_none() {
            return Some(first);
        }
        let mut best: Option<(u32, Rank)> = None;
        for idx in (0..MAX_BLOCKS as u32).filter(|idx| is_candidate(*idx)) {
            let rank = self.child_rank(idx)?;
            if best.as_ref().is_none_or(|(_, top)| rank.outranks(top)) {
                best = Some((idx, rank));
            }
        }
        best.map(|(idx, _)| idx)
    }

    /// The FR21 rank of a stored child of the head: its value from one read,
    /// its size and hash from RAM. The read copy lives only in this frame
    /// (DEC-136).
    #[inline(never)]
    fn child_rank(&self, idx: u32) -> Option<Rank> {
        let entry = self.blocks.get(idx)?;
        let (len, hash) = (entry.len(), *entry.hash());
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf)?;
        Some(Rank {
            value: block_value(&view),
            len,
            hash,
        })
    }

    /// Reads a child of the head and runs the whole per-block step on it, the
    /// window gate measured from `tail` (the physical tail, or a chain-switch
    /// replay's virtual one, Story 6.3 D3).
    #[inline(never)]
    fn apply_stored_child(&mut self, child: u32, tail: u32) -> ChildStep {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let Some(view) = self.view_retained(child, &mut buf) else {
            return ChildStep::Local;
        };
        match self.judge_head_extension(&view, child, tail) {
            Extension::Valid {
                advance,
                derivation,
            } => match self.commit_block(&view, child, derivation) {
                Ok(()) => ChildStep::Applied {
                    advance,
                    value: block_value(&view),
                },
                Err(err) if is_evidence(&err) => ChildStep::Invalid,
                Err(_) => ChildStep::Local,
            },
            Extension::Invalid => ChildStep::Invalid,
            Extension::Local => ChildStep::Local,
        }
    }

    /// The ancestor of `from` (inclusive) at `sequence`, by a RAM-only walk up
    /// `parent_ref` (ADR-016 resolution; the UTXO inverse re-resolves by it).
    /// `Ok(None)` when the walk reaches the anchor first. Each parent is
    /// exactly one sequence lower (`blocks.rs` admission), so the walk ends
    /// within the sequence distance; the `MAX_BLOCKS` bound only guards
    /// against a corrupt `parent_ref` cycle.
    fn ancestor_at(&self, from: u32, sequence: u32) -> Result<Option<u32>, UtxoSpendError> {
        let mut cur = from;
        for _ in 0..MAX_BLOCKS {
            if cur == NONE_REF {
                return Ok(None);
            }
            let entry = self.blocks.get(cur).ok_or(UtxoSpendError::MissingBlock)?;
            if entry.sequence() == sequence {
                return Ok(Some(cur));
            }
            cur = entry.parent_ref();
        }
        Err(UtxoSpendError::MissingBlock)
    }

    /// FR4 / FR9 Tier-3 Active-promotion driver (AC9): on a clean FR6 pass, walk
    /// the validated candidate tip → anchor and atomically flip every block
    /// `Stored → Active` with `is_on_active_chain = true`, then establish
    /// `active_chain_head_idx = tip` (overwriting any Story-5.2 bootstrap
    /// placeholder) and the FR48 window over it. A pure `parent_ref` walk (no
    /// storage reads), bounded by `MAX_BLOCKS`.
    fn promote_candidate_active(
        &mut self,
        candidate_tip_idx: u32,
        window_value: u64,
        complete_from: u32,
    ) {
        // Only the candidate is the active chain. A Collecting genesis anchor
        // that the candidate does not contain (FR2 adopted a window-anchored
        // segment, or a restart re-flagged it) would otherwise keep its flag
        // and leave its branch looking Connected for good (review r2).
        for idx in 0..MAX_BLOCKS as u32 {
            self.blocks.set_on_active_chain(idx, false);
        }
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
        self.establish_snake_chain_window();
        // The FR3 walk summed exactly the window just established (D5).
        self.active_branch_value = window_value;
        self.complete_from_sequence = complete_from;
    }

    /// The sequence of the tail the window over a chain from `root_seq` to
    /// `head_seq` lands on: `max(root_seq, head_seq + 1 − W)`, the whole chain
    /// when no `W` is held. One function for the Ready-entry trim and the FR3
    /// walk's window value (Story 6.1 D5), so the two cannot disagree. `W` is
    /// read now (FR56), never the capacity.
    fn window_tail_sequence(&self, root_seq: u32, head_seq: u32) -> u32 {
        match self.active_chain_length() {
            Some(w) => root_seq.max((head_seq + 1).saturating_sub(w)),
            None => root_seq,
        }
    }

    /// FR48 — establishes the snake-chain window over the active head, at every
    /// point the node enters Ready with one (genesis, the Processing→Ready
    /// promotion).
    ///
    /// The tail starts at the active chain's root (a pure `parent_ref` walk, no
    /// storage reads) and is then advanced by the ordinary release step until the
    /// window is `W` long, which lands it on `max(anchor_seq, S_head − W + 1)`.
    /// A chain shorter than `W` releases nothing — the bootstrap growth phase,
    /// where a genesis-anchored tail stays at block #0 (AC2).
    ///
    /// A segment longer than `W` (FR2 accepts one, and a restart can hold more)
    /// therefore enters Ready holding exactly `W` blocks (AC3). The excess blocks
    /// are released even when they carry an FR49/FR50/FR51 obligation (Ratified
    /// Decision 4, 2026-10-10): the segment passed FR3/FR6 as a whole and the
    /// state they seed is in the derived projections; FR48's binding governs
    /// head *extensions*, not adoption. Each is still classified first, so the
    /// release record is uniform with a steady-state advance — the result feeds
    /// only the AR16 log (Epic 11), so neither an obligation nor an unreadable
    /// block stops the release here.
    ///
    /// That covers an *unreadable* block as well (Project Lead, 2026-10-13):
    /// at adoption the obligation does not matter, so neither does whether it
    /// could be read.
    ///
    /// `W` is read now (FR56). A Ready node is durably locked, so it is always
    /// there; were it not, the window is the whole active chain and nothing is
    /// released — never the `SNAKE_CHAIN_LENGTH_MAX` capacity in its place
    /// (Story 5.11 Ratified Decision 2).
    ///
    /// Before the trim every `chain_heads` entry is recomputed against the new
    /// marking (O-024 ruling): without it the adopted chain's own head stays
    /// Stored and keeps requesting the anchor's parent, below `S_tail`. Stored
    /// fragments that can never connect are then reclaimed at once (DEC-126,
    /// DEC-127), including a genesis island the adopted chain does not contain.
    ///
    /// **Cost.** The tail is found by walking to the root and then releasing,
    /// not by a `W − 1`-step walk, so the release is literally the steady-state
    /// step. Each released block costs one storage read (transaction blocks
    /// only) plus the release step's own cost (see
    /// [`Self::advance_snake_chain_tail`]): dominated by one
    /// `delete_subtree_with_followup` per fork and per reclaimed fragment, each
    /// O(`MAX_BLOCKS`²) through `mark_subtree`. The number released is the
    /// segment's excess over `W` — 0 on a live join that stops at `W`, larger
    /// only on a restart that re-admits released blocks (R3). Bounded, but
    /// O(excess × `MAX_BRANCH_COUNT` × `MAX_BLOCKS`²) in the worst case; the
    /// common case releases nothing and deletes nothing.
    fn establish_snake_chain_window(&mut self) {
        let mut root = self.active_chain_head_idx;
        for _ in 0..MAX_BLOCKS {
            match self.blocks.get(root) {
                Some(entry) if entry.parent_ref() != NONE_REF => root = entry.parent_ref(),
                _ => break,
            }
        }
        self.snake_chain_tail_idx = root;
        // Before any reclamation or release: the promotion re-marked the active
        // chain without touching `chain_heads`. Current caches keep the adopted
        // chain's own head from looking like a Stored fragment, and make a
        // stale genesis island (now unflagged) look like one — it is reclaimed
        // here, at once, rather than at the first advance (DEC-127).
        self.chain_heads.recompute_all_caches(&self.blocks);
        if let Some(root_seq) = self.blocks.get(root).map(|entry| entry.sequence()) {
            self.reclaim_stale_fragments(root_seq);
        }

        let (Some(root_seq), Some(head_seq)) = (
            self.blocks.get(root).map(|entry| entry.sequence()),
            self.blocks
                .get(self.active_chain_head_idx)
                .map(|entry| entry.sequence()),
        ) else {
            return;
        };
        let target = self.window_tail_sequence(root_seq, head_seq);
        for _ in 0..MAX_BLOCKS {
            if self
                .blocks
                .get(self.snake_chain_tail_idx)
                .is_none_or(|tail| tail.sequence() >= target)
            {
                break;
            }
            let _ = classify_tail_drop(&self.blocks, &self.node_info, self.snake_chain_tail_idx);
            if !self.advance_snake_chain_tail() {
                break;
            }
        }
    }

    /// FR58 stale-fragment reclamation (DEC-126): deletes, whole, every Stored
    /// fragment whose lowest block `t` has `t − 1 ≤ s_tail`. Its missing parent
    /// is below the window (FR60 refuses it) or at `S_tail` without being the
    /// tail block (which would already have linked it), so the fragment's
    /// divergence is below `S_tail` and it can never connect.
    ///
    /// Runs at Ready entry and at the end of every tail advance. It reads only
    /// Stored entries, and a Stored head's tail-point is never on the active
    /// chain — its walk would have stopped there and made it Connected — as
    /// long as the caches are current: Ready entry recomputes them first, and
    /// every later mutation maintains them.
    fn reclaim_stale_fragments(&mut self, s_tail: u32) {
        for slot in 0..MAX_BRANCH_COUNT {
            let Some(tail_point) = self.chain_heads.stored_head_tail(slot) else {
                continue;
            };
            if self
                .blocks
                .get(tail_point)
                .is_some_and(|entry| entry.sequence() <= s_tail.saturating_add(1))
            {
                self.delete_subtree_with_followup(tail_point);
            }
        }
    }

    /// FR48 window-advance / tail-release step (AC5): moves the tail one block
    /// up the active chain and releases the block it leaves. Returns `false`,
    /// changing nothing, when there is nothing to advance over — no tail, or the
    /// tail is the head.
    ///
    /// The caller decides *whether* to advance: the Ready-entry trim
    /// ([`Self::establish_snake_chain_window`]), and Story 6.0's forward
    /// extension, which advances once per head extension past length `W` after
    /// [`crate::snake_chain::tail_drop_binding`] allows it.
    ///
    /// The release (Ratified Decision 2), in order:
    /// 1. **FR58 stale side-branch reclamation** (pulled forward from Story 9.7,
    ///    Project Lead 2026-10-17): every branch forked at the dropped block
    ///    diverges below the new `S_tail`, so neither chain-switch zone can ever
    ///    reach it. Each is deleted whole with
    ///    [`Self::delete_subtree_with_followup`] — a child-closed delete-set, so
    ///    the ordinary `chain_heads` event (iv) applies — while the dropped block
    ///    is still in place, so no surviving walk ever meets the freed slot;
    /// 2. the dropped block's `is_on_active_chain` is cleared and its slot freed
    ///    with the ordinary lazy [`BlockTable::delete`] — the durable bytes stay
    ///    until the slot is reused (Ratified Decision 3);
    /// 3. its one remaining child, the new tail, is unlinked
    ///    (`parent_ref = NONE_REF`) and becomes the active chain's root;
    /// 4. **FR58 stale-fragment reclamation** (Project Lead 2026-10-17): every
    ///    Stored fragment whose lowest block `t` has `t − 1 ≤ S_tail` (the new
    ///    tail) is deleted whole. Its missing parent is either below the window
    ///    (FR60 refuses it) or at `S_tail` — where it cannot be the tail block,
    ///    which would already have linked it — so the fragment's divergence point
    ///    is below `S_tail` and it can never connect. A fragment admitted after
    ///    this step waits for the next advance.
    ///
    /// No `chain_heads` pass is needed for the dropped block itself: it is not a
    /// tip (the new tail is its child), every head above it anchors on the
    /// active chain at or above the new tail, and nothing else passed through it.
    /// **Cost.** Two O(`MAX_BLOCKS`) scans find the children (the table has no
    /// child index) and one O(`MAX_BRANCH_COUNT`) pass finds the fragments. Each
    /// deleted fork or fragment then costs one `delete_subtree_with_followup`:
    /// O(`MAX_BLOCKS`²) worst case through `mark_subtree`, plus its 2.4 KB
    /// delete-set buffer (one call at a time, never nested). A step with nothing
    /// to reclaim stays O(`MAX_BLOCKS`). With `R = 0`
    /// ([`crate::snake_chain::BELOW_TAIL_RETENTION`]) the block is freed at once.
    pub(crate) fn advance_snake_chain_tail(&mut self) -> bool {
        let released = self.snake_chain_tail_idx;
        if released == self.active_chain_head_idx {
            return false;
        }
        // Runtime, not debug-only: Story 6.0 drives this, and releasing a block
        // that is not the active chain's root would leave its parent with a
        // stale `head_ref_count` and strand the chain below it.
        if !self
            .blocks
            .get(released)
            .is_some_and(|entry| entry.is_on_active_chain() && entry.parent_ref() == NONE_REF)
        {
            return false;
        }
        let Some((new_tail, s_tail)) = (0..MAX_BLOCKS as u32).find_map(|idx| {
            self.blocks
                .get(idx)
                .filter(|child| child.parent_ref() == released && child.is_on_active_chain())
                .map(|child| (idx, child.sequence()))
        }) else {
            return false;
        };

        for idx in 0..MAX_BLOCKS as u32 {
            if idx != new_tail
                && self
                    .blocks
                    .get(idx)
                    .is_some_and(|child| child.parent_ref() == released)
            {
                self.delete_subtree_with_followup(idx);
            }
        }
        self.blocks.set_on_active_chain(released, false);
        self.blocks.delete(released);
        // Index hygiene: no module state may name the freed slot. The head is a
        // descendant of the new tail (checked above). Nodes seeded from the
        // block stay seeded but stop naming the slot. The tentative provenance
        // never fires in practice — a Ready node is durably locked — and costs
        // one comparison.
        self.node_info.release_seed_source(released);
        if self.tentative_config_block_idx == released {
            self.tentative_config_block_idx = NONE_REF;
            self.chain_config.discard_tentative();
        }
        self.blocks.set_parent_ref(new_tail, NONE_REF);
        self.snake_chain_tail_idx = new_tail;
        self.reclaim_stale_fragments(s_tail);
        // The FR21 subtraction of event (iii) is the head-extension caller's
        // (`promote_head_extension`): this step also serves the Ready-entry
        // trim, which runs before the window value is seeded.
        true
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
        let Some((min_emit, per_head_retry)) = self.parent_recovery_intervals() else {
            return (TickOutcome::Idle, NextCall::Idle);
        };

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
        let Some((min_emit, per_head_retry)) = self.parent_recovery_intervals() else {
            return NextCall::Idle;
        };
        match self.chain_heads.earliest_recovery_deadline(per_head_retry) {
            Some(head_ready) => {
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
    /// not `Ready` (Collecting / Processing — no active chain), which leaves the
    /// FR60 window inactive. In `Ready` it is the sequences of the
    /// `snake_chain_tail_idx` and `active_chain_head_idx` blocks (Story 9.1),
    /// with `S_tail ≤ S_head` because the tail is the head's ancestor. The intake
    /// caller only needs "window or not", so it maps this with `.ok()`.
    ///
    /// A Ready node always holds both blocks: every path into Ready establishes
    /// the tail, and every path that clears either index also leaves Ready. Were
    /// one missing anyway, the window stands down (`NotReady`) — FR60's
    /// fail-open, the same as for a missing `W` — rather than measuring against
    /// a freed slot.
    fn active_snake_chain_window(&self) -> Result<(u32, u32), SnakeChainWindowError> {
        if !self.is_ready() {
            return Err(SnakeChainWindowError::NotReady);
        }
        let window = (
            self.blocks.get(self.snake_chain_tail_idx),
            self.blocks.get(self.active_chain_head_idx),
        );
        debug_assert!(
            window.0.is_some() && window.1.is_some(),
            "a Ready node holds its tail and head blocks"
        );
        match window {
            (Some(tail), Some(head)) => Ok((tail.sequence(), head.sequence())),
            _ => Err(SnakeChainWindowError::NotReady),
        }
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
    fn held_chain_config_content(&self) -> Option<&[u8]> {
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
    fn scan_candidate_chain_config(&self, tip: u32, probe: u32) -> (u32, bool) {
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

    /// Reads the retained block at `idx` into the caller's `buf` and views it
    /// at the length cached at admission (`BlockEntry::len`): durable slots
    /// read back padded, and the FR6 byte-exact checks need the bytes that
    /// were signed. Without a cached length (no entry, or 0) it views the whole
    /// buffer, as the padded read always did. The caller's buffer is the only
    /// copy (stack budget, DEC-136). `None` on a failed read or bytes that no
    /// longer parse.
    fn view_retained<'b>(
        &self,
        idx: u32,
        buf: &'b mut [u8; MAX_BLOCK_SIZE],
    ) -> Option<BlockView<'b>> {
        self.storage.read_block_into(idx, buf).ok()?;
        let n = match self.blocks.get(idx).map(|entry| entry.len() as usize) {
            Some(len) if len > 0 && len <= MAX_BLOCK_SIZE => len,
            _ => MAX_BLOCK_SIZE,
        };
        BlockView::from_bytes(&buf[..n]).ok()
    }

    /// Deletes `target` and its whole descendant subtree, with the FR19
    /// `chain_heads` follow-up — the **deletion half** of the FR5 policy, and
    /// nothing else.
    ///
    /// Deliberately *not* [`Self::recover_from_failed_pass`]: the two FR8 callers
    /// (the AC5 lock-time mismatch cleanup and the AC6 adopt-retry) are removing
    /// blocks from a tree whose derived projection is **correct and wanted**. The
    /// working-set rollback, the active-chain-marking reset and the
    /// Processing→Collecting reversion that the recovery performs would all be
    /// wrong here: the node is going Ready, not recovering. Keeping this as its
    /// own small function rather than a flag on the recovery is the point — a
    /// parameterized recovery would invite a future caller to take the rollback
    /// where none is wanted.
    ///
    /// Transitive by necessity, not by choice: a block is chained to its parent
    /// by `previous_hash`, so a descendant of a removed block can no longer be
    /// verified against anything and is unusable regardless.
    ///
    /// Slot release **is** durable deletion (`StorageTrait` has no delete, and
    /// deliberately so — `blocks[i] ⟷ storage_index = i` is 1:1, so freeing the
    /// in-memory slot frees the durable one and the bytes are overwritten by the
    /// next `save_block(i, …)`; ratified in Story 4.4).
    ///
    /// Returns the number of blocks deleted.
    fn delete_subtree_with_followup(&mut self, target: u32) -> usize {
        // Collect before deleting, so every ancestry walk runs against the
        // pre-deletion tree. Stack: `[u32; MAX_BLOCKS]` is 2.4 KB at the default
        // `MAX_BLOCKS = 600`. Every caller runs outside `run_processing_pass` —
        // the `receive_block` seam, the post-promotion FR8 cleanups, and the
        // snake-chain release step (reached from the promotion, from genesis and,
        // from Story 6.0, from the head extension) — so its equally-sized
        // `marked` buffer is already released, the same budget the FR5 recovery
        // reasons about, and never live at the same time as it.
        let mut delete_set = [NONE_REF; MAX_BLOCKS];
        let deleted_count = self.blocks.mark_subtree(target, &mut delete_set);
        if deleted_count == 0 {
            return 0;
        }
        // The target's parent survives (the delete-set is closed under the child
        // relation) and becomes a childless tip, which event (iv) re-tracks.
        let parent_of_target = self
            .blocks
            .get(target)
            .map_or(NONE_REF, |entry| entry.parent_ref());
        for idx in delete_set.iter().take(deleted_count) {
            self.blocks.delete(*idx);
        }
        // Two pieces of module state name block indices, and a freed slot is
        // reused by the next admission. Both clears belong here rather than at the
        // call sites: every path that deletes owes them, and a helper that leaves
        // them to its callers is a helper that will eventually be called by one
        // that forgets.
        let deleted = &delete_set[..deleted_count];
        if deleted.contains(&self.active_chain_head_idx) {
            // A dangling head would name a freed slot that the next `save_block`
            // fills with an unrelated block. The tail is the head's ancestor, so
            // it went with it.
            self.active_chain_head_idx = NONE_REF;
            self.snake_chain_tail_idx = NONE_REF;
            self.active_branch_value = 0;
            self.complete_from_sequence = 0;
        }
        if self.tentative_config_block_idx != NONE_REF
            && deleted.contains(&self.tentative_config_block_idx)
        {
            // FR8/AC8, in the general case: the tentative's justification is the
            // block that carried it. `discard_tentative` is a no-op once durable,
            // so the irrevocable lock cannot be undone through here.
            self.tentative_config_block_idx = NONE_REF;
            self.chain_config.discard_tentative();
        }
        self.chain_heads
            .on_blocks_deleted(&mut self.blocks, deleted, parent_of_target);
        deleted_count
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
    fn candidate_block_exceeding_size_limit(&self, tip: u32) -> Option<u32> {
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
    fn reevaluate_retained_blocks_against_lock(&mut self) {
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
    fn commit_durable_chain_config(&mut self, first_config_idx: u32) -> Result<(), ()> {
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
    fn delete_mismatching_chain_config_blocks(&mut self) {
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
    fn candidate_chain_config_readable_match(&self, idx: u32) -> ConfigPreload {
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
    fn adopt_candidate_chain_config(&mut self, tip: u32, first_config_idx: u32) -> Result<(), ()> {
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
            .map(|config| u32::from(config.active_chain_length()))
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
    fn held_max_utxo_outputs(&self) -> u16 {
        self.chain_config
            .active_configuration()
            .map_or(UTXO_BITFIELD_WIDTH, |config| config.max_utxo_outputs())
    }

    /// The block UTXO-output cap that Tier 1 may **enforce** against an arriving
    /// block: the chain's value once the configuration is durably locked, and
    /// the available-UTXO bitfield width before that (FR9; the
    /// [`Self::enforceable_block_size_limit`] pattern, DEC-132).
    fn enforceable_max_utxo_outputs(&self) -> u16 {
        self.chain_config
            .durable_content()
            .and_then(|_| self.chain_config.active_configuration())
            .map_or(UTXO_BITFIELD_WIDTH, |config| config.max_utxo_outputs())
    }

    /// The block-size limit **the chain declares**, once any configuration is
    /// loaded, and the framing bound `MAX_BLOCK_SIZE` until then.
    ///
    /// The fallback is not a policy choice standing in for a chain value — it is
    /// the structural ceiling every node shares (a larger block cannot be framed
    /// at all), so no two builds can diverge on it, which is what specification
    /// §6 forbids of per-build fallbacks. (Ruled by the Project Lead, 2026-09-19.)
    ///
    /// Read this where the configuration in force is known to be the one the work
    /// commits to — the FR54 genesis path, which is about to lock the very
    /// configuration it is measuring against. Anything that can **reject or
    /// delete** a block must read [`Self::enforceable_block_size_limit`] instead.
    fn block_size_limit(&self) -> u16 {
        self.chain_config
            .active_configuration()
            .map_or(MAX_BLOCK_SIZE as u16, |config| config.block_size_limit())
    }

    /// The block-size limit that may be **enforced** against an arriving or
    /// retained block: the chain's value once the configuration is durably
    /// locked, and the structural framing ceiling before that.
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
    fn enforceable_block_size_limit(&self) -> u16 {
        self.chain_config
            .durable_content()
            .and_then(|_| self.chain_config.active_configuration())
            .map_or(MAX_BLOCK_SIZE as u16, |config| config.block_size_limit())
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
    fn parent_recovery_intervals(&self) -> Option<(u64, u64)> {
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
    /// **Until Story 7.2 maintains the projections on forward extension (FR35),
    /// this is a per-node snapshot**: a Ready node's `node_info` is the state at
    /// its Ready transition, and node #0, made Ready by genesis without a pass,
    /// stays at the genesis count. Harmless for the one bound consumer, the
    /// parent-recovery cadence, which is not consensus-relevant; Story 7.2 owns
    /// keeping the watermark current before a consensus-relevant consumer binds.
    fn chain_info_at_head(&self) -> ChainInfoAtHead {
        ChainInfoAtHead {
            registered_node_count: self
                .is_ready()
                .then(|| u64::from(self.node_info.max_known_node_id()) + 1),
        }
    }
}

/// The blockchain's chain-info source: values read once, at bind time, from the
/// FR34 projections. A thin read: no field, no cache, no maintenance of its own.
struct ChainInfoAtHead {
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

#[cfg(test)]
mod tests {
    use super::*;
    use moonblokz_chain_types::{ChainConfigPayloadBuilder, MAX_BLOCK_SIZE};
    use moonblokz_configuration::{ChainConfiguration, NoopConfigChangeSink, parameter};
    use moonblokz_crypto::{
        AggregatedSignature, Crypto, CryptoError, MultiSignature, PRIVATE_KEY_SIZE, PublicKey,
        Signature, SignatureTrait,
    };
    use moonblokz_storage::{
        ControlPlaneData, INIT_PARAMS_SIZE, StorageError, backend_memory::MemoryBackend,
    };

    fn any_nonzero(bytes: &[u8]) -> bool {
        bytes.iter().any(|value| *value != 0)
    }

    /// The configuration seam under test: the real module with the no-op change
    /// sink. There is no stub any more — the tests exercise the same crate the
    /// firmware does.
    type TestConfig = ChainConfiguration<NoopConfigChangeSink>;

    /// The window the suite's configurations declare: `TestChain`'s whole
    /// active-chain capacity.
    ///
    /// A content that leaves `active_chain_length` out resolves it to the
    /// default 500, which these harnesses — built small so a segment fits test
    /// storage — cannot hold, so acceptance refuses it (FR8). Declaring the
    /// capacity keeps every other parameter at its code-baked default.
    const TEST_W: u16 = 16;

    /// The base override set as a **content region**: one literal entry
    /// declaring `active_chain_length = TEST_W`. Every other parameter resolves
    /// to its code-baked default, and those defaults are exactly the constants
    /// the retired `FixedChainConfig` returned — which is why the suite's
    /// expected values are unchanged.
    const BASE_CONFIG_CONTENT: [u8; 6] = [
        1,
        0,
        parameter::ACTIVE_CHAIN_LENGTH,
        2,
        TEST_W.to_le_bytes()[0],
        TEST_W.to_le_bytes()[1],
    ];

    /// A second content region, valid and **distinct in bytes** but resolving
    /// identically: the base entry plus a literal declaring `vote_interest`'s
    /// own default. Used where a test needs two different chain-config contents.
    const OTHER_CONFIG_CONTENT: [u8; 9] = [
        2,
        0,
        parameter::ACTIVE_CHAIN_LENGTH,
        2,
        TEST_W.to_le_bytes()[0],
        TEST_W.to_le_bytes()[1],
        parameter::VOTE_INTEREST,
        1,
        5,
    ];

    /// An override set declaring only the window `w` — the base every fixture
    /// builder starts from.
    fn window_config_builder(w: u16) -> ChainConfigPayloadBuilder {
        let mut builder = ChainConfigPayloadBuilder::new();
        builder
            .add_literal(parameter::ACTIVE_CHAIN_LENGTH, &w.to_le_bytes())
            .ok()
            .expect("a two-byte literal is well-formed");
        builder
    }

    /// Storage whose control plane is fine and whose block writes are not.
    ///
    /// `MemoryBackend` cannot express this: a backend large enough to
    /// initialize is large enough to hold blocks. The pair matters because
    /// genesis has two distinct storage failure modes and they refuse at
    /// different points — one before any write, one after the first.
    /// Storage whose control plane is fine and every block slot is corrupt.
    /// `MemoryBackend` cannot express this — it has no per-slot integrity check
    /// and so can never return `IntegrityFailure`, which only the rp2040 backend
    /// produces. Without a stub, the skip arm that matters on real hardware is
    /// unexercised.
    struct CorruptSlotsStorage;

    impl StorageTrait for CorruptSlotsStorage {
        fn init(
            &mut self,
            _private_key: [u8; PRIVATE_KEY_SIZE],
            _own_node_id: u32,
            _init_params: [u8; INIT_PARAMS_SIZE],
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn save_block(&mut self, _idx: u32, _block: &Block) -> Result<(), StorageError> {
            Ok(())
        }

        fn read_block_into(
            &self,
            idx: u32,
            _out: &mut [u8; MAX_BLOCK_SIZE],
        ) -> Result<(), StorageError> {
            // Two slots are occupied-but-corrupt; the rest are genuinely empty.
            if idx < 2 {
                Err(StorageError::IntegrityFailure)
            } else {
                Err(StorageError::BlockAbsent)
            }
        }

        fn capacity(&self) -> u32 {
            8
        }

        fn set_chain_configuration(&mut self, _block: &Block) -> Result<(), StorageError> {
            Ok(())
        }

        fn load_control_data(&mut self) -> Result<ControlPlaneData, StorageError> {
            Ok(ControlPlaneData {
                private_key: [1u8; PRIVATE_KEY_SIZE],
                own_node_id: 0,
                init_params: [0u8; INIT_PARAMS_SIZE],
                chain_configuration: None,
            })
        }
    }

    struct BlockWriteFailsStorage;

    impl StorageTrait for BlockWriteFailsStorage {
        fn init(
            &mut self,
            _private_key: [u8; PRIVATE_KEY_SIZE],
            _own_node_id: u32,
            _init_params: [u8; INIT_PARAMS_SIZE],
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn save_block(&mut self, _storage_index: u32, _block: &Block) -> Result<(), StorageError> {
            Err(StorageError::InvalidIndex)
        }

        fn read_block_into(
            &self,
            _storage_index: u32,
            _out: &mut [u8; MAX_BLOCK_SIZE],
        ) -> Result<(), StorageError> {
            Err(StorageError::BlockAbsent)
        }

        fn capacity(&self) -> u32 {
            0
        }

        fn set_chain_configuration(&mut self, _block: &Block) -> Result<(), StorageError> {
            Ok(())
        }

        fn load_control_data(&mut self) -> Result<ControlPlaneData, StorageError> {
            Ok(ControlPlaneData {
                private_key: [1u8; PRIVATE_KEY_SIZE],
                own_node_id: 0,
                init_params: [0u8; INIT_PARAMS_SIZE],
                chain_configuration: None,
            })
        }
    }

    /// A storage backend in the state a booted node's is: its control plane is
    /// initialized, which the durable `set_chain_configuration` seam requires.
    fn initialized_storage(
        private_key: [u8; PRIVATE_KEY_SIZE],
    ) -> MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }> {
        let mut storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
        storage
            .init(private_key, 0, [0u8; INIT_PARAMS_SIZE])
            .ok()
            .expect("the test backend initializes");
        storage
    }

    /// A configuration module holding no configuration — the state every node
    /// starts in, and the one `process_genesis` requires (FR54's lock is
    /// set-once).
    /// `limits` is the receiving chain's own `BUILD_LIMITS`, never a default:
    /// the module's §6 checks measure a declared value against exactly what it
    /// was handed, so a fixture that lends one chain's capacities to another
    /// would test the bound against a capacity that build does not have.
    fn empty_chain_config(limits: BuildLimits) -> TestConfig {
        ChainConfiguration::new(NoopConfigChangeSink, limits)
    }

    /// A configuration module already durably locked on an override set that
    /// declares the window at `limits`' full capacity, standing in for "genesis
    /// has run" wherever a test needs a configured node without bootstrapping
    /// one.
    fn locked_chain_config(crypto: &Crypto, limits: BuildLimits) -> TestConfig {
        let mut config = empty_chain_config(limits);
        let mut builder = window_config_builder(limits.snake_chain_length_max);
        config
            .load_durable(builder.build_signed(crypto))
            .ok()
            .expect("a window at the build's capacity is accepted content");
        config
    }

    /// The crypto seam for the construction tests — a stand-in that performs
    /// no cryptography.
    ///
    /// `init` and `new` only *move* the backend into the node; neither ever
    /// calls it. The Miri gate (`cargo +nightly miri test init_`) therefore
    /// has no reason to pay for a real signature backend, whose `Crypto::new`
    /// alone runs an EC scalar multiplication — interpreted, that dominates
    /// the whole run. Every method past construction is `unimplemented!()`:
    /// reaching one would mean a construction test had begun exercising
    /// crypto, which is exactly what this type exists to prevent. Every other
    /// test keeps the real backend, so the trait seam is still exercised
    /// end-to-end.
    struct NoCrypto;

    impl CryptoTrait for NoCrypto {
        fn new(_private_key_bytes: [u8; PRIVATE_KEY_SIZE]) -> Result<Self, CryptoError> {
            Ok(Self)
        }

        fn public_key(&self) -> &PublicKey {
            unimplemented!("construction never reads the public key")
        }

        fn sign(&self, _message: &[u8]) -> Signature {
            unimplemented!("construction never signs")
        }

        fn multi_sign(&self, _message: &[u8]) -> MultiSignature {
            unimplemented!("construction never signs")
        }

        fn verify_multi_signature(
            &self,
            _message: &[u8],
            _multi_signature: &MultiSignature,
            _public_key: &PublicKey,
        ) -> bool {
            unimplemented!("construction never verifies")
        }

        fn verify_signature(
            &self,
            _message: &[u8],
            _signature: &Signature,
            _public_key: &PublicKey,
        ) -> bool {
            unimplemented!("construction never verifies")
        }

        fn aggregate_signatures(
            &self,
            _signatures: &[&MultiSignature],
            _message: &[u8],
        ) -> Result<AggregatedSignature, CryptoError> {
            unimplemented!("construction never aggregates")
        }

        fn verify_aggregated_signature(
            &self,
            _message: &[u8],
            _aggregated_signature: &AggregatedSignature,
            _public_keys: &[&PublicKey],
        ) -> bool {
            unimplemented!("construction never verifies")
        }
    }

    /// Helper: the same triple as [`test_backends`] with [`NoCrypto`] in place
    /// of the signature backend, for the two construction tests.
    fn construction_backends() -> (
        NoCrypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        TestConfig,
    ) {
        (
            NoCrypto,
            MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new(),
            empty_chain_config(TestChain::BUILD_LIMITS),
        )
    }

    /// Helper: construct a (Crypto, MemoryBackend, TestConfig) triple for the
    /// walking-skeleton tests. Uses real backends so the trait-bound seam is
    /// exercised end-to-end; the configuration module is **empty**, which is
    /// what the genesis path requires of a node about to bootstrap.
    fn test_backends() -> (
        Crypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        TestConfig,
    ) {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let crypto = Crypto::new(private_key)
            .ok()
            .expect("test private key should be accepted by the backend");
        let storage = initialized_storage(private_key);
        let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        (crypto, storage, chain_config)
    }

    /// A node that holds **no** configuration at all — the joining node's real
    /// starting state, before any chain-config block has reached it.
    ///
    /// Needed by the admission tests: on a node that already holds a
    /// configuration, an admitted block can complete an FR2 candidate and run the
    /// whole Epic-5 lifecycle inside `receive_block`, which is exactly what an
    /// admission test must not have happening underneath it.
    fn new_unconfigured_test_chain() -> TestChain {
        let (crypto, storage, chain_config) = test_backends();
        new_chain(crypto, storage, chain_config, 5, 0)
    }

    /// Helper: build an empty node via `init` ready for a
    /// `process_genesis` call. Genesis is node-zero-only, so node zero's own
    /// key (derived from `crypto`) is stored as the trust anchor.
    fn new_chain(
        crypto: Crypto,
        storage: MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        chain_config: TestConfig,
        local_node_id: u32,
        prng_seed: u64,
    ) -> Blockchain<
        Crypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        TestConfig,
        16,
        16,
        16,
        4,
        16,
    > {
        let node_zero = *crypto.public_key().serialize();
        let mut bc_slot = core::mem::MaybeUninit::uninit();
        Blockchain::init(
            &mut bc_slot,
            crypto,
            storage,
            chain_config,
            local_node_id,
            node_zero,
            prng_seed,
        );
        // SAFETY: `init` returned, so every field of `bc_slot` is initialized.
        unsafe { bc_slot.assume_init() }
    }

    /// `init`'s field writes (`blocks` / `chain_heads` filled
    /// element-by-element through the nested tables' own `init`, the
    /// scalars written one by one) must land every field in its correct
    /// default state — a wrong field order, a skipped field, or an
    /// off-by-one inside the `unsafe` block would silently corrupt memory
    /// rather than panic, so this is verified directly rather than trusted
    /// by construction.
    ///
    /// The destructuring is deliberately exhaustive (no `..`): adding a field
    /// to `Blockchain` makes this test fail to *compile* until the new field
    /// is both initialized in `init` and asserted here — the one obligation
    /// the safe signature cannot enforce, pinned at compile time instead of
    /// by a reviewer's eye. Never compare two nodes byte-for-byte for this
    /// purpose: padding bytes are uninitialized, and Miri rejects reading them.
    #[test]
    fn init_sets_expected_defaults() {
        let (crypto, storage, chain_config) = construction_backends();
        let mut bc_slot =
            core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 16, 4, 16>>::uninit();
        let bc = Blockchain::<_, _, _, 16, 16, 16, 4, 16>::init(
            &mut bc_slot,
            crypto,
            storage,
            chain_config,
            7,
            [3u8; PUBLIC_KEY_SIZE],
            0xDEAD_BEEF,
        );

        let Blockchain {
            crypto: _,       // moved in as given; opaque backend
            storage: _,      // moved in as given; opaque backend
            chain_config: _, // moved in as given
            local_node_id,
            node_zero_public_key,
            prng: _, // seeded from `prng_seed`; its state is opaque by design
            lifecycle_phase,
            restart_refused,
            blocks,
            chain_heads,
            node_info,
            vote_engine,
            last_parent_request_emit_timestamp,
            active_chain_head_idx,
            tentative_config_block_idx,
            snake_chain_tail_idx,
            active_branch_value,
            complete_from_sequence,
        } = &*bc;

        assert_eq!(*local_node_id, 7);
        assert!(*lifecycle_phase == LifecyclePhase::Collecting);
        assert!(
            !*restart_refused,
            "a freshly constructed node has refused nothing"
        );
        assert_eq!(*node_zero_public_key, [3u8; PUBLIC_KEY_SIZE]);
        assert_eq!(blocks.len(), 0);
        // Story 4.4: the `chain_heads` table + scheduler state must init to
        // their empty/sentinel values too (`ChainHeadsTable::init` writes
        // every entry element-by-element).
        assert_eq!(chain_heads.count(), 0);
        assert_eq!(node_info.max_known_node_id(), 0);
        assert!(!node_info.is_seeded(0));
        // All-zero vote order is headed by node 0 (bootstrap rule).
        assert_eq!(vote_engine.top_creator(), Some(0));
        assert_eq!(*last_parent_request_emit_timestamp, 0);
        assert_eq!(*active_chain_head_idx, NONE_REF);
        assert_eq!(*tentative_config_block_idx, NONE_REF);
        assert_eq!(*snake_chain_tail_idx, NONE_REF);
        assert_eq!(*active_branch_value, 0);
        assert_eq!(*complete_from_sequence, 0);
        assert_eq!(bc.local_node_id(), 7);
    }

    /// `init` must produce exactly what the by-value specification `new()`
    /// produces. Both sides are destructured exhaustively (no `..`): adding a
    /// field to `Blockchain` is a compile error in `new()`'s literal *and*
    /// here until it is initialized and compared. The opaque backends
    /// (`crypto`, `storage`, `chain_config`) are moved in as given on both
    /// sides and carry no `PartialEq`; every field this crate writes is
    /// compared. Never compare the two byte-for-byte: padding is
    /// uninitialized, and Miri rejects reading it.
    #[test]
    fn init_is_equivalent_to_new() {
        let (crypto, storage, chain_config) = construction_backends();
        let mut slot = core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 16, 4, 16>>::uninit();
        let built = Blockchain::<_, _, _, 16, 16, 16, 4, 16>::init(
            &mut slot,
            crypto,
            storage,
            chain_config,
            7,
            [3u8; PUBLIC_KEY_SIZE],
            0xDEAD_BEEF,
        );
        let (crypto, storage, chain_config) = construction_backends();
        let spec = Blockchain::<_, _, _, 16, 16, 16, 4, 16>::new(
            crypto,
            storage,
            chain_config,
            7,
            [3u8; PUBLIC_KEY_SIZE],
            0xDEAD_BEEF,
        );

        let Blockchain {
            crypto: _,
            storage: _,
            chain_config: _,
            local_node_id,
            node_zero_public_key,
            prng,
            lifecycle_phase,
            restart_refused,
            blocks,
            chain_heads,
            node_info,
            vote_engine,
            last_parent_request_emit_timestamp,
            active_chain_head_idx,
            tentative_config_block_idx,
            snake_chain_tail_idx,
            active_branch_value,
            complete_from_sequence,
        } = &*built;
        let Blockchain {
            crypto: _,
            storage: _,
            chain_config: _,
            local_node_id: spec_local_node_id,
            node_zero_public_key: spec_node_zero_public_key,
            prng: spec_prng,
            lifecycle_phase: spec_lifecycle_phase,
            restart_refused: spec_restart_refused,
            blocks: spec_blocks,
            chain_heads: spec_chain_heads,
            node_info: spec_node_info,
            vote_engine: spec_vote_engine,
            last_parent_request_emit_timestamp: spec_last_parent_request_emit_timestamp,
            active_chain_head_idx: spec_active_chain_head_idx,
            tentative_config_block_idx: spec_tentative_config_block_idx,
            snake_chain_tail_idx: spec_snake_chain_tail_idx,
            active_branch_value: spec_active_branch_value,
            complete_from_sequence: spec_complete_from_sequence,
        } = &spec;

        assert_eq!(local_node_id, spec_local_node_id);
        assert_eq!(node_zero_public_key, spec_node_zero_public_key);
        assert!(prng == spec_prng);
        assert!(lifecycle_phase == spec_lifecycle_phase);
        assert!(restart_refused == spec_restart_refused);
        assert!(blocks == spec_blocks);
        assert!(chain_heads == spec_chain_heads);
        assert!(node_info == spec_node_info);
        assert!(vote_engine == spec_vote_engine);
        assert_eq!(
            last_parent_request_emit_timestamp,
            spec_last_parent_request_emit_timestamp
        );
        assert_eq!(active_chain_head_idx, spec_active_chain_head_idx);
        assert_eq!(tentative_config_block_idx, spec_tentative_config_block_idx);
        assert_eq!(snake_chain_tail_idx, spec_snake_chain_tail_idx);
        assert_eq!(active_branch_value, spec_active_branch_value);
        assert_eq!(complete_from_sequence, spec_complete_from_sequence);
    }

    /// AC2 — the neutrality proof: with the base override set (the window alone)
    /// the configuration module resolves every parameter the blockchain reads to
    /// the exact constant the retired `FixedChainConfig` returned. This is what
    /// lets the rest of the suite keep its expected values unchanged, and it
    /// replaces the stub's own `fixed_returns_expected_constants`.
    #[test]
    fn code_baked_defaults_reproduce_the_retired_stub() {
        let (crypto, _, _) = test_backends();
        let chain_config = locked_chain_config(&crypto, TestChain::BUILD_LIMITS);
        let config = chain_config
            .active_configuration()
            .expect("a locked module answers with a handle");

        assert_eq!(config.inter_block_interval_ms(), 60_000);
        assert_eq!(config.grace_period_window_ms(), 30_000);
        assert_eq!(config.block_size_limit(), 2016);
        assert_eq!(config.max_utxo_outputs(), 255);
        assert_eq!(config.max_aggregated_signatures(), 50);
        assert_eq!(config.vote_scale().get(), 1000);
        assert_eq!(config.vote_interest(), 5);
        assert_eq!(config.parent_recovery_per_head_retry_interval_ms(), 120_000);
        assert_eq!(config.parent_recovery_min_emit_interval_ms(), 10_000);
        // The one value the fixtures declare rather than default (Story 5.11).
        assert_eq!(config.active_chain_length(), TEST_W);
        assert!(chain_config.is_durable_locked());
    }

    /// AC3 — before any configuration is loaded the block-size limit falls back
    /// to the framing bound, and the parent-recovery scheduler stands down.
    /// (Project Lead ruling, 2026-09-19.)
    #[test]
    fn unconfigured_node_falls_back_to_the_framing_bound_and_idles() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 5, 0);

        assert_eq!(bc.block_size_limit(), MAX_BLOCK_SIZE as u16);
        assert!(bc.parent_recovery_intervals().is_none());
        let (outcome, next) = bc.on_tick(1_000_000);
        assert!(matches!(outcome, TickOutcome::Idle));
        assert!(matches!(next, NextCall::Idle));
    }

    /// Story 5.12 — a parameter program reading the registered-node count:
    /// `parent_recovery_min_emit_interval_ms = GETCHAININFO 1, 0; PUSH_U16 1000; MUL`.
    fn node_count_cadence_builder() -> ChainConfigPayloadBuilder {
        let mut builder = window_config_builder(TEST_W);
        builder
            .add_bytecode(
                parameter::PARENT_RECOVERY_MIN_EMIT_INTERVAL_MS,
                &[
                    0x71,
                    chain_info::REGISTERED_NODE_COUNT,
                    0,
                    0x11,
                    0xE8,
                    0x03,
                    0x42,
                    0x01,
                ],
            )
            .ok()
            .expect("the program frames");
        builder
    }

    /// Story 5.12, AC4/AC5 — in Ready the scheduler's programs read the
    /// registered-node count at the head: after genesis one node is registered.
    #[test]
    fn chain_info_reaches_the_scheduler_in_ready() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        let builder = node_count_cadence_builder();
        bc.process_genesis(1_000_000_000, builder.content())
            .ok()
            .expect("genesis succeeds");
        assert!(bc.is_ready());
        assert_eq!(
            bc.chain_info_at_head()
                .read(chain_info::REGISTERED_NODE_COUNT, &[]),
            Some(1)
        );
        assert_eq!(
            bc.parent_recovery_intervals().map(|(min_emit, _)| min_emit),
            Some(1_000),
            "one registered node, one second"
        );
    }

    /// Story 5.12, AC5 — the value is the derived watermark plus one, not a
    /// constant: a pass that registers node 2 on top of a balance block naming
    /// nodes up to 1 leaves three registered nodes, served once Ready.
    #[test]
    fn chain_info_reads_the_derived_watermark() {
        let mut bc = new_test_chain();
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(100, cfg_hash, &[(1, 100, 0, 0xB1)], 1);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        let reg = registration_block(101, anchor.view().hash(), 1, 2, 0xC5);
        let ri = bc
            .tier1_admit(&reg.view(), &reg.view().hash(), 0)
            .expect("registration admitted");
        bc.run_processing_pass(ri).expect("pass succeeds");
        assert_eq!(
            bc.chain_info_at_head()
                .read(chain_info::REGISTERED_NODE_COUNT, &[]),
            None,
            "not Ready yet"
        );

        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.set_lifecycle_phase(LifecyclePhase::Ready);
        let info = bc.chain_info_at_head();
        assert_eq!(info.read(chain_info::REGISTERED_NODE_COUNT, &[]), Some(3));
        assert_eq!(
            info.read(chain_info::REGISTERED_NODE_COUNT, &[0]),
            None,
            "identifier 1 takes no arguments"
        );
    }

    /// Story 5.12, AC4 — while Collecting there is no active chain: the read is
    /// declined and the program falls back to the code-baked default.
    #[test]
    fn chain_info_is_declined_while_collecting() {
        let (crypto, storage, _) = test_backends();
        let mut chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        chain_config
            .load_durable(node_count_cadence_builder().build_signed(&crypto))
            .ok()
            .expect("the content is accepted");
        let bc = new_chain(crypto, storage, chain_config, 5, 0);
        assert!(!bc.is_ready());
        assert_eq!(
            bc.chain_info_at_head()
                .read(chain_info::REGISTERED_NODE_COUNT, &[]),
            None
        );
        assert_eq!(
            bc.parent_recovery_intervals().map(|(min_emit, _)| min_emit),
            Some(10_000),
            "declined, so the code-baked default"
        );
    }

    /// AC1, AC4, AC5 — successful genesis bootstrap on `local_node_id == 0`
    /// yields **both** Block #0 and Block #1 in a single `process_genesis`
    /// call (no `NextCall`), with no embassy deps anywhere in the harness.
    #[test]
    fn walking_skeleton_genesis_success() {
        let (crypto, storage, chain_config) = test_backends();
        let expected_node_zero_public_key = *crypto.public_key().serialize();
        let initial_chain_config_bytes = OTHER_CONFIG_CONTENT;

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
        let block_one_config = block_one
            .view()
            .chain_config()
            .expect("Block #1 must frame a chain-config envelope");
        assert_eq!(
            block_one_config.content(),
            &initial_chain_config_bytes[..],
            "Block #1 carries the initial chain-config content verbatim"
        );
        assert!(
            bc.crypto.verify_signature(
                &initial_chain_config_bytes[..],
                &Signature::new(block_one_config.content_signature())
                    .ok()
                    .expect("the trailer is a well-formed signature"),
                bc.crypto.public_key(),
            ),
            "FR54: node #0 signs Block #1's content region"
        );
        assert!(
            any_nonzero(block_one.signature()),
            "Block #1 must be signed"
        );

        assert_eq!(
            bc.chain_config.durable_content(),
            Some(&initial_chain_config_bytes[..]),
            "FR54: genesis leaves the configuration durably locked on its content"
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
        bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT)
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
        // Nothing was loaded on the refusal path.
        assert!(!bc.chain_config.is_durable_locked());
    }

    /// Genesis content whose signature trailer would push the payload past
    /// `MAX_PAYLOAD_SIZE` is refused before anything is written.
    #[test]
    fn walking_skeleton_rejects_oversized_initial_chain_config() {
        let (crypto, storage, chain_config) = test_backends();
        let oversized = [0u8; MAX_PAYLOAD_SIZE - SIGNATURE_SIZE + 1];
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

        let outcome = bc.process_genesis(1_000_000_000, &oversized);

        match outcome {
            Err(GenesisRejectReason::InitialChainConfigTooLarge) => {}
            Err(_) => panic!("expected InitialChainConfigTooLarge refusal"),
            Ok(_) => panic!("oversized initial chain-config bytes must be refused"),
        }
    }

    /// A node whose configuration is already durably locked has been
    /// bootstrapped, so genesis is refused before it can overwrite the lock
    /// (`StorageNotEmpty`). FR54's lock is set-once.
    #[test]
    fn walking_skeleton_refuses_genesis_when_chain_config_already_locked() {
        let (crypto, storage, _) = test_backends();
        let chain_config = locked_chain_config(&crypto, TestChain::BUILD_LIMITS);
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

        let outcome = bc.process_genesis(1_000_000_000, &OTHER_CONFIG_CONTENT);

        match outcome {
            Err(GenesisRejectReason::StorageNotEmpty) => {}
            Err(_) => panic!("expected StorageNotEmpty refusal"),
            Ok(_) => panic!("genesis must not overwrite a durably locked configuration"),
        }
        // The locked content is untouched.
        assert_eq!(
            bc.chain_config.durable_content(),
            Some(&BASE_CONFIG_CONTENT[..])
        );
    }

    /// Genesis is a one-shot bootstrap: a second `process_genesis` on the same
    /// node refuses with `StorageNotEmpty` (the chain now carries genesis state).
    #[test]
    fn walking_skeleton_refuses_second_genesis() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

        let first = bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT);
        assert!(first.is_ok(), "first genesis must succeed");

        let second = bc.process_genesis(1_000_000_000, &OTHER_CONFIG_CONTENT);
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
        let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();

        let mut bc_slot =
            core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 16, 4, 16>>::uninit();
        let bc = Blockchain::<_, _, _, 16, 16, 16, 4, 16>::init(
            &mut bc_slot,
            crypto,
            BlockWriteFailsStorage,
            chain_config,
            0,
            node_zero,
            0,
        );

        let outcome = bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT);

        match outcome {
            Err(GenesisRejectReason::StorageSaveFailed) => {}
            Err(_) => panic!("expected StorageSaveFailed refusal"),
            Ok(_) => panic!("genesis must not succeed when a genesis block cannot be persisted"),
        }
        // FR54's lock is set-once, so a refusal that engaged it would refuse
        // every retry for the life of the process. The content is held
        // tentatively until the last durable write succeeds, so a storage
        // failure leaves the node able to bootstrap again.
        assert!(
            !bc.chain_config.is_durable_locked(),
            "a genesis that failed on storage must not leave the configuration locked"
        );
        assert!(
            bc.chain_config.tentative_content().is_some(),
            "the accepted content is held tentatively, ready to be replaced by a retry"
        );
    }

    /// The durable configuration seam needs the storage control plane; block
    /// writes do not. Without an up-front check an uninitialized backend would
    /// persist both genesis blocks and then refuse the configuration, and the
    /// non-empty-chain guard would turn away every retry for the life of the
    /// process. The precondition is therefore checked with the other pre-write
    /// guards, and nothing is written.
    #[test]
    fn walking_skeleton_refuses_uninitialized_storage() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let crypto = Crypto::new(private_key)
            .ok()
            .expect("test private key should be accepted by the backend");
        // Never `init`ed: `save_block` would succeed, `set_chain_configuration`
        // would not.
        let storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
        let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let mut bc_slot = core::mem::MaybeUninit::<TestChain>::uninit();
        let bc = TestChain::init(&mut bc_slot, crypto, storage, chain_config, 0, node_zero, 0);

        let outcome = bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT);

        match outcome {
            Err(GenesisRejectReason::StorageNotInitialized) => {}
            Err(_) => panic!("expected StorageNotInitialized refusal"),
            Ok(_) => panic!("genesis must not run without a usable control plane"),
        }
        assert_eq!(bc.blocks.len(), 0, "no block reached the in-memory tree");
        assert!(
            bc.storage.read_block(0).is_err(),
            "no block reached storage either"
        );
        assert!(!bc.chain_config.is_durable_locked());
    }

    /// A configuration whose own `block_size_limit` is smaller than the genesis
    /// blocks it frames would produce a chain no node can accept: every peer
    /// refuses Block #1 at Tier 1, and the founder's own restart refuses it at
    /// FR6. Genesis must not create it.
    #[test]
    fn walking_skeleton_refuses_genesis_blocks_above_the_declared_limit() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        // `block_size_limit` (id 3) declared as 300: legal for the registry
        // (> HEADER_SIZE, <= MAX_BLOCK_SIZE), smaller than Block #0. The window
        // entry is the one every content on this harness carries.
        let w = TEST_W.to_le_bytes();
        let content = [
            2u8,
            0,
            parameter::BLOCK_SIZE_LIMIT,
            2,
            0x2C,
            0x01,
            parameter::ACTIVE_CHAIN_LENGTH,
            2,
            w[0],
            w[1],
        ];

        let outcome = bc.process_genesis(1_000_000_000, &content);

        match outcome {
            Err(GenesisRejectReason::GenesisBlockExceedsBlockSizeLimit) => {}
            Err(_) => panic!("expected GenesisBlockExceedsBlockSizeLimit refusal"),
            Ok(_) => panic!("genesis must not create a chain that rejects its own blocks"),
        }
        assert_eq!(bc.blocks.len(), 0, "nothing was written");
        assert!(!bc.chain_config.is_durable_locked());
    }

    /// AC3 — read-only queries are typed to **not** carry `NextCall`.
    /// This is a compile-time guarantee: `current_phase` returns
    /// `LifecyclePhase` directly (not `CallResult<LifecyclePhase>`), and
    /// `local_node_id` returns `u32` directly.
    #[test]
    fn walking_skeleton_query_carries_no_next_call() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT)
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
        TestConfig,
        16,
        16,
        16,
        4,
        16,
    >;

    fn new_test_chain() -> TestChain {
        let (crypto, storage, _) = test_backends();
        // A node that already holds a chain configuration — the state every
        // post-genesis test assumes, and what the retired stub gave them for
        // free by answering every accessor unconditionally.
        let chain_config = locked_chain_config(&crypto, TestChain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let mut bc_slot = core::mem::MaybeUninit::<TestChain>::uninit();
        TestChain::init(&mut bc_slot, crypto, storage, chain_config, 5, node_zero, 0);
        // SAFETY: `init` returned, so every field of `bc_slot` is initialized.
        unsafe { bc_slot.assume_init() }
    }

    /// As [`node_transfer_block`], but chained to `prev` so the block can sit
    /// above another in a candidate segment.
    fn chained_node_transfer_block(
        seq: u32,
        prev: [u8; 32],
        vote: u32,
        anchor: u32,
        initializer: u32,
    ) -> Block {
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
        // A joining node, holding no configuration yet — the order in which a
        // real node meets a chain, and the only order in which the genesis can be
        // observed on its own: once a configuration is held, the genesis
        // admission completes an FR2 candidate and the whole lifecycle runs
        // inside this same call.
        let mut bc = new_unconfigured_test_chain();
        // Block-zero waives the self-vote / anchor Tier 1 checks.
        let genesis = node_transfer_block(0, 7, 0, 7);
        let (outcome, _) = bc.receive_block(genesis.view(), 100);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(
            bc.current_active_head(),
            Some(0),
            "genesis is the active head"
        );
        // FR8 (Story 5.9): block #1 carries the chain-config, exactly as the FR54
        // bootstrap emits it. It loads the tentative configuration (AC2) and
        // completes a candidate that names one (AC3), so the node goes Ready —
        // which is what makes the `NextCall::Idle` assertion below non-vacuous:
        // the intervals it would need are now available, and there is genuinely
        // no Stored head left to schedule.
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        let (outcome, next) = bc.receive_block(cfg.view(), 100);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert!(
            bc.blocks
                .get(0)
                .is_some_and(|entry| entry.is_on_active_chain()),
            "the genesis still anchors the active chain"
        );
        assert!(
            matches!(next, NextCall::Idle),
            "a fully-connected active chain schedules no parent recovery"
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

    /// AC1/AC3 — a freshly constructed node (join path via `init`) is in
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
        bc.process_genesis(1_000_000_000, &BASE_CONFIG_CONTENT)
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
        // Unconfigured: the guard is an admission property, decided from the
        // block bytes and `active_chain_head_idx` alone. Holding a configuration
        // would let the first genesis complete an FR2 candidate and run the
        // Epic-5 lifecycle inside the same call, which would be testing the
        // lifecycle rather than the guard.
        let mut bc = new_unconfigured_test_chain();

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

    /// Story 5.11 — FR2 measures a window-anchored segment against the
    /// configured `W`, not the allocated capacity: on a build with capacity 16
    /// configured with `W = 4`, four blocks qualify and three do not.
    #[test]
    fn fr2_active_length_is_the_configured_w_not_the_capacity() {
        let (crypto, storage, mut chain_config) = test_backends();
        chain_config
            .load_durable(window_config_builder(W4).build_signed(&crypto))
            .ok()
            .expect("a window below the capacity is accepted");
        let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
        assert_eq!(TestChain::BUILD_LIMITS.snake_chain_length_max, TEST_W);

        // The tail carries the configuration the node is locked on, as the FR8
        // final check requires.
        let tail = w4_config_anchor_block(100, [0xAB; 32]);
        bc.receive_block(tail.view(), 0);
        let mut prev = tail.view().hash();
        for seq in 101..=102 {
            let blk = linked_transfer_block(seq, prev);
            prev = blk.view().hash();
            bc.receive_block(blk.view(), 0);
        }
        assert!(
            bc.evaluate_stopping_condition().is_none(),
            "segment length 3 < W = 4"
        );

        let last = linked_transfer_block(103, prev);
        bc.receive_block(last.view(), 0);
        assert!(
            bc.is_ready(),
            "segment length 4 = W qualifies, on a build that allocated 16"
        );
    }

    /// Story 5.11 / 5.13 — with no configuration held the chain's window is
    /// unknown, and no segment names a configuration, so nothing is a
    /// candidate. A window-anchored segment as long as the build's whole capacity
    /// is not: the capacity is not the window. Once block #1 brings the
    /// configuration, the genesis-anchored segment carrying it qualifies — and
    /// the window-anchored one still does not, because it names none.
    #[test]
    fn fr2_without_a_configuration_no_segment_qualifies() {
        let mut bc = new_unconfigured_w4_chain();
        let mut prev = [0xAB; 32];
        for seq in 100..=103 {
            let blk = linked_transfer_block(seq, prev);
            prev = blk.view().hash();
            bc.tier1_admit(&blk.view(), &blk.view().hash(), 0)
                .expect("a transfer block is admitted");
        }
        assert!(bc.chain_config.active_configuration().is_none());
        assert!(
            bc.evaluate_stopping_condition().is_none(),
            "four blocks fill the capacity of 4, but no window is known"
        );

        let genesis = node_transfer_block(0, 7, 0, 7);
        bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("the genesis is admitted");
        assert!(
            bc.evaluate_stopping_condition().is_none(),
            "a genesis alone names no configuration"
        );

        let cfg = w4_config_anchor_block(1, genesis.view().hash());
        let cfg_idx = bc
            .tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("block #1 is admitted");
        assert_eq!(bc.active_chain_length(), Some(u32::from(W4)));
        assert_eq!(
            bc.evaluate_stopping_condition(),
            Some(cfg_idx),
            "the genesis-anchored segment carrying the configuration qualifies; \
             the longer window-anchored one, naming none, does not"
        );
    }

    /// Story 5.11 — `W <= SNAKE_CHAIN_LENGTH_MAX`, measured against this build's
    /// own `BUILD_LIMITS` (FR8): a chain-config block declaring the capacity
    /// loads, one declaring a window above it — or none, which resolves to the
    /// default 500 — is exact evidence of invalidity and never reaches storage.
    #[test]
    fn fr8_window_is_bounded_by_this_builds_capacity() {
        let mut bc = new_unconfigured_test_chain();
        assert_eq!(TestChain::BUILD_LIMITS.snake_chain_length_max, TEST_W);

        for (over, why) in [
            (
                chain_config_block_from(100, [0xAB; 32], &mut window_config_builder(TEST_W + 1)),
                "a declared window one above the capacity",
            ),
            (
                chain_config_block_from(100, [0xAC; 32], &mut ChainConfigPayloadBuilder::new()),
                "an absent window, whose default exceeds the capacity",
            ),
        ] {
            let (outcome, _) = bc.receive_block(over.view(), 0);
            assert_eq!(
                outcome,
                ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
                "{why} is refused"
            );
            assert_eq!(bc.block_tree_len(), 0, "{why} is not stored");
            assert!(bc.chain_config.active_configuration().is_none());
        }

        let at = chain_config_anchor_block(100, [0xAB; 32]);
        let (outcome, _) = bc.receive_block(at.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(bc.active_chain_length(), Some(u32::from(TEST_W)));
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
        // FR8 (Story 5.9, AC3): the candidate must name a configuration, so
        // block #1 carries the chain-config as the FR54 bootstrap emits it.
        // Admitted first, while it is still an orphan (no FR2 trigger), so the
        // genesis admission is what completes the genesis-anchored candidate —
        // which is the transition this test is about.
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        let (cfg_outcome, _) = bc.receive_block(cfg.view(), 100);
        assert_eq!(cfg_outcome, ReceiveBlockOutcome::AcceptedSilently);
        let (outcome, _) = bc.receive_block(genesis.view(), 100);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert!(
            bc.blocks
                .get(0)
                .is_some_and(|entry| entry.is_on_active_chain()),
            "the genesis is on the active chain after the FR4 promotion (AC9)"
        );
        assert!(
            bc.is_ready(),
            "genesis-anchored candidate validates → Ready (FR6/FR4, Story 5.4)"
        );
    }

    /// AC3 — a node holding no configuration does not enter Processing, even
    /// when the FR2 stopping condition is met: the FR3 derivation reads the FR37
    /// vote parameters, and running it on `vote_parameters`' inert baseline
    /// would produce a projection the node then goes `Ready` on. The block is
    /// admitted; only the stage that needs the configuration is withheld
    /// (specification §5.2). Compare `fr2_genesis_anchored_triggers_processing`,
    /// which is the same submission against a configured node.
    #[test]
    fn fr2_stays_collecting_without_configuration() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
        let genesis = node_transfer_block(0, 7, 0, 7);

        let (outcome, _) = bc.receive_block(genesis.view(), 100);

        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "the block itself is still admitted"
        );
        assert!(
            bc.current_phase() == LifecyclePhase::Collecting,
            "no configuration → no FR3 derivation, so no Processing and no Ready"
        );
        assert!(!bc.is_ready());
    }

    /// Defence in depth behind the FR2 gate: if a caller ever reaches the FR3
    /// derivation without a configuration, the vote engine refuses rather than
    /// accumulating on parameters nobody chose. Epic 6's deep-zone
    /// re-derivation and Story 5.10's restart are the callers this protects.
    #[test]
    fn processing_pass_refuses_without_configuration() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
        let genesis = node_transfer_block(0, 7, 0, 7);
        let (outcome, _) = bc.receive_block(genesis.view(), 100);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

        // The same candidate a configured node validates all the way to Ready
        // (see `fr2_genesis_anchored_triggers_processing`).
        assert_eq!(
            bc.run_processing_pass(0),
            Err(ProcessingError::Vote(VoteEngineError::NotParameterized)),
            "no FR37 parameters -> the derivation refuses, it does not guess"
        );
    }

    /// The window [`W4Chain`]'s configurations declare: its whole capacity.
    const W4: u16 = 4;

    /// A test chain with a small active-chain capacity (`SNAKE_CHAIN_LENGTH_MAX =
    /// 4`), configured with a window of the same length, so an active-length
    /// segment fits the test harness's block storage. Same shape as
    /// `new_test_chain` otherwise (local_node_id 5, join/Collecting).
    type W4Chain = Blockchain<
        Crypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        TestConfig,
        16,
        4,
        16,
        4,
        16,
    >;

    fn new_w4_chain() -> W4Chain {
        let (crypto, storage, _) = test_backends();
        // This harness's own capacities, not `TestChain`'s: its window is 4.
        let chain_config = locked_chain_config(&crypto, W4Chain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let mut slot = core::mem::MaybeUninit::uninit();
        Blockchain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
        // SAFETY: `init` returned, so every field of `slot` is initialized.
        unsafe { slot.assume_init() }
    }

    /// As [`new_w4_chain`], but holding **no** configuration — the joining node's
    /// starting state on the small-window harness.
    fn new_unconfigured_w4_chain() -> W4Chain {
        let (crypto, storage, _) = test_backends();
        let chain_config = empty_chain_config(W4Chain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let mut slot = core::mem::MaybeUninit::uninit();
        Blockchain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
        // SAFETY: `init` returned, so every field of `slot` is initialized.
        unsafe { slot.assume_init() }
    }

    /// AC2 — an active-length segment (`>= W = 4`) that does NOT reach genesis
    /// triggers Processing; one block short (len 3) it stays Collecting.
    #[test]
    fn fr2_active_length_triggers_at_w() {
        let mut bc = new_w4_chain();
        // Tail orphan at seq 100 (unresolved parent), then children up to len 3.
        // The tail is the chain-config block the FR8 final check requires in
        // scope (Story 5.9, AC3); as the segment anchor it is inert with respect
        // to the derivation — see `chain_config_anchor_block`.
        let tail = w4_config_anchor_block(100, [0xAB; 32]);
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
        // Block #1 names the configuration both branches inherit (Story 5.13).
        let cfg = chain_config_anchor_block(1, g.view().hash());
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("config admitted");
        let gh = cfg.view().hash();
        // Two distinct seq-2 children of block #1 (a fork) → both
        // genesis-anchored, both tip seq 2 → tie broken by lower tip hash.
        let a = salted_linked_block(2, gh, 3);
        let b = salted_linked_block(2, gh, 4);
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
        // Extend branch A to seq 3 → the higher sequence now outranks the tie.
        let c = salted_linked_block(3, a_hash, 3);
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
            let cfg = chain_config_anchor_block(1, g.view().hash());
            bc.tier1_admit(&cfg.view(), &cfg.view().hash(), now)
                .expect("config");
            let gh = cfg.view().hash();
            let blocks = [
                salted_linked_block(2, gh, order[0]),
                salted_linked_block(2, gh, order[1]),
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
        // Block #1 names the configuration, so the genesis branch is itself a
        // qualifying candidate (Story 5.13) — the one that must not win.
        let cfg = w4_config_anchor_block(1, g.view().hash());
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("config admitted");
        // A separate non-genesis branch of length W = 4 (tail seq 100 → tip 103),
        // its tail naming the same configuration.
        let tail = w4_config_anchor_block(100, [0xAB; 32]);
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
        // Block #1, carrying the configuration (Story 5.13) → a 2-block
        // genesis-anchored segment (< W).
        let c = chain_config_anchor_block(1, g.view().hash());
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
    /// A validly-signed chain-config block carrying the **base override set** —
    /// the exact content `new_test_chain`'s configuration is locked on, so it
    /// satisfies the FR6/FR8 content-identity check — chained to `prev`.
    ///
    /// Every fixture that drives a candidate to a successful pass needs one of
    /// these, because the FR8 final check (Story 5.9, AC3) makes a candidate
    /// segment without a chain-config block in scope invalid. Placed as the
    /// segment's **anchor** (lowest sequence) so it is provably inert with
    /// respect to everything the fixtures assert: the shared FR37/FR36 tail runs
    /// against all-zero derived state at that point, so the anti-capture interest
    /// is 0 (growth on 0 is 0), the creator-vote reset overwrites a 0 with a 0,
    /// and `mined_amount = 0` credits nothing. A fixture's original purpose is
    /// therefore preserved exactly, not approximately.
    ///
    /// `creator` is node 0, which the fixtures leave unseeded — so the
    /// per-creator FR6 checks are skipped by the pre-seed-zone rule — and which
    /// signs with the universal test key anyway, so the block is well-formed even
    /// where a fixture *does* seed node 0.
    fn chain_config_anchor_block(seq: u32, prev: [u8; 32]) -> Block {
        chain_config_block_from(seq, prev, &mut window_config_builder(TEST_W))
    }

    /// [`chain_config_anchor_block`] for the [`W4Chain`] harness, whose
    /// configuration declares its own window, [`W4`].
    fn w4_config_anchor_block(seq: u32, prev: [u8; 32]) -> Block {
        chain_config_block_from(seq, prev, &mut window_config_builder(W4))
    }

    /// A chain-config block at `seq`, chained to `prev`, carrying whatever
    /// content `payload_builder` has framed, signed by node #0 over exactly that
    /// content region.
    ///
    /// Takes the builder by `&mut` because `build_signed` returns a slice of the
    /// builder's own buffer; the caller owns the builder so the borrow outlives
    /// the call.
    fn chain_config_block_from(
        seq: u32,
        prev: [u8; 32],
        payload_builder: &mut ChainConfigPayloadBuilder,
    ) -> Block {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let header = BlockHeader {
            version: 1,
            sequence: seq,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: prev,
            signature: [0u8; 64],
        };
        let payload = payload_builder.build_signed(&signer);
        let mut builder = BlockBuilder::new().header(header);
        builder
            .set_chain_config_payload(payload)
            .ok()
            .expect("override set fits the payload");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// A **second, equally valid** override set, distinct in bytes from the base
    /// one: the base entry plus a literal declaring `vote_interest`'s own default
    /// value. It resolves every parameter identically to the base set, so a node
    /// adopting it behaves the same — the only thing that differs is the content
    /// bytes, which is exactly what the FR7/FR8 byte-identity rules turn on.
    fn alt_config_builder() -> ChainConfigPayloadBuilder {
        let mut builder = window_config_builder(TEST_W);
        builder
            .add_literal(parameter::VOTE_INTEREST, &[5])
            .ok()
            .expect("one literal entry is well-formed");
        builder
    }

    /// A deliberately small — but entirely legal — `block_size_limit`, used to
    /// build a tentative configuration that disagrees with a candidate's own.
    /// Above `HEADER_SIZE` (122), so the configuration module accepts it, and far
    /// below the framing ceiling, so a realistic block can exceed it.
    const SMALL_BLOCK_SIZE_LIMIT: u16 = 200;

    /// An override set declaring [`SMALL_BLOCK_SIZE_LIMIT`] and the window `w`.
    fn small_limit_config_builder(w: u16) -> ChainConfigPayloadBuilder {
        let mut builder = window_config_builder(w);
        builder
            .add_literal(
                parameter::BLOCK_SIZE_LIMIT,
                &SMALL_BLOCK_SIZE_LIMIT.to_le_bytes(),
            )
            .ok()
            .expect("a two-byte literal is well-formed");
        builder
    }

    /// An override set that is **well-formed but structurally illegal**:
    /// `vote_scale = 0`, which the configuration module refuses on a bound (it is
    /// the denominator of the FR37 anti-capture rule). The framing is valid, so
    /// the envelope walks and the FR7 signature verifies — the refusal comes from
    /// the module, which is the ordering AC2 is about.
    fn bound_violating_config_builder() -> ChainConfigPayloadBuilder {
        let mut builder = ChainConfigPayloadBuilder::new();
        builder
            .add_literal(parameter::VOTE_SCALE, &0u16.to_le_bytes())
            .ok()
            .expect("the entry itself is well-formed; the bound is what fails");
        builder
    }

    /// The content region of a chain-config block, as the FR7/FR8 comparisons
    /// see it.
    fn content_of(block: &Block) -> &[u8] {
        block
            .view()
            .chain_config()
            .expect("a chain-config block frames")
            .content()
    }

    /// Admits a [`chain_config_anchor_block`] at `seq` chained to `prev` and
    /// returns its hash, for use as the next block's `previous_hash`. The block
    /// is deliberately admitted through `tier1_admit`, so the FR7 content
    /// signature is really verified on the way in.
    fn admit_chain_config_anchor(bc: &mut TestChain, seq: u32, prev: [u8; 32]) -> [u8; 32] {
        let cfg = chain_config_anchor_block(seq, prev);
        let hash = cfg.view().hash();
        bc.tier1_admit(&cfg.view(), &hash, 0)
            .expect("chain-config anchor admitted");
        hash
    }

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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0xB1), (2, 300, 20, 0xB2)], 2);
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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(100, cfg_hash, &[(1, 100, 0, 0xB1)], 1);
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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0xB1), (2, 300, 0, 0xB2)], 2);
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
        // FR8 (Story 5.9, AC3): the segment is anchored by a chain-config block,
        // which is inert here — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // A transfer from node 7 to node 9, neither ever seeded.
        let anchor = chained_node_transfer_block(100, cfg_hash, 3, 99, 7);
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
        bc.tier1_admit(&g.view(), &g.view().hash(), 0)
            .expect("genesis admitted");
        // FR8 (Story 5.9, AC3): block #1 carries the chain-config. It contributes
        // no balance block, so the watermark this test measures is untouched.
        let ci = {
            let cfg = chain_config_anchor_block(1, g.view().hash());
            bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
                .expect("chain-config block admitted")
        };

        bc.run_processing_pass(ci).expect("pass succeeds");

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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(
            100,
            cfg_hash,
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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0xB1)], 1);
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
            // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
            // block in scope, so the segment is anchored by one. Inert with
            // respect to everything below — see `chain_config_anchor_block`.
            let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
            let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0xB1), (2, 300, 0, 0xB2)], 2);
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
        let genesis = node_transfer_block(0, 3, 0, 7);
        // FR8 (Story 5.9, AC3): block #1 carries the chain-config, admitted first
        // as an orphan so the genesis admission completes the candidate.
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        bc.receive_block(cfg.view(), 0);
        let (outcome, _next) = bc.receive_block(genesis.view(), 0);
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

    /// AC10 (Story 5.4) + AC11(c)/(f) (Story 5.5, amended 2026-07-30) — the
    /// FR6-failure path end to end, *including the immediate retry*: a
    /// qualifying candidate that violates an FR6 invariant has its offender
    /// deleted, and the shortened branch is re-evaluated and validated **inside
    /// the same call**, so the node reaches Ready without waiting for another
    /// admission. That is the whole point of the retry-on-`Invalid` rule: the
    /// failed pass had already proved every block below the offender, and
    /// `block_idx` names the earliest one.
    ///
    /// The candidate `[#0 genesis, #1 chain-config, #2 registration]` is
    /// continuous genesis-anchored (so FR2 qualifies on the genesis admission)
    /// but block #2's `new_node_id = 5 ≠ watermark + 1 = 1` violates the FR6
    /// registration-monotonicity rule. Block #1 is the chain-config the FR8
    /// final check (Story 5.9, AC3) requires — and it has to be *below* the
    /// offender, because the shortened branch the retry validates must still name
    /// a configuration.
    #[test]
    fn fr5_seam_recovers_and_retries_invalid_candidate_in_one_call() {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        // Out-of-sequence registration child (new_node_id 5, expected 1).
        let child = registration_block(2, cfg.view().hash(), 1, 5, 0xC5);
        // Admit the upper blocks first, while they are still orphans (Stored, no
        // FR2 — not yet anchored), then the genesis, so the continuous
        // genesis-anchored candidate qualifies on that last admission.
        let (outcome, _) = bc.receive_block(child.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "the orphan child is really admitted (the seam below is not vacuous)"
        );
        let (cfg_outcome, _) = bc.receive_block(cfg.view(), 0);
        assert_eq!(cfg_outcome, ReceiveBlockOutcome::AcceptedSilently);
        let child_idx = bc
            .blocks
            .find(2, &child.view().hash())
            .expect("child in the tree");
        assert!(bc.current_phase() == LifecyclePhase::Collecting);
        let (outcome, _) = bc.receive_block(genesis.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        // AC11(a): the offender and its descendants are gone, the genesis and the
        // chain-config block survive.
        assert!(
            bc.blocks.get(child_idx).is_none(),
            "the offending block is deleted from the tree (and its durable slot freed)"
        );
        let genesis_idx = bc
            .blocks
            .find(0, &genesis.view().hash())
            .expect("genesis survives");
        let cfg_idx = bc
            .blocks
            .find(1, &cfg.view().hash())
            .expect("chain-config block survives");
        assert_eq!(bc.blocks.len(), 2);
        // AC11(f), amended: the shortened branch is re-evaluated in this very
        // call and validates, so the node is Ready on return — no second
        // admission, no tick, no wait for ambient traffic.
        assert!(
            bc.is_ready(),
            "the retry validates the shortened genesis-anchored candidate in-call"
        );
        assert_eq!(
            bc.active_chain_head_idx, cfg_idx,
            "the retry's Ready transition establishes the surviving tip as the active head"
        );
        assert_eq!(
            bc.blocks
                .get(genesis_idx)
                .expect("genesis present")
                .status(),
            BlockStatus::Active,
            "the surviving candidate is promoted Stored→Active by the retry"
        );
        // AC11(c): the offender's derived effect is gone — the retry re-derived
        // from the surviving segment alone, it did not resume the failed pass.
        assert!(
            !bc.node_info.is_seeded(5),
            "the offending registration's effect is absent from the working set"
        );
        assert_eq!(bc.node_info.max_known_node_id(), 0);
    }

    // --- Story 5.5: FR5 atomic recovery -------------------------------------

    /// AC11(a) — an `Invalid` failure deletes the offending block **and** its
    /// transitive descendants, and nothing else: a sibling subtree whose
    /// ancestry does not pass through the target survives, as does the target's
    /// own ancestor.
    #[test]
    fn fr5_deletes_offender_subtree_and_spares_sibling() {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let gi = bc
            .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("genesis admitted");
        // Offending branch: genesis ← b1 ← b2.
        let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
        let bi1 = bc
            .tier1_admit(&b1.view(), &b1.view().hash(), 0)
            .expect("b1 admitted");
        let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, 1, 0);
        let bi2 = bc
            .tier1_admit(&b2.view(), &b2.view().hash(), 0)
            .expect("b2 admitted");
        // Sibling branch forking at the genesis (a different amount → a distinct
        // hash, so it is a genuine second child, not an FR11 duplicate).
        let c1 = transfer_block(1, genesis.view().hash(), 1, 2, 200, 1, 0);
        let ci1 = bc
            .tier1_admit(&c1.view(), &c1.view().hash(), 0)
            .expect("c1 admitted");
        assert_eq!(bc.blocks.len(), 4);

        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(
            ProcessingError::Invalid {
                block_idx: bi1,
                reason: ValidationReason::UnseededActor,
            },
            bi2,
        );

        assert!(
            bc.blocks.get(bi1).is_none(),
            "the earliest offender is deleted"
        );
        assert!(
            bc.blocks.get(bi2).is_none(),
            "its transitive descendant is deleted too"
        );
        assert!(
            bc.blocks.get(gi).is_some(),
            "the target's ancestor survives"
        );
        assert!(
            bc.blocks.get(ci1).is_some(),
            "the sibling subtree is untouched"
        );
        assert_eq!(bc.blocks.len(), 2);
        // FR19 event (iv): only the sibling branch is still tracked, and the
        // genesis keeps no entry of its own (it still has the sibling child).
        assert_eq!(bc.chain_heads.count(), 1);
        assert!(bc.chain_heads.occupied_heads().any(|(h, _)| h == ci1));
        assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
    }

    /// AC11(b) — an arithmetic vote failure is not exact evidence against any
    /// specific block, so exactly **one** block is deleted: the candidate head.
    /// The local failures delete nothing.
    /// Its parent becomes the new tip and stays tracked, so the shortened branch
    /// remains an FR2 candidate.
    #[test]
    fn fr5_non_invalid_error_deletes_only_the_candidate_head() {
        fn run(err: ProcessingError) -> (usize, bool, bool) {
            let mut bc = new_test_chain();
            let genesis = node_transfer_block(0, 0, 0, 0);
            bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
                .expect("genesis admitted");
            let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
            let bi1 = bc
                .tier1_admit(&b1.view(), &b1.view().hash(), 0)
                .expect("b1 admitted");
            let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, 1, 0);
            let bi2 = bc
                .tier1_admit(&b2.view(), &b2.view().hash(), 0)
                .expect("b2 admitted");
            bc.set_lifecycle_phase(LifecyclePhase::Processing);
            bc.recover_from_failed_pass(err, bi2);
            (
                bc.blocks.len(),
                bc.blocks.get(bi2).is_none(),
                // The retargeted entry tracks b1 as the new tip.
                bc.chain_heads.occupied_heads().any(|(h, _)| h == bi1),
            )
        }
        // A local failure is no evidence at all: nothing is deleted (amended
        // FR5, DEC-037 and DEC-134).
        for err in [
            ProcessingError::StorageRead,
            ProcessingError::Vote(VoteEngineError::NotParameterized),
            ProcessingError::MissingBlock,
            ProcessingError::MarkOverflow,
        ] {
            assert_eq!(run(err).0, 3, "a local failure deletes nothing");
        }
        // `Vote(_)` is the one the head fallback exists for: the Story-5.4
        // review accepted that a vote failure carries no `block_idx`, and this
        // arm is what makes that imprecision safe.
        assert_eq!(
            run(ProcessingError::Vote(
                VoteEngineError::AccumulatedVoteOverflow
            )),
            (2, true, true),
            "the head fallback deletes exactly the candidate head and keeps \
             the shortened branch tracked"
        );
    }

    /// Task 2 / AC3 degenerate target: an `Invalid` whose `block_idx` names an
    /// empty or out-of-range slot must still perform the rollback and the
    /// reversion. That is the branch which skips `on_blocks_deleted` *and* the
    /// `active_chain_head_idx` clearing through `if deleted_count > 0`, so it
    /// needs coverage at the recovery level — `mark_subtree_of_empty_or_out_of_range_root_is_empty`
    /// only proves the helper returns an empty set.
    #[test]
    fn fr5_degenerate_target_still_rolls_back_and_reverts() {
        let mut bc = new_test_chain();
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0xB1), (2, 300, 20, 0xB2)], 5);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 0);
        bc.tier1_admit(&tx.view(), &tx.view().hash(), 0)
            .expect("tx admitted");
        let reg = registration_block(102, tx.view().hash(), 1, 3, 0xC3);
        let ri = bc
            .tier1_admit(&reg.view(), &reg.view().hash(), 0)
            .expect("registration admitted");

        // Dirty the working set for real, so the rollback has something to undo.
        bc.run_processing_pass(ri).expect_err("watermark violation");
        assert!(bc.node_info.is_seeded(1), "the aborted pass derived state");
        let blocks_before = bc.blocks.len();
        let mut heads_before = [(NONE_REF, NONE_REF); 4];
        for (slot, head) in heads_before.iter_mut().zip(bc.chain_heads.occupied_heads()) {
            *slot = head;
        }

        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(
            ProcessingError::Invalid {
                block_idx: NONE_REF,
                reason: ValidationReason::RegistrationWatermark,
            },
            ri,
        );

        assert!(!bc.node_info.is_seeded(1), "rollback still runs");
        assert_eq!(bc.node_info.max_known_node_id(), 0, "watermark still reset");
        assert_eq!(
            bc.current_phase(),
            LifecyclePhase::Collecting,
            "reversion still runs"
        );
        assert_eq!(bc.blocks.len(), blocks_before, "nothing is deleted");
        let mut heads_after = [(NONE_REF, NONE_REF); 4];
        for (slot, head) in heads_after.iter_mut().zip(bc.chain_heads.occupied_heads()) {
            *slot = head;
        }
        assert_eq!(heads_after, heads_before, "the tip table is untouched");
    }

    /// AC11(c) — the working set is fully rolled back: per-node projection
    /// (balances, keys, watermark), accumulated vote, and the surviving blocks'
    /// available-UTXO bitfields. Driven through the real
    /// `run_processing_pass` → `recover_from_failed_pass` pair over a
    /// window-anchored candidate that derives state *before* it fails.
    #[test]
    fn fr5_working_set_is_clean_after_recovery() {
        let mut bc = new_test_chain();
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // Window-anchored candidate: balance seed (watermark 5) → valid transfer
        // → out-of-sequence registration (id 3, expected 6).
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 10, 0xB1), (2, 300, 20, 0xB2)], 5);
        let ai = bc
            .tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 0);
        let ti = bc
            .tier1_admit(&tx.view(), &tx.view().hash(), 0)
            .expect("tx admitted");
        let reg = registration_block(102, tx.view().hash(), 1, 3, 0xC3);
        let ri = bc
            .tier1_admit(&reg.view(), &reg.view().hash(), 0)
            .expect("registration admitted");

        let err = bc.run_processing_pass(ri).expect_err("watermark violation");
        assert_eq!(
            err,
            ProcessingError::Invalid {
                block_idx: ri,
                reason: ValidationReason::RegistrationWatermark,
            }
        );
        // The aborted pass leaves its partial derivation behind — that is exactly
        // what the recovery has to discard.
        assert!(bc.node_info.is_seeded(1));
        assert_eq!(bc.node_info.max_known_node_id(), 5);

        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(err, ri);

        assert!(!bc.node_info.is_seeded(1), "roster reset");
        assert!(!bc.node_info.is_seeded(2));
        assert_eq!(bc.node_info.balance_of(1), 0, "balances reset");
        assert_eq!(bc.node_info.balance_of(2), 0);
        assert!(bc.node_info.public_key_of(1).is_none(), "key mapping reset");
        assert_eq!(bc.node_info.max_known_node_id(), 0, "watermark reset");
        assert_eq!(
            bc.vote_engine.accumulated_vote_of(1),
            0,
            "accumulated vote reset"
        );
        assert_eq!(bc.vote_engine.accumulated_vote_of(2), 0);
        // The surviving segment's available-UTXO bits are at the clean all-zero baseline
        // (owned by the pass's entry/abort handling — recovery does not sweep
        // them a second time, and must not need to).
        for idx in [ai, ti] {
            for bit in 0..8 {
                assert_eq!(
                    bc.blocks.utxo_available(idx, bit),
                    Some(false),
                    "no available-UTXO bit survives a failed candidate"
                );
            }
        }
        assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
    }

    /// AC11(d)/(e) — deleting the block `active_chain_head_idx` points at clears
    /// the anchor placeholder (and empties `chain_heads`), which is what makes
    /// re-acquisition of the discarded genesis possible: the single-genesis guard
    /// keys on `active_chain_head_idx != NONE_REF`.
    #[test]
    fn fr5_clears_active_head_when_its_block_is_deleted() {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let gi = bc
            .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("genesis admitted");
        let child = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
        let ci = bc
            .tier1_admit(&child.view(), &child.view().hash(), 0)
            .expect("child admitted");
        assert_eq!(bc.active_chain_head_idx, gi);

        // The genesis pair is not exempt: an `Invalid` pinned at block #0 deletes
        // it and everything descending from it (FR5 deletion is forward progress).
        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(
            ProcessingError::Invalid {
                block_idx: gi,
                reason: ValidationReason::CreatorSignatureInvalid,
            },
            ci,
        );

        assert_eq!(bc.blocks.len(), 0, "the whole subtree is gone");
        assert_eq!(
            bc.active_chain_head_idx, NONE_REF,
            "the anchor placeholder is cleared with its target"
        );
        assert_eq!(bc.chain_heads.count(), 0, "no tracked tip remains");
        // Re-acquisition is now possible — the guard no longer refuses a genesis.
        assert!(
            bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
                .is_ok(),
            "a node that discarded its genesis can re-acquire one"
        );
    }

    /// AC7, amended 2026-07-30 — recovery restores the **whole** pre-acquisition
    /// active-chain marking, not just the anchor index: every block's
    /// `is_on_active_chain` bit is cleared, and the FR19 genesis bootstrap is
    /// re-established on the surviving block #0. The pre-marked survivors here
    /// stand in for a `promote_candidate_active` that ran before this recovery
    /// (the Story-5.10 / Epic-6 reuse) — without the clearing they would keep
    /// claiming to be on an active chain that no longer has a head.
    #[test]
    fn fr5_restores_active_chain_marking_and_keeps_the_genesis_bootstrap() {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let gi = bc
            .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("genesis admitted");
        let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
        let bi1 = bc
            .tier1_admit(&b1.view(), &b1.view().hash(), 0)
            .expect("b1 admitted");
        let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, 1, 0);
        let bi2 = bc
            .tier1_admit(&b2.view(), &b2.view().hash(), 0)
            .expect("b2 admitted");
        // Stand in for a prior promotion: mark the whole chain Active and move
        // the anchor to the tip, exactly as `promote_candidate_active` would —
        // it writes the status and the bit together, so recovery must undo both.
        for idx in [gi, bi1, bi2] {
            bc.blocks.set_status(idx, BlockStatus::Active);
            bc.blocks.set_on_active_chain(idx, true);
        }
        bc.active_chain_head_idx = bi2;

        // Fail at b2 → only b2 is deleted; the genesis and b1 survive marked.
        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(
            ProcessingError::Invalid {
                block_idx: bi2,
                reason: ValidationReason::CreatorSignatureInvalid,
            },
            bi2,
        );

        assert!(bc.blocks.get(bi2).is_none(), "the offender is deleted");
        assert!(
            !bc.blocks
                .get(bi1)
                .expect("b1 survives")
                .is_on_active_chain(),
            "a surviving non-genesis block no longer claims to be on the active chain"
        );
        assert!(
            bc.blocks
                .get(gi)
                .expect("genesis survives")
                .is_on_active_chain(),
            "the FR19 genesis bootstrap is re-established on the surviving block #0"
        );
        // FR9: collecting state holds every retained block at `Stored` — the
        // promotion's status half is undone with its flag half, and the genesis
        // is no exception (its bootstrap marking is not an FR9 promotion).
        for idx in [gi, bi1] {
            assert_eq!(
                bc.blocks.get(idx).expect("survivor").status(),
                BlockStatus::Stored,
                "every surviving block is back at Stored (FR9 collecting-state rule)"
            );
        }
        assert_eq!(
            bc.active_chain_head_idx, gi,
            "the anchor is restored to the genesis, not left at the deleted tip"
        );
        // The bootstrap is what keeps the shortened branch Connected: a demoted
        // head would carry the all-zero missing-parent hash and request it forever.
        assert!(
            bc.chain_heads.occupied_heads().any(|(head, _)| head == bi1),
            "the shortened branch is still tracked"
        );
    }

    /// AC11(g) — recovery is `now`-independent (FR63/NFR5): the same failing
    /// candidate replayed under two wall-clocks produces the same deleted set,
    /// the same tip table, the same phase, and the same anchor. Extends the
    /// `receive_block_ignores_now` pattern of Stories 4.3/4.4/5.3.
    #[test]
    fn fr5_recovery_ignores_now() {
        // Compare *identity*, not cardinality: which slots survived, the tip
        // table's (head, tail-point) pairs, the anchor, the phase, and both
        // admission outcomes. `blocks.len()` alone cannot distinguish a
        // recovery that deleted a different block of the same count, and
        // discarding the outcomes would let the whole test pass vacuously if
        // both runs failed at intake and never reached the pass at all.
        #[derive(PartialEq, Debug)]
        struct Snapshot {
            occupied: [bool; 16],
            heads: [(u32, u32); 4],
            active: u32,
            ready: bool,
            outcomes: [ReceiveBlockOutcome; 2],
        }
        fn run(now: u64) -> Snapshot {
            let mut bc = new_test_chain();
            let genesis = node_transfer_block(0, 0, 0, 0);
            // Block #1 is the chain-config the FR8 final check requires below the
            // offender (Story 5.9, AC3) — see
            // `fr5_seam_recovers_and_retries_invalid_candidate_in_one_call`.
            let cfg = chain_config_anchor_block(1, genesis.view().hash());
            let child = registration_block(2, cfg.view().hash(), 1, 5, 0xC5);
            let (first, _) = bc.receive_block(child.view(), now);
            bc.receive_block(cfg.view(), now.saturating_add(1_000));
            let (second, _) = bc.receive_block(genesis.view(), now.saturating_add(9_000));

            let mut occupied = [false; 16];
            for (slot, flag) in occupied.iter_mut().enumerate() {
                *flag = bc.blocks.get(slot as u32).is_some();
            }
            let mut heads = [(NONE_REF, NONE_REF); 4];
            for (entry, head) in heads.iter_mut().zip(bc.chain_heads.occupied_heads()) {
                *entry = head;
            }
            Snapshot {
                occupied,
                heads,
                active: bc.active_chain_head_idx,
                ready: bc.is_ready(),
                outcomes: [first, second],
            }
        }
        let baseline = run(0);
        assert_eq!(
            baseline,
            run(1_000_000),
            "the recovery outcome is identical across wall-clocks"
        );
        // Non-vacuity: both blocks really were admitted (so the FR2 gate ran the
        // pass), the pass really failed (phase back to Collecting), and the
        // deletion really happened (the offending child is gone).
        assert_eq!(
            baseline.outcomes,
            [
                ReceiveBlockOutcome::AcceptedSilently,
                ReceiveBlockOutcome::AcceptedSilently
            ],
            "both admissions succeeded, so the failing pass was actually reached"
        );
        assert!(
            baseline.ready,
            "the failed pass recovered and its in-call retry validated the shortened candidate"
        );
        assert_eq!(
            baseline.occupied.iter().filter(|slot| **slot).count(),
            2,
            "recovery deleted the offending subtree and left exactly the genesis \
             and the chain-config block"
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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let blk = credit_block(100, cfg_hash, 8, 500, 7, 9, 0);
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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // max_node_id 9 so the transfer's (unseeded, pre-window) initializer 7 and
        // receiver 9 are within the valid node-id range — only node 3 is
        // individually seeded (partial FR50 coverage).
        let anchor = balance_block(100, cfg_hash, &[(3, 100, 0, 0xB3)], 9);
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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // Balance block declares max_node_id 5 → watermark 5; the next valid
        // registration id is 6. A registration for id 3 violates the stride-1 rule.
        let anchor = balance_block(100, cfg_hash, &[(1, 100, 0, 0xB1)], 5);
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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // max_node_id 8 so the transfer's initializer 1 and receiver 2 are in range;
        // the vote target 9 is beyond the watermark → cannot exist.
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0xB1)], 8);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        // Vote target 9 is beyond max_known_node_id (8) → not a possible node.
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

    /// FR6 node-existence bound — a transaction that references a node id beyond
    /// `max_known_node_id` (contiguous ids ⇒ it cannot exist) is rejected on BOTH
    /// sides: the initializer (input) and the receiver (output). This holds even for
    /// an unseeded (pre-window) node — its existence is still range-checkable — so a
    /// window-anchored candidate is not blindly trusted.
    #[test]
    fn fr6_rejects_out_of_range_referenced_node() {
        let mut bc = new_test_chain();
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // Window-anchored, watermark 5 (only node 1 individually seeded).
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0xB1)], 5);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        // Output side: receiver 99 is beyond the watermark.
        let out = transfer_block(101, anchor.view().hash(), 1, 99, 100, 1, 0);
        let oi = bc
            .tier1_admit(&out.view(), &out.view().hash(), 0)
            .expect("out admitted");
        assert_eq!(
            bc.run_processing_pass(oi),
            Err(ProcessingError::Invalid {
                block_idx: oi,
                reason: ValidationReason::NodeIdOutOfRange,
            }),
            "a transfer TO a node beyond the watermark is rejected (output side)"
        );
        // Input side: an (unseeded) initializer 88 is beyond the watermark — normally
        // an unseeded initializer is trusted on a window-anchored candidate, but its
        // existence is still range-bounded.
        let inp = transfer_block(101, anchor.view().hash(), 88, 2, 100, 1, 0);
        let ii = bc
            .tier1_admit(&inp.view(), &inp.view().hash(), 0)
            .expect("inp admitted");
        assert_eq!(
            bc.run_processing_pass(ii),
            Err(ProcessingError::Invalid {
                block_idx: ii,
                reason: ValidationReason::NodeIdOutOfRange,
            }),
            "a transfer FROM a node beyond the watermark is rejected (input side)"
        );
    }

    /// FR6 vote-target existence is a WATERMARK RANGE check, not a per-node
    /// `is_seeded` lookup. A balance block covers only a subset of nodes (FR50) but
    /// declares the full `max_node_id`; a transaction may legitimately vote for a
    /// node that exists (id ≤ watermark) yet whose own balance-block coverage is
    /// not present earlier in the window. This must be ACCEPTED — the pre-fix
    /// `is_seeded(vote)` check would have falsely rejected it as `VoteTargetUnknown`.
    #[test]
    fn fr6_vote_target_in_range_but_not_individually_seeded_is_accepted() {
        let mut bc = new_test_chain();
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // Partial-coverage balance block: seeds only node 1, but declares
        // max_node_id = 10 (nodes 2..=10 exist pre-window / elsewhere in the window
        // but are not individually seeded by THIS block).
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0xB1)], 10);
        bc.tier1_admit(&anchor.view(), &anchor.view().hash(), 0)
            .expect("anchor admitted");
        // Node 1 (seeded) votes for node 5: 5 ∉ seeded-set but 5 ≤ watermark(10).
        let tx = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 5);
        let ti = bc
            .tier1_admit(&tx.view(), &tx.view().hash(), 0)
            .expect("tx admitted");
        assert_eq!(
            bc.run_processing_pass(ti).map(|_| ()),
            Ok(()),
            "a vote for an in-range node is accepted even if not individually seeded"
        );
        // Boundary: a vote for node 11 (> watermark 10) is still exact-evidence invalid.
        let tx2 = transfer_block(101, anchor.view().hash(), 1, 2, 100, 1, 11);
        let ti2 = bc
            .tier1_admit(&tx2.view(), &tx2.view().hash(), 0)
            .expect("tx2 admitted");
        assert_eq!(
            bc.run_processing_pass(ti2),
            Err(ProcessingError::Invalid {
                block_idx: ti2,
                reason: ValidationReason::VoteTargetUnknown,
            }),
            "a vote for a node beyond the watermark is still rejected"
        );
    }

    /// FR3/FR6 — on a WINDOW-anchored candidate the incremental watermark is only
    /// authoritative once the first balance block establishes it. A registration
    /// that precedes the first balance block is in the trusted pre-window region
    /// (AC4): its monotonicity is NOT re-checked (it would otherwise be measured
    /// against a still-0 watermark and falsely rejected). The earliest balance
    /// block's `max_node_id` (read once at the end of the backward mark) seeds the
    /// existence floor. Genesis-anchored candidates are unaffected — they re-derive
    /// the watermark from block #0, so their registrations ARE monotonicity-checked
    /// (covered by `fr6_rejects_out_of_sequence_registration`).
    #[test]
    fn fr6_window_anchored_registration_before_first_balance_is_trusted() {
        let mut bc = new_test_chain();
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // Orphan anchor (seq 100, window-anchored): a registration for node 7 —
        // stride-1 against a 0 watermark would demand id 1, so the OLD per-0 check
        // would reject it. It precedes the segment's only balance block (seq 101).
        let reg = registration_block(100, cfg_hash, 1, 7, 0xC7);
        bc.tier1_admit(&reg.view(), &reg.view().hash(), 0)
            .expect("registration admitted");
        // Balance block at seq 101: declares the full count (max_node_id 10) — the
        // existence floor — and seeds node 1.
        let bal = balance_block(101, reg.view().hash(), &[(1, 100, 0, 0xB1)], 10);
        let bi = bc
            .tier1_admit(&bal.view(), &bal.view().hash(), 0)
            .expect("balance admitted");
        assert_eq!(
            bc.run_processing_pass(bi).map(|_| ()),
            Ok(()),
            "a window-anchored pre-first-balance registration is trusted, not \
             rejected against a 0 watermark"
        );
        // The registered node is on the roster afterwards.
        assert!(
            bc.node_info.is_seeded(7),
            "node 7 registered during the pass"
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
        // FR8 (Story 5.9, AC3): the candidate must name a configuration, and the
        // existence check runs before the forward traversal (PRD FR3) — so
        // without block #1 the pass would report the whole-candidate verdict
        // instead of the per-block one under test. The config block sits *above*
        // the offender, so the walk still reaches #0 first.
        let cfg = chain_config_anchor_block(1, block.view().hash());
        let tip = bc
            .tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("chain-config block admitted");
        assert_eq!(
            bc.run_processing_pass(tip),
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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // Earliest balance block → watermark initialized to 1.
        let b0 = balance_block(100, cfg_hash, &[(1, 500, 0, 0xB1)], 1);
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
        // `new_test_chain` is durably locked on `BASE_CONFIG_CONTENT`; this
        // block carries a different (but equally well-framed) content region.
        let mut bc = new_test_chain();
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
        let mut config_payload = window_config_builder(TEST_W);
        config_payload
            .add_literal(parameter::VOTE_INTEREST, &[5])
            .ok()
            .expect("a one-entry override set frames");
        builder
            .set_chain_config_payload(config_payload.build_signed(&signer))
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
        // FR8 (Story 5.9, AC3): the candidate must carry a chain-config
        // block in scope, so the segment is anchored by one. Inert with
        // respect to everything below — see `chain_config_anchor_block`.
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let anchor = balance_block(100, cfg_hash, &[(1, 500, 0, 0xB1)], 1);
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
        // FR8 (Story 5.9, AC3): block #1 carries the chain-config the candidate
        // must name — the existence check precedes the forward traversal (PRD
        // FR3), and it sits below the offender so the walk still reaches it.
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
            .expect("chain-config block admitted");
        // Block #2: a transfer whose initializer (node 1) never registered.
        let child = transfer_block(2, cfg.view().hash(), 1, 2, 100, 1, 0);
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

    // =======================================================================
    // Story 5.9 — FR7 content-signature commitment + FR8 tentative/durable
    // =======================================================================

    /// AC2 — the **first** chain-config block whose FR7 signature verifies and
    /// whose content the module accepts is loaded tentatively, and is retained
    /// like any other admitted block.
    #[test]
    fn fr8_first_config_block_loads_tentatively() {
        let mut bc = new_unconfigured_test_chain();
        assert!(
            bc.chain_config.active_configuration().is_none(),
            "a joining node starts with no configuration"
        );
        let cfg = chain_config_anchor_block(100, [0xAB; 32]);

        let (outcome, _) = bc.receive_block(cfg.view(), 0);

        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        let idx = bc
            .blocks
            .find(100, &cfg.view().hash())
            .expect("the config block is retained (FR8)");
        assert_eq!(
            bc.chain_config.tentative_content(),
            Some(content_of(&cfg)),
            "the content region is held tentatively, signature trailer excluded"
        );
        assert!(
            !bc.chain_config.is_durable_locked(),
            "a join-path load is tentative, never a lock"
        );
        assert_eq!(
            bc.tentative_config_block_idx, idx,
            "the provenance names the retained block"
        );
    }

    /// AC2 — a valid-signature config block whose content violates a structural
    /// bound is exact evidence of invalidity (FR16): it does not enter durable
    /// storage, and no tentative configuration remains loaded.
    #[test]
    fn fr8_bound_violating_content_is_rejected_and_stores_nothing() {
        let mut bc = new_unconfigured_test_chain();
        let cfg = chain_config_block_from(100, [0xAB; 32], &mut bound_violating_config_builder());

        let (outcome, _) = bc.receive_block(cfg.view(), 0);

        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            "a refused content is exact evidence, not a silent discard"
        );
        assert_eq!(
            bc.blocks.len(),
            0,
            "the block never entered durable storage"
        );
        assert!(
            bc.chain_config.active_configuration().is_none(),
            "no configuration remains loaded after a refusal"
        );
        assert_eq!(bc.tentative_config_block_idx, NONE_REF);
    }

    /// AC2 + AC7 — a second chain-config block arriving while the configuration
    /// is merely **tentative** must neither override it nor be discarded.
    ///
    /// Both halves matter. FR8 says such a block "shall be stored in the
    /// block-tree subject to FR16 and shall not override the tentative
    /// configuration"; and the AC6 mismatch path *depends* on it being retained,
    /// because the content it adopts comes from a config block that disagrees
    /// with the current tentative. A tentative-keyed FR17 gate would discard
    /// exactly the block the recovery needs.
    #[test]
    fn fr8_second_config_block_while_tentative_neither_overrides_nor_is_discarded() {
        let mut bc = new_unconfigured_test_chain();
        let first = chain_config_anchor_block(100, [0xAB; 32]);
        bc.receive_block(first.view(), 0);
        let first_idx = bc
            .blocks
            .find(100, &first.view().hash())
            .expect("first config block retained");

        let second = chain_config_block_from(101, first.view().hash(), &mut alt_config_builder());
        let (outcome, _) = bc.receive_block(second.view(), 0);

        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "FR17 must stand down while the configuration is only tentative"
        );
        assert!(
            bc.blocks.find(101, &second.view().hash()).is_some(),
            "the disagreeing block is retained, not discarded"
        );
        assert_eq!(
            bc.chain_config.tentative_content(),
            Some(content_of(&first)),
            "the tentative configuration is not overridden"
        );
        assert_eq!(
            bc.tentative_config_block_idx, first_idx,
            "provenance still names the first block"
        );
    }

    /// AC7 — once the configuration is durably locked, the FR17 gate *does* fire:
    /// a config block whose content differs is silently discarded. The contrast
    /// with the test above is the whole of AC7.
    #[test]
    fn fr17_discards_mismatching_config_block_only_once_durably_locked() {
        let mut bc = new_test_chain(); // durably locked on the base override set
        let cfg = chain_config_block_from(100, [0xAB; 32], &mut alt_config_builder());

        let (outcome, _) = bc.receive_block(cfg.view(), 0);

        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            "post-lock, a disagreeing config block is discarded (FR17)"
        );
        assert_eq!(bc.blocks.len(), 0);
    }

    /// AC3 — a candidate segment carrying **no** chain-config block cannot
    /// satisfy FR6 chain-config compliance, so the pass refuses it and the FR5
    /// recovery rolls it back.
    #[test]
    fn fr8_candidate_without_config_block_is_refused() {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 3, 0, 7);
        let gi = bc
            .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("genesis admitted");

        assert_eq!(
            bc.run_processing_pass(gi),
            Err(ProcessingError::Invalid {
                block_idx: gi,
                reason: ValidationReason::MissingChainConfigBlock,
            }),
            "a candidate naming no configuration is not a chain to go Ready on"
        );
    }

    /// Story 5.13 — a segment that names no configuration is not an FR2
    /// candidate at all, so nothing is deleted for it. Before 5.13 it qualified,
    /// failed the FR8 final check, and FR5 deleted its head — a valid block —
    /// once per re-qualification.
    #[test]
    fn fr2_segment_naming_no_configuration_is_not_a_candidate() {
        // A window-anchored segment of exactly W = 4 blocks, none of them a
        // chain-config block, on a configured node.
        let mut bc = new_w4_chain();
        let tail = node_transfer_block(100, 3, 99, 7);
        bc.receive_block(tail.view(), 0);
        let b101 = linked_transfer_block(101, tail.view().hash());
        let b102 = linked_transfer_block(102, b101.view().hash());
        let b103 = linked_transfer_block(103, b102.view().hash());
        for blk in [&b101, &b102, &b103] {
            bc.receive_block(blk.view(), 0);
        }

        assert!(
            bc.evaluate_stopping_condition().is_none(),
            "length W, but the segment names no configuration"
        );
        assert!(
            bc.current_phase() == LifecyclePhase::Collecting,
            "no pass ran"
        );
        assert_eq!(bc.block_tree_len(), 4, "nothing was deleted");

        // The segment's own configuration arriving above it makes it a
        // candidate, which validates.
        let cfg = w4_config_anchor_block(104, b103.view().hash());
        bc.receive_block(cfg.view(), 0);
        assert!(bc.is_ready(), "the segment now names its configuration");
        // Nothing was deleted for the waiting: the one block gone is #100, which
        // the five-block segment's Ready entry released to keep the window at
        // exactly W = 4 (FR48, Story 9.1).
        assert_eq!(
            bc.block_tree_len(),
            4,
            "every block survived the wait; only the window trim released one"
        );
        assert!(
            !bc.block_tree_contains(100, &tail.view().hash()),
            "#100 is the one released"
        );
        for blk in [&b101, &b102, &b103, &cfg] {
            let view = blk.view();
            assert!(bc.block_tree_contains(view.sequence(), &view.hash()));
        }
        assert_eq!(bc.active_snake_chain_window(), Ok((101, 104)));
        assert_eq!(
            bc.current_active_head(),
            Some(104),
            "the active head is the config block that completed the segment"
        );
    }

    /// AC4 + AC5 — the Ready transition commits the configuration durably exactly
    /// once, and deletes every disagreeing chain-config block in the tree,
    /// transitively, without touching the active chain.
    ///
    /// The side branch is built to be the hard case: it forks at the genesis, its
    /// config block disagrees, and it carries a descendant above that block, so
    /// the cleanup has to be transitive and has to follow up on `chain_heads`.
    #[test]
    fn fr8_ready_locks_durably_and_deletes_disagreeing_config_subtrees() {
        let mut bc = new_unconfigured_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        // Main branch: #0 → cfg A (#1) → cfg A (#2) → cfg A (#3), tip sequence 3.
        // Three blocks carrying *identical* content, which AC3 permits and in
        // fact requires: every in-scope config block must be byte-identical to
        // the tentative. They are chain-config blocks rather than transfers
        // because the candidate is genesis-anchored, where there is no pre-seed
        // trust zone — a transfer between unregistered nodes would fail FR6 as an
        // unseeded actor, and this test is not about that.
        let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
        let main_2 = chain_config_anchor_block(2, cfg_a.view().hash());
        let main_3 = chain_config_anchor_block(3, main_2.view().hash());
        // Side branch off the genesis: cfg B (#1') → tx (#2'). Tip sequence 2, so
        // FR2 selection prefers the main branch's higher tip. The side branch is
        // never validated (it is not the candidate), so its transfer block's
        // unseeded actors are irrelevant — it is here to prove the cleanup is
        // transitive and follows up on `chain_heads`.
        let cfg_b = chain_config_block_from(1, genesis.view().hash(), &mut alt_config_builder());
        let side_2 = linked_transfer_block(2, cfg_b.view().hash());

        // Config A first, so it is the tentative (AC2). Everything is admitted
        // while still orphaned — window-anchored segments far below W = 16, so no
        // FR2 trigger — and the genesis comes last to connect them all at once.
        for block in [&cfg_a, &main_2, &main_3, &cfg_b, &side_2] {
            let (outcome, _) = bc.receive_block(block.view(), 0);
            assert_eq!(
                outcome,
                ReceiveBlockOutcome::AcceptedSilently,
                "every block is admitted before the genesis connects them"
            );
        }
        assert_eq!(
            bc.chain_config.tentative_content(),
            Some(content_of(&cfg_a)),
            "config A is the tentative; config B is retained but does not override"
        );

        let (outcome, _) = bc.receive_block(genesis.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

        // AC4: the commitment is durable, over config A's content.
        assert!(bc.is_ready(), "the main candidate validates → Ready");
        assert!(bc.chain_config.is_durable_locked(), "FR8 lock engaged");
        assert_eq!(
            bc.chain_config.durable_content(),
            Some(content_of(&cfg_a)),
            "the locked content is the candidate's own"
        );
        // AC5: config B and its descendant are gone, transitively.
        assert!(
            bc.blocks.find(1, &cfg_b.view().hash()).is_none(),
            "the disagreeing config block is deleted"
        );
        assert!(
            bc.blocks.find(2, &side_2.view().hash()).is_none(),
            "and so is its descendant, which is unverifiable without it"
        );
        // The active chain is untouched — a consequence of AC3, not a precaution.
        for (seq, block) in [(0u32, &genesis), (1, &cfg_a), (2, &main_2), (3, &main_3)] {
            let idx = bc
                .blocks
                .find(seq, &block.view().hash())
                .unwrap_or_else(|| panic!("main-branch block at sequence {seq} survives"));
            assert!(
                bc.blocks
                    .get(idx)
                    .is_some_and(|entry| entry.is_on_active_chain()),
                "main-branch block at sequence {seq} is on the active chain"
            );
        }
        assert_eq!(bc.blocks.len(), 4, "exactly the active chain remains");
    }

    /// AC4 — a second durable commitment is **refused**, not silently re-applied.
    /// The set-once guarantee is the configuration module's (Story 5.7); this
    /// asserts the lifecycle does not paper over it.
    #[test]
    fn fr8_second_durable_commit_is_refused() {
        let mut bc = new_unconfigured_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        bc.receive_block(cfg.view(), 0);
        bc.receive_block(genesis.view(), 0);
        assert!(bc.chain_config.is_durable_locked(), "locked once");
        let cfg_idx = bc
            .blocks
            .find(1, &cfg.view().hash())
            .expect("config block on the active chain");

        assert!(
            bc.commit_durable_chain_config(cfg_idx).is_err(),
            "the lock is set-once for the lifetime of the chain"
        );
        assert!(
            bc.chain_config.is_durable_locked(),
            "and the refusal leaves the existing lock intact"
        );
        // The lifecycle refuses above because the storage seam is itself set-once,
        // so that assertion alone never reaches the module. Assert the module's
        // own refusal directly — it is the guarantee AC4 actually names, and the
        // one this story must not paper over.
        assert!(
            bc.chain_config.promote_durable().is_err(),
            "the configuration module refuses a second promotion in its own right"
        );
    }

    /// AC6 — on a final-check content mismatch the node adopts the candidate's
    /// own first in-scope config content and re-runs the pass over the same
    /// candidate, in the same call, reaching Ready without waiting for another
    /// admission. The superseded tentative's block is removed.
    #[test]
    fn fr8_mismatch_adopts_candidate_content_and_reruns_in_one_call() {
        let mut bc = new_unconfigured_test_chain();
        // An off-candidate config block arrives first and becomes the tentative.
        // Sequence 500, alone: a length-1 window-anchored segment never qualifies
        // under FR2, so it is never itself a candidate.
        let stray = chain_config_block_from(500, [0xEE; 32], &mut alt_config_builder());
        bc.receive_block(stray.view(), 0);
        assert_eq!(
            bc.chain_config.tentative_content(),
            Some(content_of(&stray)),
            "the stray block supplied the tentative configuration"
        );

        let genesis = node_transfer_block(0, 0, 0, 0);
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        bc.receive_block(cfg.view(), 0);
        let (outcome, _) = bc.receive_block(genesis.view(), 0);

        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert!(
            bc.is_ready(),
            "the adopt-retry validated the same candidate inside the same call"
        );
        assert_eq!(
            bc.chain_config.durable_content(),
            Some(content_of(&cfg)),
            "the chain's own configuration was adopted and locked, not the stray's"
        );
        assert!(
            bc.blocks.find(500, &stray.view().hash()).is_none(),
            "the superseded tentative's block is removed"
        );
        assert_eq!(bc.blocks.len(), 2, "genesis + the chain's config block");
    }

    /// AC6 — a candidate carrying **two differing** config contents can never
    /// satisfy AC3 under any adoption, so it takes the hard FR5 rollback with no
    /// adopt-retry. This is the one shape that could otherwise oscillate
    /// adopt→mismatch→adopt, so the test's termination is part of what it proves.
    ///
    /// The arrival order is the adversarial one: the *upper* config block loads
    /// the tentative first, so the run is `pass → adopt → pass → FR5 → pass`,
    /// exercising both single-use retry tokens in one call — the worst case the
    /// three-pass bound permits, and no more.
    #[test]
    fn fr8_two_differing_config_contents_take_the_hard_rollback() {
        let mut bc = new_unconfigured_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
        let cfg_b = chain_config_block_from(2, cfg_a.view().hash(), &mut alt_config_builder());

        // B first: it becomes the tentative, so the pass mismatches at A — the
        // candidate's *first* config block — and the adopt path fires.
        bc.receive_block(cfg_b.view(), 0);
        assert_eq!(
            bc.chain_config.tentative_content(),
            Some(content_of(&cfg_b)),
            "the upper config block supplied the tentative"
        );
        bc.receive_block(cfg_a.view(), 0);
        let (outcome, _) = bc.receive_block(genesis.view(), 0);

        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        // B is exact evidence of non-compliance once A is adopted, so FR5 deletes
        // it; the shortened candidate then validates on the Story-5.5 retry.
        assert!(
            bc.blocks.find(2, &cfg_b.view().hash()).is_none(),
            "the second, disagreeing config block is deleted as exact evidence"
        );
        assert!(bc.is_ready(), "the shortened candidate validates");
        assert_eq!(
            bc.chain_config.durable_content(),
            Some(content_of(&cfg_a)),
            "the chain locked on its first in-scope configuration"
        );
        assert_eq!(bc.blocks.len(), 2, "genesis + config A");
    }

    /// AC8 — when an FR5 recovery deletes the subtree containing the tentatively
    /// loaded config block, the tentative configuration goes with it: the
    /// justification for holding it is gone.
    #[test]
    fn fr8_recovery_unloads_a_deleted_tentative_configuration() {
        let mut bc = new_unconfigured_test_chain();
        let cfg = chain_config_anchor_block(100, [0xAB; 32]);
        bc.receive_block(cfg.view(), 0);
        let cfg_idx = bc
            .blocks
            .find(100, &cfg.view().hash())
            .expect("config block retained");
        assert!(bc.chain_config.active_configuration().is_some());

        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(
            ProcessingError::Invalid {
                block_idx: cfg_idx,
                reason: ValidationReason::PreviousHashMismatch,
            },
            cfg_idx,
        );

        assert!(bc.blocks.get(cfg_idx).is_none(), "the block was deleted");
        assert!(
            bc.chain_config.active_configuration().is_none(),
            "the tentative configuration is discarded with its block"
        );
        assert_eq!(bc.tentative_config_block_idx, NONE_REF);
    }

    /// AC8 — and only then. A recovery whose delete-set does not contain the
    /// tentative's block leaves the configuration loaded.
    #[test]
    fn fr8_recovery_keeps_a_surviving_tentative_configuration() {
        let mut bc = new_unconfigured_test_chain();
        let cfg = chain_config_anchor_block(100, [0xAB; 32]);
        bc.receive_block(cfg.view(), 0);
        let cfg_idx = bc
            .blocks
            .find(100, &cfg.view().hash())
            .expect("config block retained");
        // An unrelated orphan on its own branch — deleting it cannot reach the
        // config block.
        let other = node_transfer_block(200, 3, 199, 7);
        bc.receive_block(other.view(), 0);
        let other_idx = bc
            .blocks
            .find(200, &other.view().hash())
            .expect("other block retained");

        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(
            ProcessingError::Invalid {
                block_idx: other_idx,
                reason: ValidationReason::PreviousHashMismatch,
            },
            other_idx,
        );

        assert!(
            bc.blocks.get(cfg_idx).is_some(),
            "the config block survives"
        );
        assert_eq!(
            bc.chain_config.tentative_content(),
            Some(content_of(&cfg)),
            "an untouched tentative configuration stays loaded"
        );
        assert_eq!(bc.tentative_config_block_idx, cfg_idx);
    }

    /// AC8 — a **durable-locked** configuration is never unloaded. The lock is
    /// irrevocable for the lifetime of the chain, and the module enforces that
    /// itself, which is why the recovery needs no lock check of its own.
    #[test]
    fn fr8_recovery_never_unloads_a_durable_configuration() {
        let mut bc = new_test_chain(); // durably locked on the base override set
        let cfg = chain_config_anchor_block(100, [0xAB; 32]);
        bc.receive_block(cfg.view(), 0);
        let cfg_idx = bc
            .blocks
            .find(100, &cfg.view().hash())
            .expect("a matching config block is admitted post-lock");

        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.recover_from_failed_pass(
            ProcessingError::Invalid {
                block_idx: cfg_idx,
                reason: ValidationReason::PreviousHashMismatch,
            },
            cfg_idx,
        );

        assert!(bc.blocks.get(cfg_idx).is_none(), "the block was deleted");
        assert!(
            bc.chain_config.is_durable_locked(),
            "the FR8 lock survives the deletion of the block that carried it"
        );
    }

    /// AC9 — the commitment lifecycle is wall-clock-independent (FR63/NFR5): the
    /// same block set replayed under two clocks produces the same lock, the same
    /// cleanup delete-set and the same tree.
    #[test]
    fn fr8_commitment_ignores_now() {
        fn run(now: u64) -> ([bool; 16], bool, bool, usize) {
            let mut bc = new_unconfigured_test_chain();
            let genesis = node_transfer_block(0, 0, 0, 0);
            let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
            let cfg_b =
                chain_config_block_from(1, genesis.view().hash(), &mut alt_config_builder());
            let side = linked_transfer_block(2, cfg_b.view().hash());
            let main_2 = chain_config_anchor_block(2, cfg_a.view().hash());
            let main_3 = chain_config_anchor_block(3, main_2.view().hash());
            for (step, block) in [&cfg_a, &main_2, &main_3, &cfg_b, &side, &genesis]
                .into_iter()
                .enumerate()
            {
                bc.receive_block(block.view(), now.saturating_add(step as u64 * 1_000));
            }
            let mut occupied = [false; 16];
            for (slot, flag) in occupied.iter_mut().enumerate() {
                *flag = bc.blocks.get(slot as u32).is_some();
            }
            (
                occupied,
                bc.is_ready(),
                bc.chain_config.is_durable_locked(),
                bc.blocks.len(),
            )
        }
        let baseline = run(0);
        assert_eq!(
            baseline,
            run(5_000_000),
            "the FR8 lock and the AC5 cleanup are identical across wall-clocks"
        );
        // Non-vacuity: the run really reached the lock and really cleaned up.
        assert!(
            baseline.1 && baseline.2,
            "the replay reached the durable lock"
        );
        assert_eq!(baseline.3, 4, "the side branch was cleaned up");
    }

    /// AC9 — and it is arrival-order-independent where FR8 requires it: whichever
    /// config block happens to load the tentative first, the node converges on
    /// the same locked configuration and the same retained tree. The two orders
    /// get there by different routes — one locks directly (AC5 cleans up), the
    /// other adopts and re-runs (AC6 removes the superseded block) — and that the
    /// destination is identical is the property.
    #[test]
    fn fr8_lock_is_arrival_order_independent() {
        fn run(config_a_first: bool) -> (bool, usize, [u8; 2]) {
            let mut bc = new_unconfigured_test_chain();
            let genesis = node_transfer_block(0, 0, 0, 0);
            let cfg_a = chain_config_anchor_block(1, genesis.view().hash());
            let cfg_b =
                chain_config_block_from(1, genesis.view().hash(), &mut alt_config_builder());
            let side = linked_transfer_block(2, cfg_b.view().hash());
            let main_2 = chain_config_anchor_block(2, cfg_a.view().hash());
            let main_3 = chain_config_anchor_block(3, main_2.view().hash());
            // Only the order of the two *config* blocks differs; the main branch
            // is the FR2 winner either way (tip sequence 3 against 2).
            let order: [&Block; 6] = if config_a_first {
                [&cfg_a, &cfg_b, &side, &main_2, &main_3, &genesis]
            } else {
                [&cfg_b, &side, &cfg_a, &main_2, &main_3, &genesis]
            };
            for block in order {
                bc.receive_block(block.view(), 0);
            }
            // The locked content as a fingerprint: its first two bytes are the
            // `config_value_count`, which is 1 for the base override set config A
            // carries and 2 for config B's.
            let locked = bc
                .chain_config
                .durable_content()
                .map(|content| [content[0], content[1]])
                .unwrap_or([0xFF, 0xFF]);
            (bc.is_ready(), bc.blocks.len(), locked)
        }

        let a_first = run(true);
        assert_eq!(
            a_first,
            run(false),
            "both arrival orders converge on the same lock and the same tree"
        );
        assert_eq!(
            a_first,
            (true, 4, [1, 0]),
            "and they converge on config A — the candidate's own — with the side branch gone"
        );
    }

    /// FR3 candidate chain-config preload — the ordering that keeps a stale
    /// tentative from costing a valid block.
    ///
    /// PRD FR3 requires the candidate's *own* configuration content to be the
    /// basis of every chain-config-derived check in the forward traversal. This
    /// is the scenario where that ordering is load-bearing rather than
    /// decorative, and every step of it is reachable:
    ///
    /// 1. A large balance block is admitted while the node holds no
    ///    configuration, so intake measures it against the framing ceiling.
    /// 2. A stray, off-candidate chain-config block then loads a tentative that
    ///    declares a *small* `block_size_limit`.
    /// 3. The candidate completes, and its own chain-config block declares the
    ///    default limit — under which the balance block is perfectly legal.
    ///
    /// With the preload, the divergence is caught before a single candidate block
    /// is validated: the node adopts the candidate's content and re-runs, and the
    /// balance block is measured against the limit its own chain set. Without it,
    /// the forward walk reaches the balance block first and deletes it as
    /// `BlockTooLarge` under a limit no block on that chain was ever subject to.
    #[test]
    fn fr3_preload_prevents_a_stale_tentative_from_condemning_a_valid_block() {
        let mut bc = new_unconfigured_w4_chain();
        // (1) A balance block bigger than the small limit the stray will declare,
        // admitted while the node is unconfigured.
        // `max_node_id = 9` so the linked transfers' pre-window actors (nodes 7
        // and 9) are inside the derived node-id range; three entries so the block
        // comfortably exceeds the stray's declared limit.
        let big = balance_block(
            100,
            [0xAB; 32],
            &[(1, 500, 0, 0xB1), (2, 300, 0, 0xB2), (3, 100, 0, 0xB3)],
            9,
        );
        assert!(
            big.len() > SMALL_BLOCK_SIZE_LIMIT as usize,
            "the fixture is only meaningful if the block exceeds the stray's limit"
        );
        let b101 = linked_transfer_block(101, big.view().hash());
        let b102 = linked_transfer_block(102, b101.view().hash());
        for block in [&big, &b101, &b102] {
            let (outcome, _) = bc.receive_block(block.view(), 0);
            assert_eq!(
                outcome,
                ReceiveBlockOutcome::AcceptedSilently,
                "admitted while unconfigured, against the framing ceiling"
            );
        }

        // (2) The stray loads a tentative declaring the small limit. Off-candidate
        // and alone, so it is never itself an FR2 candidate.
        let stray = chain_config_block_from(500, [0xEE; 32], &mut small_limit_config_builder(W4));
        bc.receive_block(stray.view(), 0);
        assert!(
            bc.chain_config.tentative_content().is_some(),
            "the stray supplied the tentative configuration"
        );

        // (3) The candidate's own chain-config block completes the segment at
        // W = 4 and triggers FR2.
        let cfg = w4_config_anchor_block(103, b102.view().hash());
        let (outcome, _) = bc.receive_block(cfg.view(), 0);

        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert!(
            bc.blocks.find(100, &big.view().hash()).is_some(),
            "the balance block was never measured against a limit its chain did not set"
        );
        assert!(bc.is_ready(), "the adopt-retry validated the candidate");
        assert_eq!(
            bc.chain_config.durable_content(),
            Some(content_of(&cfg)),
            "the chain locked on its own configuration, not the stray's"
        );
        assert!(
            bc.blocks.find(500, &stray.view().hash()).is_none(),
            "the superseded tentative's block is gone"
        );
    }

    // --- Code-review regressions (2026-09-20) -------------------------------

    /// The acquisition loop must not retry a pass once the recovery has taken the
    /// configuration with it.
    ///
    /// `receive_block` evaluates its "a configuration is loaded" gate once, on
    /// entry. The AC8 step-3b unload can retract the configuration *inside* the
    /// loop — whenever the FR5 delete-set happens to contain the block that
    /// supplied the tentative — and the `Invalid` retry token is still armed at
    /// that point. The retry then runs a whole pass with no configuration at all,
    /// which Story 5.8's FR2 gate exists precisely to prevent.
    ///
    /// What that costs depends on the shape. In this one the unconfigured pass
    /// reaches the Ready path over a candidate carrying no chain-config block,
    /// tripping the AC3 assertion in debug and silently abandoning the transition
    /// in release. In a shape where the pass instead refuses at the first FR37
    /// vote effect, the refusal is `Vote(NotParameterized)` — which carries no
    /// `block_idx`, so the FR5 fallback deletes the **candidate head**: a valid
    /// block destroyed for the node's own missing configuration. The guard is
    /// against re-entering at all, so it covers both.
    ///
    /// The candidate is `[#0 genesis, #1 invalid, #2 chain-config]`, so the
    /// offender's subtree contains the config block and the unload fires.
    #[test]
    fn fr5_retry_stops_when_recovery_unloads_the_configuration() {
        let mut bc = new_unconfigured_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        // Out-of-sequence registration (new_node_id 5, expected 1) — invalid.
        let bad = registration_block(1, genesis.view().hash(), 1, 5, 0xC5);
        let cfg = chain_config_anchor_block(2, bad.view().hash());
        for block in [&cfg, &bad] {
            bc.receive_block(block.view(), 0);
        }
        assert!(
            bc.chain_config.active_configuration().is_some(),
            "the config block supplied a tentative configuration"
        );

        let (outcome, _) = bc.receive_block(genesis.view(), 0);

        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        // The offender and the config block above it are gone, and the unload
        // fired — but the genesis, which is not evidence of anything, survives.
        assert!(
            bc.chain_config.active_configuration().is_none(),
            "the recovery unloaded the tentative with the block that carried it"
        );
        assert!(
            bc.blocks.find(0, &genesis.view().hash()).is_some(),
            "the genesis must not be deleted by a retry the node can no longer run"
        );
        assert_eq!(bc.blocks.len(), 1, "exactly the genesis remains");
        assert!(bc.current_phase() == LifecyclePhase::Collecting);
    }

    /// PRD FR9: a merely-tentative chain-config must not reject an arriving block.
    ///
    /// The block-size limit is a chain-config-derived value, and FR9 says such
    /// values "produce Invalid classification (and downstream deletion) only after
    /// the chain-configuration is durably locked". A stray config block declaring
    /// a tight limit therefore must not cost a joining node the legitimate blocks
    /// of the chain it is actually trying to join — otherwise which blocks a node
    /// retains depends on the order its peers happened to gossip them (AC9).
    #[test]
    fn fr9_tentative_block_size_limit_does_not_reject_at_intake() {
        let mut bc = new_unconfigured_test_chain();
        let stray =
            chain_config_block_from(500, [0xEE; 32], &mut small_limit_config_builder(TEST_W));
        bc.receive_block(stray.view(), 0);
        assert!(
            bc.chain_config.tentative_content().is_some(),
            "the stray declares the tight limit, tentatively"
        );

        let big = balance_block(
            100,
            [0xAB; 32],
            &[(1, 500, 0, 0xB1), (2, 300, 0, 0xB2), (3, 100, 0, 0xB3)],
            9,
        );
        assert!(big.len() > SMALL_BLOCK_SIZE_LIMIT as usize);

        let (outcome, _) = bc.receive_block(big.view(), 0);

        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "a tentative-only size failure must not reject the block (FR9)"
        );
        assert!(
            bc.blocks.find(100, &big.view().hash()).is_some(),
            "and it must be retained in durable storage"
        );
    }

    /// PRD FR9's other half: the deferred enforcement is re-run at the durable
    /// lock, which is one of the two moments FR9 names.
    ///
    /// A candidate that declares a limit its own blocks exceed is not a chain this
    /// node may adopt — but the verdict is reached at the commitment, not while
    /// the configuration is still tentative, and it arrives as an ordinary FR5
    /// rollback with nothing promoted and nothing locked.
    #[test]
    fn fr9_size_limit_is_reevaluated_at_the_durable_lock() {
        let mut bc = new_unconfigured_w4_chain();
        // A four-block window-anchored candidate whose own chain-config declares a
        // limit the balance block at its base exceeds.
        let big = balance_block(
            100,
            [0xAB; 32],
            &[(1, 500, 0, 0xB1), (2, 300, 0, 0xB2), (3, 100, 0, 0xB3)],
            9,
        );
        assert!(big.len() > SMALL_BLOCK_SIZE_LIMIT as usize);
        let b101 = linked_transfer_block(101, big.view().hash());
        let b102 = linked_transfer_block(102, b101.view().hash());
        let cfg =
            chain_config_block_from(103, b102.view().hash(), &mut small_limit_config_builder(W4));
        for block in [&big, &b101, &b102, &cfg] {
            let (outcome, _) = bc.receive_block(block.view(), 0);
            assert_eq!(
                outcome,
                ReceiveBlockOutcome::AcceptedSilently,
                "every block is admitted — the limit is not enforceable yet (FR9)"
            );
        }

        assert!(
            !bc.is_ready(),
            "the re-evaluation at the lock refuses the candidate"
        );
        assert!(
            !bc.chain_config.is_durable_locked(),
            "and nothing was locked: the verdict precedes the commitment"
        );
        assert!(
            bc.blocks.find(100, &big.view().hash()).is_none(),
            "the offending block is the one FR5 deletes"
        );
        assert!(
            bc.current_phase() == LifecyclePhase::Collecting,
            "the FR5 recovery reverted the phase"
        );
    }

    /// PRD FR8: a chain-config block whose content violates a structural bound
    /// "shall not enter durable storage" — unconditionally, not only when it is
    /// the block that happens to load.
    ///
    /// The FR17 gate cannot cover this: it stands down while the configuration is
    /// merely tentative (AC7), which is exactly the window in which a second,
    /// structurally illegal config block can arrive.
    #[test]
    fn fr8_bound_violating_content_is_refused_even_when_not_loading() {
        let mut bc = new_unconfigured_test_chain();
        let first = chain_config_anchor_block(100, [0xAB; 32]);
        bc.receive_block(first.view(), 0);
        assert!(
            bc.chain_config.tentative_content().is_some(),
            "a configuration is already held, so the next one cannot load"
        );

        let illegal = chain_config_block_from(
            101,
            first.view().hash(),
            &mut bound_violating_config_builder(),
        );
        let (outcome, _) = bc.receive_block(illegal.view(), 0);

        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
            "a bound violation is exact evidence whether or not the block loads"
        );
        assert!(
            bc.blocks.find(101, &illegal.view().hash()).is_none(),
            "and it does not enter durable storage"
        );
        assert_eq!(
            bc.chain_config.tentative_content(),
            Some(content_of(&first)),
            "the held configuration is untouched by the refusal"
        );
    }

    // ===================================================================
    // FR59 — restart equivalence (Story 5.10)
    //
    // `MemoryBackend` lives in RAM, so a "power cycle" is modelled the only
    // way it can be: the durable backend is carried into a freshly
    // constructed node while every piece of derived state — tree, heads,
    // projection, configuration — starts empty, exactly as it would after a
    // reboot.
    // ===================================================================

    /// Carries `bc`'s durable storage into a brand-new node. The new node gets a
    /// fresh, *unconfigured* configuration module and an empty tree: everything
    /// it ends up holding, it recovered from the durable footprint.
    fn restart(bc: TestChain) -> TestChain {
        let storage = bc.storage;
        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key should be accepted by the backend");
        let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        new_chain(crypto, storage, chain_config, 5, 0)
    }

    /// Drives an unconfigured node to `Ready` the way the network does: a
    /// genesis plus chain-config blocks, admitted while orphaned so the genesis
    /// connects them all at once. Reaching `Ready` runs the real FR8 durable
    /// commit, which is what puts the configuration into the control plane —
    /// the durable evidence the restart later reads back.
    fn node_ready_from_the_mesh() -> (TestChain, Block, Block) {
        let mut bc = new_unconfigured_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        for block in [&cfg, &genesis] {
            let (outcome, _) = bc.receive_block(block.view(), 0);
            assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        }
        assert!(bc.is_ready(), "precondition: the node reached Ready");
        assert!(
            bc.chain_config.is_durable_locked(),
            "precondition: reaching Ready performed the FR8 durable commit"
        );
        (bc, genesis, cfg)
    }

    /// AC1/AC3 precondition, proven end to end through the real storage seam:
    /// a block shorter than a slot comes back padded, and only the structural
    /// length recovery still finds the block inside it. Without this, every
    /// hash the rebuild computes would be wrong.
    #[test]
    fn fr59_a_short_block_survives_the_storage_round_trip() {
        let (_, mut storage, _) = test_backends();
        let block = node_transfer_block(0, 7, 0, 7);
        let exact = block.serialized_bytes();
        assert!(
            exact.len() < MAX_BLOCK_SIZE,
            "precondition: shorter than a slot"
        );
        storage.save_block(0, &block).ok().expect("save");

        let read_back = storage.read_block(0).ok().expect("read");
        assert_eq!(
            read_back.len(),
            MAX_BLOCK_SIZE,
            "the backend returns the whole padded slot - this is the problem FR59 faces"
        );

        let view = TestChain::exact_view(read_back.serialized_bytes())
            .expect("the exact length is recoverable");
        assert_eq!(
            view.serialized_bytes(),
            exact,
            "byte-identical to what was saved"
        );
        assert_eq!(view.hash(), block.view().hash(), "and so is the hash");
        assert_ne!(
            read_back.view().hash(),
            block.view().hash(),
            "while the padded read-back hashes to something else entirely"
        );
    }

    /// AC5/AC2 — the whole spine: rebuild from durable blocks, restore the FR8
    /// lock from the control plane, re-run FR2/FR3/FR6 and land in `Ready`.
    #[test]
    fn fr59_restart_rebuilds_and_reaches_ready() {
        let (bc, genesis, cfg) = node_ready_from_the_mesh();
        let active_before = bc.current_active_head();

        let mut restarted = restart(bc);
        assert!(
            restarted.chain_config.active_configuration().is_none(),
            "precondition: the restarted node starts with nothing"
        );

        let (outcome, _) = restarted.initialize_from_storage(500);

        assert_eq!(outcome, InitOutcome::ResumedReady);
        assert!(
            restarted.is_ready(),
            "FR4 reached through the ordinary spine"
        );
        assert!(
            restarted.chain_config.is_durable_locked(),
            "AC2 - the FR8 lock is restored from the control plane"
        );
        assert_eq!(
            restarted.current_active_head(),
            active_before,
            "the same active chain is re-derived"
        );
        assert!(
            restarted.blocks.find(0, &genesis.view().hash()).is_some()
                && restarted.blocks.find(1, &cfg.view().hash()).is_some(),
            "both durable blocks are back in the tree, indexed by (sequence, hash)"
        );
    }

    /// AC5 — no qualifying candidate means the node simply stays `Collecting`
    /// and keeps its blocks, which FR59 step (4) states explicitly.
    #[test]
    fn fr59_restart_stays_collecting_without_a_qualifying_candidate() {
        let mut bc = new_unconfigured_test_chain();
        // A lone orphan far above the window: admitted, but neither
        // genesis-anchored nor long enough to satisfy FR2.
        let cfg = chain_config_anchor_block(100, [0xAB; 32]);
        let (outcome, _) = bc.receive_block(cfg.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

        let mut restarted = restart(bc);
        let (outcome, _) = restarted.initialize_from_storage(500);

        assert_eq!(outcome, InitOutcome::ResumedCollecting);
        assert_eq!(restarted.current_phase(), LifecyclePhase::Collecting);
        assert_eq!(restarted.blocks.len(), 1, "the retained block survived");
    }

    /// AC8 — the equivalence the story exists to deliver: a restarted node and a
    /// fresh node fed the same blocks agree on the active chain, the phase, and
    /// the locked configuration.
    #[test]
    fn fr59_restart_is_equivalent_to_a_fresh_node_fed_the_same_blocks() {
        let (bc, genesis, cfg) = node_ready_from_the_mesh();
        let mut restarted = restart(bc);
        let (outcome, _) = restarted.initialize_from_storage(500);
        assert_eq!(outcome, InitOutcome::ResumedReady);

        // The comparison node never restarts: it receives the same two blocks.
        let mut fresh = new_unconfigured_test_chain();
        for block in [&cfg, &genesis] {
            let (outcome, _) = fresh.receive_block(block.view(), 0);
            assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        }

        assert_eq!(restarted.is_ready(), fresh.is_ready());
        assert_eq!(restarted.current_active_head(), fresh.current_active_head());
        assert_eq!(restarted.blocks.len(), fresh.blocks.len());
        // AC8 names the projection and the chain_heads set explicitly, and the
        // review found that omitting them hid a real bug: every rebuilt Stored
        // head had lost its missing-parent hash, which a chain_heads comparison
        // would have caught immediately.
        assert_eq!(
            restarted.chain_heads.count(),
            fresh.chain_heads.count(),
            "AC8 - the same chain_heads set"
        );
        assert_eq!(
            restarted.node_info.max_known_node_id(),
            fresh.node_info.max_known_node_id(),
            "AC8 - the same derived projection"
        );
        assert_eq!(
            restarted.chain_config.durable_content(),
            fresh.chain_config.durable_content(),
            "both committed the same configuration"
        );
        for (sequence, hash) in [(0u32, genesis.view().hash()), (1u32, cfg.view().hash())] {
            assert_eq!(
                restarted.blocks.find(sequence, &hash).is_some(),
                fresh.blocks.find(sequence, &hash).is_some(),
                "the two trees hold the same blocks"
            );
        }
    }

    /// AC3 — durable slots are not necessarily contiguous, so the scan must run
    /// the whole capacity rather than stopping at the first empty slot. A node
    /// that stopped early would silently lose its chain.
    #[test]
    fn fr59_restart_scan_does_not_stop_at_the_first_empty_slot() {
        let (_, mut storage, _) = test_backends();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let cfg = chain_config_anchor_block(1, genesis.view().hash());
        // Deliberately leaving slot 0 empty and scattering the blocks.
        storage.save_block(1, &genesis).ok().expect("save");
        storage.save_block(3, &cfg).ok().expect("save");

        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let mut bc = new_chain(
            crypto,
            storage,
            empty_chain_config(TestChain::BUILD_LIMITS),
            5,
            0,
        );
        let (_, _) = bc.initialize_from_storage(500);

        assert_eq!(bc.blocks.len(), 2, "both scattered blocks were found");
        assert!(bc.blocks.get(1).is_some() && bc.blocks.get(3).is_some());
        assert!(
            bc.blocks.get(0).is_none() && bc.blocks.get(2).is_none(),
            "blocks land at their own durable index, never compacted"
        );
    }

    /// AC3 — durable order is not topological. A parent written to a *higher*
    /// slot than its child must still be linked, which is why linkage is a
    /// second pass over the completed table rather than done inline.
    #[test]
    fn fr59_restart_links_parents_stored_after_their_children() {
        let (_, mut storage, _) = test_backends();
        let genesis = node_transfer_block(0, 0, 0, 0);
        let child = chain_config_anchor_block(1, genesis.view().hash());
        // Child first, parent second — the order a one-pass rebuild would break on.
        storage.save_block(0, &child).ok().expect("save");
        storage.save_block(1, &genesis).ok().expect("save");

        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let mut bc = new_chain(
            crypto,
            storage,
            empty_chain_config(TestChain::BUILD_LIMITS),
            5,
            0,
        );
        let (_, _) = bc.initialize_from_storage(500);

        let child_idx = bc
            .blocks
            .find(1, &child.view().hash())
            .expect("the child is in the tree");
        let parent_idx = bc
            .blocks
            .find(0, &genesis.view().hash())
            .expect("the parent is in the tree");
        assert_eq!(
            bc.blocks.get(child_idx).map(|entry| entry.parent_ref()),
            Some(parent_idx),
            "the child resolved to its parent despite the inverted slot order"
        );
    }

    /// AC7 — a retained side branch survives the restart with its fork point
    /// intact; FR20 forbids silently collapsing it.
    #[test]
    fn fr59_restart_preserves_side_branches() {
        let mut bc = new_unconfigured_test_chain();
        // A fork that survives to be tested: the branch root is itself an orphan
        // far above the window, so no FR2 candidate ever qualifies and neither
        // the FR5 recovery nor the FR8 lock-time cleanup can prune a branch
        // before the restart. The two tips differ in payload type, which is what
        // makes them distinct blocks at the same sequence rather than duplicates.
        let root = linked_transfer_block(100, [0xAB; 32]);
        let tip_a = linked_transfer_block(101, root.view().hash());
        let tip_b = chain_config_anchor_block(101, root.view().hash());
        for block in [&root, &tip_a, &tip_b] {
            let (outcome, _) = bc.receive_block(block.view(), 0);
            assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(
            bc.chain_heads.count(),
            2,
            "precondition: the tree really forked, and both tips are tracked"
        );
        assert!(!bc.is_ready(), "precondition: no candidate qualified");

        let mut restarted = restart(bc);
        let (outcome, _) = restarted.initialize_from_storage(500);

        assert_eq!(outcome, InitOutcome::ResumedCollecting);
        assert_eq!(restarted.blocks.len(), 3, "no branch was collapsed (FR20)");
        assert_eq!(
            restarted.chain_heads.count(),
            2,
            "AC7 - both branches are tracked again after the rebuild"
        );

        let root_idx = restarted
            .blocks
            .find(100, &root.view().hash())
            .expect("the fork point is retained");
        for tip in [&tip_a, &tip_b] {
            let tip_idx = restarted
                .blocks
                .find(101, &tip.view().hash())
                .expect("both tips are retained");
            assert_eq!(
                restarted
                    .blocks
                    .get(tip_idx)
                    .map(|entry| entry.parent_ref()),
                Some(root_idx),
                "and both still hang off the same fork point"
            );
        }
    }

    /// AC9 (ratified 2026-09-20) — `StorageTrait` has no delete, so a block
    /// removed before the shutdown is still readable afterwards and comes back.
    /// The rebuilt tree is therefore **not** the pre-shutdown tree; what is
    /// guaranteed is that the node still converges, because the deletion drivers
    /// are deterministic and re-fire.
    #[test]
    fn fr59_restart_resurrects_a_deleted_block_and_still_converges() {
        let (mut bc, genesis, _cfg) = node_ready_from_the_mesh();

        // The post-deletion durable state, reproduced exactly: bytes present in
        // a slot, no entry in the tree. That is all `BlockTable::delete` leaves
        // behind, because `StorageTrait` has no delete and the slot is only
        // reclaimed when a later `save_block` overwrites it.
        let orphaned = linked_transfer_block(5, [0x77; 32]);
        bc.storage.save_block(6, &orphaned).ok().expect("save");
        assert!(
            bc.blocks.find(5, &orphaned.view().hash()).is_none(),
            "precondition: the block is durable but not in the pre-restart tree"
        );
        let head_before = bc.current_active_head();

        let mut restarted = restart(bc);
        let (outcome, _) = restarted.initialize_from_storage(500);

        assert!(
            restarted.blocks.find(5, &orphaned.view().hash()).is_some(),
            "AC9 - a slot that was never overwritten reads back and is admitted again"
        );
        assert_eq!(
            outcome,
            InitOutcome::ResumedReady,
            "and the node still converges on its chain"
        );
        assert_eq!(
            restarted.current_active_head(),
            head_before,
            "the resurrected block did not disturb the active chain"
        );
        assert!(
            restarted.blocks.find(0, &genesis.view().hash()).is_some(),
            "the genesis is still there"
        );
    }

    /// AC3/AC11 — a slot whose payload does not frame coherently is skipped, not
    /// fatal: one bad slot must not cost the node its chain. An approval block
    /// with a populated payload is the reachable case today, because Epic 6 has
    /// not defined that format and `content_length` refuses to guess at it.
    #[test]
    fn fr59_restart_skips_a_slot_whose_length_cannot_be_recovered() {
        let (_, mut storage, _) = test_backends();
        let genesis = node_transfer_block(0, 0, 0, 0);
        storage.save_block(0, &genesis).ok().expect("save");

        let mut raw = [0u8; HEADER_SIZE + 4];
        raw[0] = 1; // version
        raw[13] = moonblokz_chain_types::PAYLOAD_TYPE_APPROVAL;
        raw[HEADER_SIZE] = 0xFF; // a payload with no defined framing
        let undecodable = Block::from_bytes(&raw)
            .ok()
            .expect("structurally parseable, just not measurable");
        storage.save_block(1, &undecodable).ok().expect("save");

        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let mut bc = new_chain(
            crypto,
            storage,
            empty_chain_config(TestChain::BUILD_LIMITS),
            5,
            0,
        );
        let (_, _) = bc.initialize_from_storage(500);

        assert_eq!(bc.blocks.len(), 1, "the unmeasurable slot is skipped");
        assert!(
            bc.blocks.find(0, &genesis.view().hash()).is_some(),
            "and the good block is still recovered"
        );
    }

    /// AC11 — a populated store whose control plane cannot be read is refused,
    /// not panicked on and not silently rebuilt: the node would be reconstructing
    /// a chain without knowing the configuration it was accepted under.
    #[test]
    fn fr59_restart_rejects_a_populated_store_with_an_unreadable_control_plane() {
        // Never `init`ed, so `load_control_data` fails - but `save_block` still
        // writes into the slot region, so blocks are readable.
        let mut storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
        let genesis = node_transfer_block(0, 0, 0, 0);
        storage.save_block(0, &genesis).ok().expect("save");

        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let mut bc = new_chain(
            crypto,
            storage,
            empty_chain_config(TestChain::BUILD_LIMITS),
            5,
            0,
        );

        let (outcome, next) = bc.initialize_from_storage(500);

        assert_eq!(
            outcome,
            InitOutcome::Rejected(RestartRejectReason::ControlPlaneUnreadable)
        );
        assert!(matches!(next, NextCall::Idle));
        assert_eq!(bc.blocks.len(), 0, "nothing was rebuilt");
    }

    /// The same unreadable control plane with an *empty* store is not an error:
    /// that is exactly what a fresh node looks like, and Story 5.1's join path
    /// must keep working.
    #[test]
    fn fr59_an_empty_store_is_a_fresh_join_even_without_a_control_plane() {
        let storage = MemoryBackend::<{ 8 * MAX_BLOCK_SIZE + 8000 }>::new();
        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let mut bc = new_chain(
            crypto,
            storage,
            empty_chain_config(TestChain::BUILD_LIMITS),
            5,
            0,
        );

        let (outcome, next) = bc.initialize_from_storage(500);

        assert_eq!(outcome, InitOutcome::StartedCollecting);
        assert!(matches!(next, NextCall::Idle));
        assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
    }

    /// FR8's tentative phase is not durable, so a node that shut down before the
    /// lock comes back holding nothing — yet its retained tree still carries the
    /// config block it had adopted. Re-adopting is what keeps the restart
    /// equivalent to a fresh node fed the same blocks; without it the node holds
    /// no configuration and cannot run the FR3 derivation at all.
    #[test]
    fn fr59_restart_reestablishes_a_tentative_when_nothing_was_locked() {
        let mut bc = new_unconfigured_test_chain();
        let cfg = chain_config_anchor_block(100, [0xAB; 32]);
        let (outcome, _) = bc.receive_block(cfg.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert!(
            !bc.chain_config.is_durable_locked(),
            "precondition: the configuration is only tentative"
        );
        let mut restarted = restart(bc);
        let (_, _) = restarted.initialize_from_storage(500);

        assert!(
            !restarted.chain_config.is_durable_locked(),
            "a tentative is re-established as a tentative, never promoted by a restart"
        );
        assert_eq!(
            restarted.chain_config.tentative_content(),
            Some(content_of(&cfg)),
            "the same configuration content is held again, from the retained block"
        );
    }

    /// AC10 — the rebuild is a pure function of the durable footprint: the same
    /// store restarted twice yields the same outcome and the same tree.
    #[test]
    fn fr59_restart_is_deterministic() {
        let (bc, _, _) = node_ready_from_the_mesh();

        let mut first = restart(bc);
        let (first_outcome, _) = first.initialize_from_storage(500);
        let first_len = first.blocks.len();
        let first_head = first.current_active_head();
        let first_heads = first.chain_heads.count();
        let first_phase = first.current_phase();
        let mut first_tree = [None; 16];
        for (idx, cell) in first_tree.iter_mut().enumerate() {
            *cell = first
                .blocks
                .get(idx as u32)
                .map(|entry| (entry.sequence(), *entry.hash(), entry.parent_ref()));
        }

        // Restart the *same* durable store a second time, from scratch again.
        let mut second = restart(first);
        // A different `now`: it must not influence the reconstruction.
        let (second_outcome, _) = second.initialize_from_storage(9_999);

        assert_eq!(first_outcome, second_outcome);
        assert_eq!(first_len, second.blocks.len());
        assert_eq!(first_head, second.current_active_head());
        assert_eq!(
            first_heads,
            second.chain_heads.count(),
            "same chain_heads set"
        );
        assert_eq!(first_phase, second.current_phase(), "same phase trace");
        // AC10 asks for the same *tree*, not merely the same block count.
        for idx in 0..16u32 {
            assert_eq!(
                first_tree[idx as usize],
                second.blocks.get(idx).map(|entry| (
                    entry.sequence(),
                    *entry.hash(),
                    entry.parent_ref()
                )),
                "slot {idx} must rebuild identically"
            );
        }
    }

    // ---- Review regressions (2026-09-21) --------------------------------

    /// **Review finding, confirmed by execution.** Every rebuilt Stored head used
    /// to come back with an all-zero `missing_parent_hash`, so FR19 emitted
    /// parent-recovery requests for a hash that can never resolve — for the
    /// lifetime of the node. Asserted through the observable outbound request
    /// rather than the cache field, which is what a peer would actually receive.
    #[test]
    fn fr59_restart_preserves_the_missing_parent_hash_of_a_stored_head() {
        let mut bc = new_unconfigured_test_chain();
        let orphan = chain_config_anchor_block(100, [0xAB; 32]);
        let (outcome, _) = bc.receive_block(orphan.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);

        let mut restarted = restart(bc);
        let (_, _) = restarted.initialize_from_storage(500);

        let (tick, _) = restarted.on_tick(1_000_000);
        match tick {
            TickOutcome::SendParentRecoveryRequest(request) => {
                assert_eq!(
                    request.missing_parent_hash(),
                    &[0xAB; 32],
                    "the restarted node must request the parent the branch actually names"
                );
            }
            _ => panic!("a Stored head should schedule FR19 parent recovery after a restart"),
        }
    }

    /// **Review finding, confirmed by execution.** The single-genesis rule lives
    /// in `tier1_admit`, which the rebuild bypasses, so two distinct sequence-0
    /// blocks both entered the tree — a state live intake cannot produce.
    #[test]
    fn fr59_restart_admits_at_most_one_genesis() {
        let (_, mut storage, _) = test_backends();
        let genesis_a = node_transfer_block(0, 0, 0, 0);
        let genesis_b = node_transfer_block(0, 7, 0, 7);
        assert_ne!(
            genesis_a.view().hash(),
            genesis_b.view().hash(),
            "precondition: two distinct sequence-0 blocks"
        );
        storage.save_block(0, &genesis_a).ok().expect("save");
        storage.save_block(1, &genesis_b).ok().expect("save");

        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let mut bc = new_chain(
            crypto,
            storage,
            empty_chain_config(TestChain::BUILD_LIMITS),
            5,
            0,
        );
        let (_, _) = bc.initialize_from_storage(500);

        let genesis_count = (0..16u32)
            .filter(|idx| {
                bc.blocks
                    .get(*idx)
                    .is_some_and(|entry| entry.sequence() == 0)
            })
            .count();
        assert_eq!(
            genesis_count, 1,
            "the rebuild must honour the single-genesis rule that tier1_admit enforces"
        );
        assert!(
            bc.blocks.find(0, &genesis_a.view().hash()).is_some(),
            "first by index wins, matching the live first-come rule"
        );
    }

    /// `initialize_from_storage` is a one-shot boot step. A second call used to
    /// be guarded only by `debug_assert!`s, which compile out in exactly the
    /// release builds that run on the device.
    #[test]
    fn fr59_a_second_initialize_from_storage_is_refused() {
        let (bc, _, _) = node_ready_from_the_mesh();
        let mut restarted = restart(bc);
        let (first, _) = restarted.initialize_from_storage(500);
        assert_eq!(first, InitOutcome::ResumedReady);
        let blocks_after_first = restarted.blocks.len();

        let (second, _) = restarted.initialize_from_storage(600);

        assert_eq!(
            second,
            InitOutcome::Rejected(RestartRejectReason::AlreadyInitialized)
        );
        assert_eq!(
            restarted.blocks.len(),
            blocks_after_first,
            "the refused call must not have touched the tree"
        );
    }

    /// AC11's second trigger: a store whose slots are all unreadable is damaged,
    /// not empty, and must not be reported as a fresh join — that would discard
    /// the node's whole chain silently.
    #[test]
    fn fr59_a_store_whose_every_slot_is_corrupt_is_refused() {
        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let mut slot = core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 16, 4, 16>>::uninit();
        let bc = Blockchain::<_, _, _, 16, 16, 16, 4, 16>::init(
            &mut slot,
            crypto,
            CorruptSlotsStorage,
            chain_config,
            5,
            node_zero,
            0,
        );

        let (outcome, _) = bc.initialize_from_storage(500);

        assert_eq!(
            outcome,
            InitOutcome::Rejected(RestartRejectReason::NoUsableTree)
        );
        assert_eq!(bc.blocks.len(), 0);
    }

    /// The irrevocable FR8/FR54 lock must not be taken on the control plane's
    /// word alone: the block it carries is verified through the same FR7 gate
    /// the revocable tentative path uses (review decision, 2026-09-21).
    #[test]
    fn fr59_a_control_plane_config_failing_fr7_is_refused() {
        let (_, mut storage, _) = test_backends();
        // A chain-config block whose content signature is not node #0's.
        let mut forged = chain_config_anchor_block(1, [0u8; 32]);
        let tampered = {
            let mut bytes = [0u8; MAX_BLOCK_SIZE];
            let exact = forged.serialized_bytes();
            bytes[..exact.len()].copy_from_slice(exact);
            // Flip a byte inside the content region, invalidating the signature
            // over it while leaving the envelope framing intact.
            bytes[HEADER_SIZE + 2] ^= 0xFF;
            Block::from_bytes(&bytes[..exact.len()])
                .ok()
                .expect("still structurally a block")
        };
        forged = tampered;
        storage
            .set_chain_configuration(&forged)
            .ok()
            .expect("control plane accepts it - storage does not verify signatures");
        let genesis = node_transfer_block(0, 0, 0, 0);
        storage.save_block(0, &genesis).ok().expect("save");

        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let mut bc = new_chain(
            crypto,
            storage,
            empty_chain_config(TestChain::BUILD_LIMITS),
            5,
            0,
        );

        let (outcome, _) = bc.initialize_from_storage(500);

        assert_eq!(
            outcome,
            InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable)
        );
        assert!(
            !bc.chain_config.is_durable_locked(),
            "an unverifiable configuration must never become an irrevocable lock"
        );
    }

    /// AC9's convergence argument named the FR8 lock-time cleanups, but they sit
    /// behind `if !is_durable_locked()` in the spine and so never ran on a
    /// restart. An off-chain mismatching chain-config block survived forever.
    #[test]
    fn fr59_restart_cleans_up_an_off_chain_mismatching_config_block() {
        let (mut bc, _, _) = node_ready_from_the_mesh();
        // Validly signed by node #0, but carrying different content from the
        // configuration the chain locked. The live path refuses it outright.
        let mismatching = chain_config_block_from(100, [0xAB; 32], &mut alt_config_builder());
        let (live, _) = bc.receive_block(mismatching.view(), 0);
        assert_ne!(
            live,
            ReceiveBlockOutcome::AcceptedSilently,
            "precondition: the live path refuses a post-lock mismatching config"
        );
        // Plant it directly in a durable slot, as a pre-lock session would have.
        bc.storage.save_block(6, &mismatching).ok().expect("save");

        let mut restarted = restart(bc);
        let (outcome, _) = restarted.initialize_from_storage(500);

        assert_eq!(outcome, InitOutcome::ResumedReady);
        assert!(
            restarted
                .blocks
                .find(100, &mismatching.view().hash())
                .is_none(),
            "the restored lock must re-run its mismatch cleanup over the rebuilt tree"
        );
    }

    // ---- A refused restart must not be ignorable (2026-09-21) ------------

    /// The refusal only protects the chain if the module stops accepting work.
    /// Before this guard, a caller that ignored `Rejected(_)` kept feeding the
    /// node, and because the rebuild left an empty tree over a populated store
    /// the first admission took slot 0 and `save_block` overwrote a durable
    /// block — the node silently destroying the chain it failed to load.
    #[test]
    fn a_refused_restart_stops_accepting_blocks_instead_of_overwriting_the_chain() {
        let (_, mut storage, _) = test_backends();
        // A control-plane configuration whose content signature no longer
        // verifies, so the restart refuses with `ChainConfigUnusable`.
        let cfg = chain_config_anchor_block(1, [0u8; 32]);
        let tampered = {
            let mut bytes = [0u8; MAX_BLOCK_SIZE];
            let exact = cfg.serialized_bytes();
            bytes[..exact.len()].copy_from_slice(exact);
            bytes[HEADER_SIZE + 2] ^= 0xFF;
            Block::from_bytes(&bytes[..exact.len()])
                .ok()
                .expect("still structurally a block")
        };
        storage
            .set_chain_configuration(&tampered)
            .ok()
            .expect("the control plane does not verify signatures");
        let genesis = node_transfer_block(0, 0, 0, 0);
        let durable_hash = genesis.view().hash();
        storage.save_block(0, &genesis).ok().expect("save");

        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let mut bc = new_chain(
            crypto,
            storage,
            empty_chain_config(TestChain::BUILD_LIMITS),
            5,
            0,
        );
        let (outcome, _) = bc.initialize_from_storage(500);
        assert_eq!(
            outcome,
            InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable)
        );

        // The caller ignores the refusal and keeps feeding the node.
        let incoming = chain_config_anchor_block(100, [0xCD; 32]);
        let (admitted, next) = bc.receive_block(incoming.view(), 600);

        assert_eq!(
            admitted,
            ReceiveBlockOutcome::Rejected(RejectReason::Unstorable),
            "an operational refusal - the block may be valid, but this node cannot store anything"
        );
        assert!(matches!(next, NextCall::Idle));
        assert_eq!(bc.blocks.len(), 0, "and nothing entered the tree");

        let slot0 =
            bc.storage.read_block(0).ok().and_then(|block| {
                TestChain::exact_view(block.serialized_bytes()).map(|v| v.hash())
            });
        assert_eq!(
            slot0,
            Some(durable_hash),
            "the durable block the restart could not load is still intact"
        );
    }

    /// The same guard for the other refusal that leaves an unrebuilt store.
    #[test]
    fn a_no_usable_tree_refusal_also_stops_accepting_blocks() {
        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key");
        let node_zero = *crypto.public_key().serialize();
        let mut slot = core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 16, 4, 16>>::uninit();
        let bc = Blockchain::<_, _, _, 16, 16, 16, 4, 16>::init(
            &mut slot,
            crypto,
            CorruptSlotsStorage,
            empty_chain_config(TestChain::BUILD_LIMITS),
            5,
            node_zero,
            0,
        );
        let (outcome, _) = bc.initialize_from_storage(500);
        assert_eq!(
            outcome,
            InitOutcome::Rejected(RestartRejectReason::NoUsableTree)
        );

        let incoming = node_transfer_block(0, 0, 0, 0);
        let (admitted, _) = bc.receive_block(incoming.view(), 600);
        assert_eq!(
            admitted,
            ReceiveBlockOutcome::Rejected(RejectReason::Unstorable)
        );
    }

    /// `AlreadyInitialized` must **not** poison the node: it means the node is
    /// already up and running, and the caller simply asked twice.
    #[test]
    fn a_duplicate_initialize_call_does_not_stop_a_healthy_node() {
        let (bc, _, _) = node_ready_from_the_mesh();
        let mut restarted = restart(bc);
        let (first, _) = restarted.initialize_from_storage(500);
        assert_eq!(first, InitOutcome::ResumedReady);

        let (second, _) = restarted.initialize_from_storage(600);
        assert_eq!(
            second,
            InitOutcome::Rejected(RestartRejectReason::AlreadyInitialized)
        );

        let incoming = linked_transfer_block(7, [0x99; 32]);
        let (admitted, _) = restarted.receive_block(incoming.view(), 700);
        assert_ne!(
            admitted,
            ReceiveBlockOutcome::Rejected(RejectReason::Unstorable),
            "a healthy node must keep working after a spurious second init call"
        );
    }

    // ===================================================================
    // Story 9.1 — snake-chain window mechanics and the FR48 tail drop
    // ===================================================================

    use crate::snake_chain::{TailBinding, TailObligation, tail_drop_binding};

    /// A node-zero genesis bootstrap on a chain whose configuration declares the
    /// window `w` (TestChain capacity 16).
    fn genesis_node_with_window(w: u16) -> TestChain {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        let builder = window_config_builder(w);
        bc.process_genesis(1_000_000_000, builder.content())
            .ok()
            .expect("genesis succeeds");
        bc
    }

    /// A `W4Chain` that went Ready on the window-anchored segment `100..=last`,
    /// its tail block #100 the chain-config block the FR8 final check requires.
    /// Returns the node and the hash of each block, indexed by `seq - 100`.
    fn w4_ready_on_segment(last: u32) -> (W4Chain, [[u8; 32]; 8]) {
        let mut bc = new_w4_chain();
        let mut hashes = [[0u8; 32]; 8];
        let anchor = w4_config_anchor_block(100, [0xAB; 32]);
        hashes[0] = anchor.view().hash();
        bc.tier1_admit(&anchor.view(), &hashes[0], 0)
            .expect("anchor admitted");
        for seq in 101..=last {
            let blk = linked_transfer_block(seq, hashes[(seq - 101) as usize]);
            hashes[(seq - 100) as usize] = blk.view().hash();
            bc.tier1_admit(&blk.view(), &blk.view().hash(), 0)
                .expect("block admitted");
        }
        bc.drive_dominant_chain_acquisition();
        assert!(bc.is_ready(), "precondition: the segment validated");
        (bc, hashes)
    }

    fn slot_of(bc: &W4Chain, seq: u32, hash: &[u8; 32]) -> Option<u32> {
        bc.blocks.find(seq, hash)
    }

    /// Receives `block` as a child of the active head; the Story 6.0 forward
    /// extension makes it the new head and, past `W`, advances the tail.
    fn extend_active_head(bc: &mut W4Chain, block: &Block, now: u64) -> u32 {
        let (outcome, _) = bc.receive_block(block.view(), now);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        let view = block.view();
        let idx = slot_of(bc, view.sequence(), &view.hash()).expect("stored");
        assert_eq!(bc.active_chain_head_idx, idx, "the extension is the head");
        assert_eq!(
            bc.blocks.get(idx).map(|e| e.status()),
            Some(BlockStatus::Active)
        );
        idx
    }

    /// AC10.1 / AC2 — genesis: the tail is block #0 and the window is `(0, 1)`;
    /// with `W > 2` nothing is released (the bootstrap growth phase).
    #[test]
    fn snake_genesis_tail_is_block_zero() {
        let bc = genesis_node_with_window(16);
        assert_eq!(bc.snake_chain_tail_idx, 0);
        assert_eq!(bc.active_snake_chain_window(), Ok((0, 1)));
        assert_eq!(bc.block_tree_len(), 2);
    }

    /// AC2 — `W = 2`: genesis is already `W` long; the tail stays at #0 and
    /// nothing is released.
    #[test]
    fn snake_genesis_at_w_two_releases_nothing() {
        let bc = genesis_node_with_window(2);
        assert_eq!(bc.active_snake_chain_window(), Ok((0, 1)));
        assert_eq!(bc.block_tree_len(), 2);
    }

    /// AC2 — `W = 1` (legal: acceptance only demands `W ≥ 1`): the tail is
    /// block #1 and block #0 is released. Its chain-config replay would be
    /// FR49's business (Story 9.2); the new root requests nothing.
    #[test]
    fn snake_genesis_at_w_one_releases_block_zero() {
        let bc = genesis_node_with_window(1);
        assert_eq!(bc.active_snake_chain_window(), Ok((1, 1)));
        assert_eq!(bc.block_tree_len(), 1);
        assert!(bc.blocks.get(0).is_none(), "block #0's slot is free");
        let tail = bc.blocks.get(1).expect("block #1 survives");
        assert_eq!(tail.parent_ref(), NONE_REF, "unlinked from the freed slot");
        assert!(tail.is_on_active_chain());
        assert!(
            !bc.chain_heads.has_stored_head(),
            "the new root does not request the block it replaced"
        );
    }

    /// AC10.2 / AC3 — Ready entry on a genesis-anchored segment of length
    /// `W + 2` releases exactly two blocks, and the window is `W` long. The
    /// extra blocks are chain-config replays, which FR6 accepts on a
    /// genesis-anchored candidate; the released #1 is one, and goes anyway
    /// (Ratified Decision 4).
    #[test]
    fn snake_ready_entry_on_a_longer_genesis_segment_releases_the_excess() {
        let mut bc = new_w4_chain();
        let genesis = node_transfer_block(0, 3, 0, 7);
        let mut prev = genesis.view().hash();
        bc.tier1_admit(&genesis.view(), &prev, 0)
            .expect("genesis admitted");
        for seq in 1..=5 {
            let cfg = w4_config_anchor_block(seq, prev);
            prev = cfg.view().hash();
            bc.tier1_admit(&cfg.view(), &prev, 0)
                .expect("config admitted");
        }
        bc.drive_dominant_chain_acquisition();
        assert!(bc.is_ready());
        assert_eq!(bc.active_snake_chain_window(), Ok((2, 5)));
        assert_eq!(bc.block_tree_len(), 4, "exactly W blocks remain");
        assert!(bc.blocks.get(0).is_none() && bc.blocks.get(1).is_none());
        let tail = bc.blocks.get(bc.snake_chain_tail_idx).expect("tail");
        assert_eq!(tail.parent_ref(), NONE_REF);
        assert!(tail.is_on_active_chain());
        assert!(!bc.chain_heads.has_stored_head());
    }

    /// AC10.3 — Ready entry on a window-anchored segment of exactly `W`
    /// releases nothing.
    #[test]
    fn snake_ready_entry_on_exactly_w_releases_nothing() {
        let (bc, _) = w4_ready_on_segment(103);
        assert_eq!(bc.active_snake_chain_window(), Ok((100, 103)));
        assert_eq!(bc.block_tree_len(), 4);
        // O-024: the adopted chain's head is Connected, not a Stored head still
        // asking for the anchor's parent below S_tail.
        assert!(!bc.chain_heads.has_stored_head());
    }

    /// Review patch — a released seed source stops naming its slot: the node
    /// stays seeded, and the unrelated block that reuses the slot does not
    /// classify as a seed source.
    #[test]
    fn snake_released_seed_source_does_not_follow_the_slot() {
        let (mut bc, h) = w4_ready_on_segment(103);
        let slot_100 = slot_of(&bc, 100, &h[0]).expect("#100");
        let key = *bc.crypto.public_key().serialize();
        bc.node_info.seed_node(1, &key, 0, slot_100);
        let b104 = w4_config_anchor_block(104, h[3]);
        extend_active_head(&mut bc, &b104, 0);
        assert_eq!(
            bc.active_snake_chain_window(),
            Ok((101, 104)),
            "#100 released"
        );
        assert!(bc.node_info.is_seeded(1), "the node stays seeded");
        assert!(bc.node_info.key_is_registered(&key));
        // The next admission reuses the freed slot.
        let orphan = node_transfer_block(106, 3, 105, 7);
        let (outcome, _) = bc.receive_block(orphan.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(slot_of(&bc, 106, &orphan.view().hash()), Some(slot_100));
        assert_eq!(
            classify_tail_drop(&bc.blocks, &bc.node_info, slot_100),
            Ok(TailObligation::None),
            "the reused slot is not anyone's seed source"
        );
    }

    /// Review patch — the release step refuses a tail that is not the active
    /// chain's root, at runtime.
    #[test]
    fn snake_advance_refuses_a_tail_that_is_not_the_root() {
        let (mut bc, h) = w4_ready_on_segment(103);
        let b104 = w4_config_anchor_block(104, h[3]);
        extend_active_head(&mut bc, &b104, 0);
        let slot_102 = slot_of(&bc, 102, &h[2]).expect("#102");
        let real_tail = bc.snake_chain_tail_idx;
        bc.snake_chain_tail_idx = slot_102; // has a parent: not the root
        assert!(!bc.advance_snake_chain_tail());
        assert_eq!(bc.block_tree_len(), 4, "nothing released");
        bc.snake_chain_tail_idx = real_tail;
        assert!(bc.advance_snake_chain_tail());
    }

    /// One drive step's record: the new `S_tail`, the released slot, and the
    /// classification and binding decided before the release.
    type DriveRecord = (u32, u32, TailObligation, TailBinding);

    /// One step of the drive in [`drive_past_w`]: classify the tail, decide
    /// the binding for `extension`, then extend — the forward extension
    /// advances the window. Returns the trace record.
    fn drive_step(bc: &mut W4Chain, extension: &Block, now: u64) -> DriveRecord {
        let released = bc.snake_chain_tail_idx;
        let obligation =
            classify_tail_drop(&bc.blocks, &bc.node_info, released).expect("the tail is readable");
        let binding = tail_drop_binding(obligation, &extension.view());
        extend_active_head(bc, extension, now);
        assert_ne!(bc.snake_chain_tail_idx, released, "the window advances");
        let (s_tail, _) = bc.active_snake_chain_window().expect("Ready");
        (s_tail, released, obligation, binding)
    }

    /// The AC10.4 drive: from the `W`-long window `100..=103`, two head
    /// extensions. Before the first, two forks hang off #100 (one of them two
    /// blocks deep); before the second, one fork hangs off #101 and one off
    /// #102. Returns the trace, the node, and the forks' hashes:
    /// `[#100 fork, its child, second #100 fork, #101 fork, #102 fork]`.
    fn drive_past_w(now: u64) -> ([DriveRecord; 2], W4Chain, [[u8; 32]; 5]) {
        let (mut bc, h) = w4_ready_on_segment(103);
        let fork_a = salted_linked_block(101, h[0], 5);
        let fork_a_child = salted_linked_block(102, fork_a.view().hash(), 5);
        let fork_b = salted_linked_block(101, h[0], 6);
        for blk in [&fork_a, &fork_a_child, &fork_b] {
            let (outcome, _) = bc.receive_block(blk.view(), now);
            assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        }
        // Dropping #100 (chain-config) needs a chain-config extension (FR49).
        let b104 = w4_config_anchor_block(104, h[3]);
        let first = drive_step(&mut bc, &b104, now);
        let fork_c = salted_linked_block(102, h[1], 8);
        let keep = salted_linked_block(103, h[2], 6);
        for blk in [&fork_c, &keep] {
            let (outcome, _) = bc.receive_block(blk.view(), now);
            assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        }
        assert!(!bc.chain_heads.has_stored_head(), "every fork is Connected");
        // A Ready projection is complete (Story 6.0 D3): this segment seeds no
        // node but #0, so the extension must not name another actor.
        let b105 = w4_config_anchor_block(105, b104.view().hash());
        let second = drive_step(&mut bc, &b105, now);
        (
            [first, second],
            bc,
            [
                fork_a.view().hash(),
                fork_a_child.view().hash(),
                fork_b.view().hash(),
                fork_c.view().hash(),
                keep.view().hash(),
            ],
        )
    }

    /// AC10.4 / AC5 / AC6 — the window advance one block at a time: tail
    /// positions, released slots, the new tail unlinked, and FR58 stale
    /// reclamation (DEC-125): every branch forked at a dropped block is deleted
    /// whole (two in one scan at #100), a branch forked above the new tail is
    /// kept, and nothing is left asking for a parent below `S_tail`.
    #[test]
    fn snake_drive_past_w() {
        let (h, slot_100, slot_101) = {
            let (bc, h) = w4_ready_on_segment(103);
            (h, slot_of(&bc, 100, &h[0]), slot_of(&bc, 101, &h[1]))
        };
        let (trace, mut bc, [fork_a, fork_a_child, fork_b, fork_c, keep]) = drive_past_w(1_000);

        assert_eq!(
            trace[0],
            (
                101,
                slot_100.expect("#100"),
                TailObligation::ChainConfig,
                TailBinding::Advance
            )
        );
        assert_eq!(
            trace[1],
            (
                102,
                slot_101.expect("#101"),
                TailObligation::None,
                TailBinding::Advance
            )
        );
        assert_eq!(bc.active_snake_chain_window(), Ok((102, 105)));
        assert!(slot_of(&bc, 100, &h[0]).is_none() && slot_of(&bc, 101, &h[1]).is_none());

        // The new tail is the active chain's root, unlinked from the freed slot.
        let tail = bc.blocks.get(bc.snake_chain_tail_idx).expect("tail");
        assert_eq!(tail.sequence(), 102);
        assert_eq!(tail.parent_ref(), NONE_REF);
        assert!(tail.is_on_active_chain());

        // FR58: every branch forked at a dropped block is gone, whole.
        assert!(slot_of(&bc, 101, &fork_a).is_none(), "#100 fork deleted");
        assert!(
            slot_of(&bc, 102, &fork_a_child).is_none(),
            "with its descendant"
        );
        assert!(
            slot_of(&bc, 101, &fork_b).is_none(),
            "second #100 fork, same scan"
        );
        assert!(slot_of(&bc, 102, &fork_c).is_none(), "#101 fork deleted");
        let keep_idx = slot_of(&bc, 103, &keep).expect("in-range fork retained");
        assert_eq!(
            bc.blocks.get(keep_idx).map(|e| e.parent_ref()),
            Some(bc.snake_chain_tail_idx),
            "still attached to the new tail"
        );
        assert_eq!(bc.block_tree_len(), 5, "#102..#105 and the #102 fork");

        // No head is left asking for a parent below S_tail.
        assert!(!bc.chain_heads.has_stored_head());
        assert_eq!(
            bc.chain_heads.count(),
            2,
            "the active head and the #102 fork"
        );
        let (outcome, _) = bc.on_tick(u64::MAX / 2);
        assert!(!matches!(
            outcome,
            TickOutcome::SendParentRecoveryRequest(_)
        ));
    }

    /// Review r2 (DEC-127) — a Collecting genesis anchor that the adopted chain
    /// does not contain loses its flag at the promotion and is reclaimed at
    /// Ready entry, so its branch neither looks Connected nor lingers. Live
    /// path: only block #0 arrived, so the genesis branch names no
    /// configuration and FR2 adopts a window-anchored segment instead. Also
    /// pins that the head recompute runs before the Ready-entry reclamation.
    #[test]
    fn snake_ready_entry_reclaims_a_genesis_island() {
        let mut bc = new_w4_chain();
        let genesis = node_transfer_block(0, 3, 0, 7);
        let (outcome, _) = bc.receive_block(genesis.view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        let gi = slot_of(&bc, 0, &genesis.view().hash()).expect("genesis stored");
        assert!(
            bc.blocks.get(gi).is_some_and(|e| e.is_on_active_chain()),
            "precondition: the Collecting bootstrap anchor"
        );
        let anchor = w4_config_anchor_block(100, [0xAB; 32]);
        bc.receive_block(anchor.view(), 0);
        let mut prev = anchor.view().hash();
        for seq in 101..=103 {
            let blk = linked_transfer_block(seq, prev);
            prev = blk.view().hash();
            bc.receive_block(blk.view(), 0);
        }
        assert!(bc.is_ready(), "the window-anchored segment won");
        assert_eq!(bc.active_snake_chain_window(), Ok((100, 103)));
        assert!(
            slot_of(&bc, 0, &genesis.view().hash()).is_none(),
            "island reclaimed"
        );
        assert_eq!(bc.block_tree_len(), 4);
        assert_eq!(bc.chain_heads.count(), 1, "only the active head");
        assert!(!bc.chain_heads.has_stored_head());
    }

    /// FR58 stale-fragment reclamation (pulled forward 2026-10-17): at the tail
    /// advance, a Stored fragment whose lowest block `t` has `t - 1 <= S_tail`
    /// is deleted whole; one with `t - 1 > S_tail` may still connect and stays.
    /// Both are admitted in Ready before the advance (FR60 accepts them).
    #[test]
    fn snake_advance_reclaims_fragments_that_can_never_connect() {
        let (mut bc, h) = w4_ready_on_segment(103);
        // Three orphans, two of them stale. After the advance S_tail = 101.
        let stale = node_transfer_block(102, 3, 101, 7); // t - 1 = 101 = S_tail
        let stale_two = node_transfer_block(101, 4, 100, 7); // t - 1 = 100 < S_tail
        let alive = node_transfer_block(103, 3, 102, 7); // t - 1 = 102 > S_tail
        for blk in [&stale, &stale_two, &alive] {
            let (outcome, _) = bc.receive_block(blk.view(), 0);
            assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        }
        let stored_before: [Option<u32>; 4] =
            core::array::from_fn(|s| bc.chain_heads.stored_head_tail(s));
        assert_eq!(stored_before.iter().flatten().count(), 3, "precondition");

        let b104 = w4_config_anchor_block(104, h[3]);
        extend_active_head(&mut bc, &b104, 0);
        assert_eq!(bc.active_snake_chain_window(), Ok((101, 104)));

        assert!(
            slot_of(&bc, 102, &stale.view().hash()).is_none(),
            "stale fragment deleted"
        );
        assert!(
            slot_of(&bc, 101, &stale_two.view().hash()).is_none(),
            "second fragment too"
        );
        let alive_idx = slot_of(&bc, 103, &alive.view().hash()).expect("may still connect");
        let stored_after: [Option<u32>; 4] =
            core::array::from_fn(|s| bc.chain_heads.stored_head_tail(s));
        assert_eq!(
            stored_after.iter().flatten().count(),
            1,
            "only the live fragment is Stored"
        );
        assert!(stored_after.contains(&Some(alive_idx)));
        // The active chain is untouched by the reclamation.
        for (i, seq) in (101..=104).enumerate() {
            let hash = if seq == 104 {
                b104.view().hash()
            } else {
                h[i + 1]
            };
            assert!(slot_of(&bc, seq, &hash).is_some(), "active #{seq} kept");
        }
    }

    /// AC10.8 — AR16 replay (FR63): the same event sequence twice gives
    /// identical tail positions, releases, classifications and decisions,
    /// whatever the wall clock reads.
    #[test]
    fn snake_drive_is_replay_deterministic() {
        let (first, a, _) = drive_past_w(1_000);
        let (second, b, _) = drive_past_w(9_999_999);
        assert_eq!(first, second);
        assert_eq!(a.active_snake_chain_window(), b.active_snake_chain_window());
        assert_eq!(a.snake_chain_tail_idx, b.snake_chain_tail_idx);
    }

    /// AC10.5 / AC4 — FR60 goes live through the real `receive_block` path: a
    /// block at `S_head + W` or beyond, or below `S_tail`, is `OutOfWindow`.
    #[test]
    fn snake_fr60_window_is_live_in_ready() {
        // Genesis on W = 16: window (0, 1).
        let mut bc = genesis_node_with_window(16);
        let (outcome, _) = bc.receive_block(node_transfer_block(17, 3, 16, 7).view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow)
        );
        let (outcome, _) = bc.receive_block(node_transfer_block(16, 3, 15, 7).view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::AcceptedSilently,
            "S_head + W - 1"
        );

        // W = 4, entered Ready on 100..=104 → window (101, 104).
        let (mut bc, _) = w4_ready_on_segment(104);
        assert_eq!(bc.active_snake_chain_window(), Ok((101, 104)));
        let below = node_transfer_block(100, 3, 99, 7);
        let (outcome, _) = bc.receive_block(below.view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow),
            "below S_tail — a block at the just-released sequence #100"
        );
        let (outcome, _) = bc.receive_block(node_transfer_block(108, 3, 107, 7).view(), 0);
        assert_eq!(
            outcome,
            ReceiveBlockOutcome::Rejected(RejectReason::OutOfWindow)
        );
        let (outcome, _) = bc.receive_block(node_transfer_block(107, 3, 106, 7).view(), 0);
        assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
    }

    /// AC10.9 / AC1 — every site that clears or resets the active head clears
    /// the tail, and the tail is `NONE_REF` whenever the phase is not Ready.
    /// Each reset path is entered with a tail deliberately set, so the clear is
    /// what is under test, not the starting value.
    #[test]
    fn snake_reset_sites_clear_the_tail() {
        // Tier-1 genesis anchor (Collecting).
        let mut bc = new_test_chain();
        bc.snake_chain_tail_idx = 3;
        let genesis = node_transfer_block(0, 3, 0, 7);
        let gi = bc
            .tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("genesis admitted");
        assert!(!bc.is_ready());
        assert_eq!(bc.snake_chain_tail_idx, NONE_REF);

        // FR5 recovery (Processing → Collecting).
        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        bc.snake_chain_tail_idx = gi;
        bc.recover_from_failed_pass(ProcessingError::MissingBlock, gi);
        assert!(!bc.is_ready());
        assert_eq!(bc.snake_chain_tail_idx, NONE_REF);

        // Restart rebuild.
        let mut bc = new_test_chain();
        bc.snake_chain_tail_idx = 0;
        bc.rebuild_block_tree_from_storage(0);
        assert!(!bc.is_ready());
        assert_eq!(bc.snake_chain_tail_idx, NONE_REF);

        // Subtree deletion that takes the active head. Production reaches it
        // only outside Ready (the FR8 adopt path runs in Processing), so the
        // node is put there; the tail is the genesis window's.
        let mut bc = genesis_node_with_window(16);
        assert_ne!(bc.snake_chain_tail_idx, NONE_REF);
        bc.lifecycle_phase = LifecyclePhase::Processing;
        let head = bc.active_chain_head_idx;
        bc.delete_subtree_with_followup(head);
        assert!(!bc.is_ready());
        assert_eq!(bc.active_chain_head_idx, NONE_REF);
        assert_eq!(bc.snake_chain_tail_idx, NONE_REF);
    }

    /// AC3 + Ratified Decision 3 — a released block's durable bytes survive
    /// (lazy release), so a restart re-admits it, and the Ready re-entry
    /// releases it again: the restarted node holds the same `W`-long window.
    #[test]
    fn snake_restart_rereleases_a_resurrected_tail_block() {
        let (bc, h) = w4_ready_on_segment(104);
        assert_eq!(bc.block_tree_len(), 4);
        let storage = bc.storage;
        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
        let chain_config = empty_chain_config(W4Chain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let mut slot = core::mem::MaybeUninit::uninit();
        W4Chain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
        // SAFETY: `init` returned, so every field of `slot` is initialized.
        let mut restarted = unsafe { slot.assume_init() };
        restarted.initialize_from_storage(500);
        assert!(restarted.is_ready());
        assert_eq!(restarted.active_snake_chain_window(), Ok((101, 104)));
        assert_eq!(restarted.block_tree_len(), 4);
        assert!(slot_of(&restarted, 100, &h[0]).is_none());
    }

    // --- Story 6.8: ADR-016 sequence-indexed UTXO input -----------------------

    /// A `payload_type=1` block of complex transactions, chained to `prev` and
    /// created by `creator`. The UTXO-side builder deferred-work D32 asked for.
    fn complex_tx_block(
        seq: u32,
        prev: [u8; 32],
        creator: u32,
        mined_amount: u32,
        txs: &[&moonblokz_chain_types::ComplexTransaction],
    ) -> Block {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
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
        for tx in txs {
            builder
                .add_complex_transaction(tx)
                .ok()
                .expect("add complex");
        }
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// One complex transaction (vote 0, the node-#0 exception): the given
    /// UTXO inputs `(block_sequence, output_index, declared amount)`, an optional balance input
    /// `(initializer, amount)` anchored just below `seq`, then the outputs, each
    /// `Ok(amount)` for a UTXO output or `Err((receiver, amount))` for a
    /// balance output, in order.
    fn utxo_tx(
        seq: u32,
        utxo_inputs: &[(u32, u8, u64)],
        balance_input: Option<(u32, u64)>,
        outputs: &[Result<u64, (u32, u64)>],
    ) -> moonblokz_chain_types::ComplexTransaction {
        utxo_tx_vote(0, seq, utxo_inputs, balance_input, outputs)
    }

    /// [`utxo_tx`] whose `vote` names `vote`.
    fn utxo_tx_vote(
        vote: u32,
        seq: u32,
        utxo_inputs: &[(u32, u8, u64)],
        balance_input: Option<(u32, u64)>,
        outputs: &[Result<u64, (u32, u64)>],
    ) -> moonblokz_chain_types::ComplexTransaction {
        let mut cx = moonblokz_chain_types::ComplexTransaction::new(vote);
        for &(block_sequence, output_index, amount) in utxo_inputs {
            cx.add_utxo_input(block_sequence, output_index, amount, &[0u8; 64])
                .ok()
                .expect("add utxo input");
        }
        if let Some((initializer, amount)) = balance_input {
            cx.add_balance_input(seq - 1, initializer, amount, 0, &[0u8; 64])
                .ok()
                .expect("add balance input");
        }
        for output in outputs {
            match *output {
                Ok(amount) => cx.add_utxo_output(&[0xA5; 32], amount),
                Err((receiver, amount)) => cx.add_balance_output(receiver, amount),
            }
            .ok()
            .expect("add output");
        }
        cx
    }

    fn admit(bc: &mut TestChain, block: &Block) -> u32 {
        bc.tier1_admit(&block.view(), &block.view().hash(), 0)
            .expect("block admitted")
    }

    /// The UTXO harness: a chain-config anchor at 99, then a balance block at
    /// 100 seeding node 1 with 100 and nodes 2 and 3 (the creator) with 0.
    fn utxo_test_chain() -> (TestChain, [u8; 32]) {
        let mut bc = new_test_chain();
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        let seed = balance_block(
            100,
            cfg_hash,
            &[(1, 100, 0, 0xB1), (2, 0, 0, 0xB2), (3, 0, 0, 0xB3)],
            3,
        );
        admit(&mut bc, &seed);
        (bc, seed.view().hash())
    }

    /// Block 101: node 1 moves its whole balance into two UTXO outputs, 60
    /// (index 0) and 40 (index 1).
    fn utxo_mint_block(prev: [u8; 32]) -> Block {
        let tx = utxo_tx(101, &[], Some((1, 100)), &[Ok(60), Ok(40)]);
        complex_tx_block(101, prev, 3, 0, &[&tx])
    }

    /// AC8 (1) / Story 6.11 AC6.1 — deriving the mint sets one bit per UTXO
    /// output; the spend clears the input's bit (and only it), and the
    /// referenced amount reaches the balance output.
    #[test]
    fn utxo_spend_clears_the_bit_and_credits_the_amount() {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        let mi = admit(&mut bc, &mint);
        let tx = utxo_tx(102, &[(101, 1, 40)], None, &[Err((2, 40))]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);

        bc.run_processing_pass(si).expect("pass succeeds");

        assert_eq!(bc.blocks.utxo_available(mi, 1), Some(false), "spent output");
        assert_eq!(
            bc.blocks.utxo_available(mi, 0),
            Some(true),
            "untouched output"
        );
        assert_eq!(
            bc.blocks.utxo_available(mi, 2),
            Some(false),
            "no third output"
        );
        assert_eq!(bc.node_info.balance_of(1), 0, "minted everything");
        assert_eq!(bc.node_info.balance_of(2), 40, "the UTXO's amount");
        assert_eq!(bc.node_info.balance_of(3), 0, "no fee, nothing mined");
    }

    /// AC8 (2) — a second spend of the same output, in a later block, is
    /// `UtxoUnavailable` against that later block; the abort rolls every bit
    /// back to "nothing derived".
    #[test]
    fn utxo_double_spend_across_blocks_is_unavailable() {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        let mi = admit(&mut bc, &mint);
        let tx = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
        let first = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        admit(&mut bc, &first);
        let tx = utxo_tx(103, &[(101, 0, 60)], None, &[Err((2, 60))]);
        let second = complex_tx_block(103, first.view().hash(), 3, 0, &[&tx]);
        let di = admit(&mut bc, &second);

        assert_eq!(
            bc.run_processing_pass(di),
            Err(ProcessingError::Invalid {
                block_idx: di,
                reason: ValidationReason::UtxoUnavailable,
            })
        );
        assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false), "rolled back");
        assert_eq!(bc.blocks.utxo_available(mi, 1), Some(false), "rolled back");
    }

    /// Runs the pass over `mint ← spend(inputs)` and returns its verdict and
    /// the spending block's slot.
    fn spend_verdict(inputs: &[(u32, u8, u64)]) -> (Result<(), ProcessingError>, u32) {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        admit(&mut bc, &mint);
        let tx = utxo_tx(102, inputs, None, &[]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);
        (bc.run_processing_pass(si).map(|_| ()), si)
    }

    /// AC8 (3) / DEC-129 — on a window-anchored candidate a reference below
    /// the anchor (99) is trusted pre-window history when it is at most `W`
    /// (16) blocks back: no bit, and the declared amounts are trusted, so the
    /// fee is still known (DEC-131).
    #[test]
    fn utxo_reference_below_a_window_anchor_is_trusted_within_w() {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        admit(&mut bc, &mint);
        let tx = utxo_tx(102, &[(98, 0, 50), (86, 3, 30)], None, &[Err((2, 70))]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);

        bc.run_processing_pass(si).expect("pass succeeds");

        assert_eq!(bc.node_info.balance_of(2), 70, "the output is credited");
        assert_eq!(
            bc.node_info.balance_of(3),
            10,
            "fee 80 - 70 from the declared amounts"
        );
    }

    /// AC8 (3) / DEC-129 — a reference more than `W` blocks back is
    /// `UtxoUnresolvable`, below the anchor or not.
    #[test]
    fn utxo_reference_beyond_w_is_unresolvable() {
        for referenced in [85, 50, 0] {
            let (verdict, si) = spend_verdict(&[(referenced, 0, 0)]);
            assert_eq!(
                verdict,
                Err(ProcessingError::Invalid {
                    block_idx: si,
                    reason: ValidationReason::UtxoUnresolvable,
                }),
                "block_sequence {referenced}"
            );
        }
    }

    /// DEC-129 boundary on a `W = 4` chain: exactly `W` back is trusted, one
    /// more is not.
    #[test]
    fn utxo_distance_bound_is_exactly_w() {
        fn verdict(referenced: u32) -> (Result<(), ProcessingError>, u32) {
            let mut bc = new_w4_chain();
            let cfg = w4_config_anchor_block(99, [0xAB; 32]);
            bc.tier1_admit(&cfg.view(), &cfg.view().hash(), 0)
                .expect("config admitted");
            let seed = balance_block(100, cfg.view().hash(), &[(2, 0, 0, 0xB2)], 3);
            bc.tier1_admit(&seed.view(), &seed.view().hash(), 0)
                .expect("seed admitted");
            let tx = utxo_tx(101, &[(referenced, 0, 5)], None, &[Err((2, 5))]);
            let spend = complex_tx_block(101, seed.view().hash(), 3, 0, &[&tx]);
            let si = bc
                .tier1_admit(&spend.view(), &spend.view().hash(), 0)
                .expect("spend admitted");
            (bc.run_processing_pass(si).map(|_| ()), si)
        }
        assert_eq!(verdict(97).0, Ok(()), "101 - 97 = W");
        let (result, si) = verdict(96);
        assert_eq!(
            result,
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoUnresolvable,
            }),
            "101 - 96 > W"
        );
    }

    /// AC3 — without trust (a genesis-anchored candidate, or Ready, where
    /// `NONE_REF` is the released tail) a reference below the anchor is
    /// `UtxoUnresolvable`, even within `W`.
    #[test]
    fn utxo_reference_below_the_anchor_is_unresolvable_without_trust() {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        let mi = admit(&mut bc, &mint);
        assert!(matches!(
            bc.resolve_and_spend_utxo(mi, 102, 98, 0, 0, false),
            Err(UtxoSpendError::Invalid(ValidationReason::UtxoUnresolvable))
        ));
        assert!(matches!(
            bc.resolve_and_spend_utxo(mi, 102, 98, 0, 0, true),
            Ok(None)
        ));
    }

    /// AC8 (5) / Story 6.11 AC3 — an `output_index` past the referenced
    /// block's UTXO outputs (or into a block with none) has no available bit:
    /// exact evidence, decided from RAM.
    #[test]
    fn utxo_out_of_bounds_index_is_unavailable() {
        for (referenced, index) in [(101, 2), (101, 255), (100, 0), (99, 0)] {
            let (verdict, si) = spend_verdict(&[(referenced, index, 0)]);
            assert_eq!(
                verdict,
                Err(ProcessingError::Invalid {
                    block_idx: si,
                    reason: ValidationReason::UtxoUnavailable,
                }),
                "({referenced}, {index})"
            );
        }
    }

    /// AC8 (4) — ADR-016 trade-off (FR39): an output at the same
    /// `(sequence, index)` on a side branch is never found. The resolver only
    /// visits the consuming block's ancestors, whose block 101 has no output
    /// and so no available bit; the side branch was never derived.
    #[test]
    fn utxo_output_on_a_side_branch_is_not_resolvable() {
        let (mut bc, h100) = utxo_test_chain();
        let side = utxo_mint_block(h100);
        let side_idx = admit(&mut bc, &side);
        // The active ancestry's block 101 carries no UTXO output.
        let own = transfer_block(101, h100, 2, 3, 0, 0, 0);
        admit(&mut bc, &own);
        let tx = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
        let spend = complex_tx_block(102, own.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);

        assert_eq!(
            bc.run_processing_pass(si),
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::UtxoUnavailable,
            })
        );
        assert_eq!(
            bc.blocks.has_available_utxo(side_idx),
            Some(false),
            "a side branch is never derived: its whole bitfield stays 0"
        );
    }

    /// AC8 (7) / AC5 — Tier 1 rejects a UTXO input whose `block_sequence` is
    /// not below the block's own, and the block is not stored (FR16).
    #[test]
    fn utxo_input_not_before_block_is_rejected_at_intake() {
        let (mut bc, h100) = utxo_test_chain();
        let stored = bc.blocks.len();
        for referenced in [101, 102] {
            let tx = utxo_tx(101, &[(referenced, 0, 1)], None, &[Err((2, 1))]);
            let block = complex_tx_block(101, h100, 3, 0, &[&tx]);
            assert_eq!(
                bc.tier1_admit(&block.view(), &block.view().hash(), 0),
                Err(AdmitError::Rejected(Tier1Failure::UtxoInputNotBeforeBlock))
            );
        }
        assert_eq!(bc.blocks.len(), stored, "nothing stored");
    }

    /// AC8 (8) / AC6 — the fee counts UTXO outputs: a balance input of 100
    /// paid entirely into a UTXO output leaves no surplus, so the creator gets
    /// its mined amount and nothing more (it used to get another 100).
    #[test]
    fn utxo_output_is_not_paid_out_as_fee() {
        let (mut bc, h100) = utxo_test_chain();
        let tx = utxo_tx(101, &[], Some((1, 100)), &[Ok(100)]);
        let block = complex_tx_block(101, h100, 3, 7, &[&tx]);
        let bi = admit(&mut bc, &block);

        bc.run_processing_pass(bi).expect("pass succeeds");

        assert_eq!(bc.node_info.balance_of(3), 7, "mined 7, fee 0");
        assert_eq!(bc.node_info.balance_of(1), 0);
    }

    /// AC8 (9) / D1 — the UTXO amount is an input: 50 (UTXO) + 10 (balance)
    /// against 55 of outputs pays a fee of 5. Outputs above the declared
    /// inputs never reach the pass: Tier 1 rejects them (DEC-131).
    #[test]
    fn utxo_amount_counts_as_input() {
        let (mut bc, h100) = utxo_test_chain();
        let tx = utxo_tx(101, &[], Some((1, 50)), &[Ok(50)]);
        let mint = complex_tx_block(101, h100, 3, 0, &[&tx]);
        admit(&mut bc, &mint);
        let over = utxo_tx(102, &[(101, 0, 50)], Some((1, 10)), &[Err((2, 61))]);
        let over = complex_tx_block(102, mint.view().hash(), 3, 0, &[&over]);
        assert_eq!(
            bc.tier1_admit(&over.view(), &over.view().hash(), 0),
            Err(AdmitError::Rejected(Tier1Failure::InputsLessThanOutputs))
        );
        let tx = utxo_tx(102, &[(101, 0, 50)], Some((1, 10)), &[Err((2, 55))]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);

        bc.run_processing_pass(si).expect("pass succeeds");

        assert_eq!(bc.node_info.balance_of(3), 5, "fee = 60 - 55");
        assert_eq!(bc.node_info.balance_of(2), 55);
        assert_eq!(bc.node_info.balance_of(1), 40, "100 - 50 - 10");
    }

    /// DEC-131 — a declared amount that is not the referenced output's is
    /// `UtxoAmountMismatch`; the abort leaves nothing derived.
    #[test]
    fn utxo_declared_amount_mismatch_is_invalid() {
        for declared in [39, 41] {
            let (mut bc, h100) = utxo_test_chain();
            let mint = utxo_mint_block(h100);
            let mi = admit(&mut bc, &mint);
            let tx = utxo_tx(102, &[(101, 1, declared)], None, &[Err((2, declared))]);
            let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
            let si = admit(&mut bc, &spend);
            assert_eq!(
                bc.run_processing_pass(si),
                Err(ProcessingError::Invalid {
                    block_idx: si,
                    reason: ValidationReason::UtxoAmountMismatch,
                }),
                "declared {declared}, output 40"
            );
            assert_eq!(bc.blocks.utxo_available(mi, 1), Some(false));
        }
    }

    /// AC8 (10) / AC2 — `output_index` counts the block's UTXO-output stream
    /// across transactions, skipping balance outputs: the second
    /// transaction's only UTXO output is index 2, not 0.
    #[test]
    fn utxo_output_index_spans_the_whole_block() {
        let (mut bc, h100) = utxo_test_chain();
        let first = utxo_tx(101, &[], Some((1, 60)), &[Ok(10), Err((2, 5)), Ok(45)]);
        let second = utxo_tx(101, &[], Some((1, 30)), &[Ok(30)]);
        let mint = complex_tx_block(101, h100, 3, 0, &[&first, &second]);
        let mi = admit(&mut bc, &mint);
        let tx = utxo_tx(102, &[(101, 2, 30)], None, &[Err((2, 30))]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);

        bc.run_processing_pass(si).expect("pass succeeds");

        assert_eq!(bc.blocks.utxo_available(mi, 2), Some(false), "spent");
        assert_eq!(bc.blocks.utxo_available(mi, 0), Some(true));
        assert_eq!(bc.blocks.utxo_available(mi, 1), Some(true), "the 45 output");
        assert_eq!(
            bc.blocks.utxo_available(mi, 3),
            Some(false),
            "no fourth output"
        );
        assert_eq!(bc.node_info.balance_of(2), 5 + 30, "the 30 output");
        assert_eq!(bc.node_info.balance_of(3), 0, "no fee anywhere");
    }

    /// AC8 (2) — the same output named twice in one transaction, or by two
    /// transactions of one block, is spent once: the second is
    /// `UtxoUnavailable`.
    #[test]
    fn utxo_double_spend_within_one_block_is_unavailable() {
        let same_tx = utxo_tx(102, &[(101, 0, 60), (101, 0, 60)], None, &[Err((2, 60))]);
        let first = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
        let second = utxo_tx(102, &[(101, 0, 60)], None, &[Err((2, 60))]);
        for txs in [&[&same_tx][..], &[&first, &second][..]] {
            let (mut bc, h100) = utxo_test_chain();
            let mint = utxo_mint_block(h100);
            admit(&mut bc, &mint);
            let spend = complex_tx_block(102, mint.view().hash(), 3, 0, txs);
            let si = admit(&mut bc, &spend);
            assert_eq!(
                bc.run_processing_pass(si),
                Err(ProcessingError::Invalid {
                    block_idx: si,
                    reason: ValidationReason::UtxoUnavailable,
                }),
                "{} transaction(s)",
                txs.len()
            );
        }
    }

    /// AC6 — an input sum beyond `u64` is rejected at Tier 1 (DEC-011,
    /// DEC-131); the block's fee total, summed across transactions, is checked
    /// in the pass: `ValueOverflow`, never a clamped credit.
    #[test]
    fn utxo_value_overflow_is_invalid() {
        const HALF: u64 = 1 << 63;
        let (mut bc, h100) = utxo_test_chain();
        // Two zero-input carry-forwards, each a UTXO output of 2^63.
        let a = utxo_tx(101, &[], None, &[Ok(HALF)]);
        let b = utxo_tx(101, &[], None, &[Ok(HALF)]);
        let mint = complex_tx_block(101, h100, 3, 0, &[&a, &b]);
        admit(&mut bc, &mint);

        let both = utxo_tx(102, &[(101, 0, HALF), (101, 1, HALF)], None, &[]);
        let both = complex_tx_block(102, mint.view().hash(), 3, 0, &[&both]);
        assert_eq!(
            bc.tier1_admit(&both.view(), &both.view().hash(), 0),
            Err(AdmitError::Rejected(Tier1Failure::AmountOverflow))
        );

        let first = utxo_tx(102, &[(101, 0, HALF)], None, &[]);
        let second = utxo_tx(102, &[(101, 1, HALF)], None, &[]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&first, &second]);
        let si = admit(&mut bc, &spend);
        assert_eq!(
            bc.run_processing_pass(si),
            Err(ProcessingError::Invalid {
                block_idx: si,
                reason: ValidationReason::ValueOverflow,
            })
        );
    }

    /// A storage backend whose reads of one slot start failing after a set
    /// number of successful ones, counting every attempt on that slot.
    struct FailingReadStorage {
        inner: MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        failing_slot: u32,
        reads_left: core::cell::Cell<u32>,
        attempts: core::cell::Cell<u32>,
    }

    impl StorageTrait for FailingReadStorage {
        fn init(
            &mut self,
            private_key: [u8; PRIVATE_KEY_SIZE],
            own_node_id: u32,
            init_params: [u8; INIT_PARAMS_SIZE],
        ) -> Result<(), StorageError> {
            self.inner.init(private_key, own_node_id, init_params)
        }

        fn save_block(&mut self, idx: u32, block: &Block) -> Result<(), StorageError> {
            self.inner.save_block(idx, block)
        }

        fn read_block_into(
            &self,
            idx: u32,
            out: &mut [u8; MAX_BLOCK_SIZE],
        ) -> Result<(), StorageError> {
            if idx == self.failing_slot {
                self.attempts.set(self.attempts.get() + 1);
                let left = self.reads_left.get();
                if left == 0 {
                    return Err(StorageError::BackendIo { code: 9 });
                }
                self.reads_left.set(left - 1);
            }
            self.inner.read_block_into(idx, out)
        }

        fn capacity(&self) -> u32 {
            self.inner.capacity()
        }

        fn set_chain_configuration(&mut self, block: &Block) -> Result<(), StorageError> {
            self.inner.set_chain_configuration(block)
        }

        fn load_control_data(&mut self) -> Result<ControlPlaneData, StorageError> {
            self.inner.load_control_data()
        }
    }

    type FailingReadChain = Blockchain<Crypto, FailingReadStorage, TestConfig, 16, 16, 16, 4, 16>;

    /// The UTXO harness on a [`FailingReadChain`] whose reads all succeed
    /// until a test arms `failing_slot`: chain-config anchor 99, balance block
    /// 100, and the [`utxo_mint_block`] at 101. Returns the node, the mint and
    /// its slot.
    fn failing_read_utxo_chain() -> (FailingReadChain, Block, u32) {
        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
        let chain_config = locked_chain_config(&crypto, FailingReadChain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let storage = FailingReadStorage {
            inner: initialized_storage([1u8; PRIVATE_KEY_SIZE]),
            failing_slot: NONE_REF,
            reads_left: core::cell::Cell::new(0),
            attempts: core::cell::Cell::new(0),
        };
        let mut slot = core::mem::MaybeUninit::<FailingReadChain>::uninit();
        FailingReadChain::init(&mut slot, crypto, storage, chain_config, 5, node_zero, 0);
        // SAFETY: `init` returned, so every field of `slot` is initialized.
        let mut bc = unsafe { slot.assume_init() };

        let cfg = chain_config_anchor_block(99, [0xAB; 32]);
        failing_read_admit(&mut bc, &cfg);
        let seed = balance_block(
            100,
            cfg.view().hash(),
            &[(1, 100, 0, 0xB1), (2, 0, 0, 0xB2), (3, 0, 0, 0xB3)],
            3,
        );
        failing_read_admit(&mut bc, &seed);
        let mint = utxo_mint_block(seed.view().hash());
        let mi = failing_read_admit(&mut bc, &mint);
        (bc, mint, mi)
    }

    fn failing_read_admit(bc: &mut FailingReadChain, block: &Block) -> u32 {
        bc.tier1_admit(&block.view(), &block.view().hash(), 0)
            .expect("block admitted")
    }

    /// AC8 (6) / AC3 step 5 — a failed read of the referenced block is a local
    /// fault: the pass reports `StorageRead`, never `Invalid`, so nothing is
    /// charged against the spending block. (The FR5 driver's head fallback for
    /// `StorageRead` is unchanged here; DEC-037 is Story 6.0.)
    #[test]
    fn utxo_read_failure_is_reported_as_storage_read() {
        let (mut bc, mint, mi) = failing_read_utxo_chain();
        let tx = utxo_tx(102, &[(101, 1, 40)], None, &[Err((2, 40))]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = failing_read_admit(&mut bc, &spend);

        bc.storage.failing_slot = mi;
        bc.storage.reads_left.set(1);
        let stored = bc.blocks.len();

        assert_eq!(
            bc.run_processing_pass(si),
            Err(ProcessingError::StorageRead)
        );
        assert_eq!(
            bc.storage.attempts.get(),
            2,
            "the segment walk read the block, then the resolver's read failed"
        );
        assert_eq!(bc.blocks.len(), stored, "the pass itself deletes nothing");
    }

    /// Story 6.11 AC3 / AC6.3 — an output whose bit is 0 is rejected before the
    /// resolver reads the referenced block: past the block's outputs (no read
    /// at all beyond the segment walk's), or already spent by an earlier block
    /// (only that earlier spend reads).
    #[test]
    fn utxo_unavailable_output_is_rejected_without_a_read() {
        // (spending blocks' inputs, resolver reads expected on the mint)
        let past_the_outputs: &[&[(u32, u8, u64)]] = &[&[(101, 2, 0)]];
        let spent_earlier: &[&[(u32, u8, u64)]] = &[&[(101, 0, 60)], &[(101, 0, 60)]];
        for (spends, resolver_reads) in [(past_the_outputs, 0), (spent_earlier, 1)] {
            let (mut bc, mint, mi) = failing_read_utxo_chain();
            let mut prev = mint.view().hash();
            let mut tip = mi;
            for (k, inputs) in spends.iter().enumerate() {
                let seq = 102 + k as u32;
                let amount = inputs[0].2;
                let tx = utxo_tx(seq, inputs, None, &[Err((2, amount))]);
                let block = complex_tx_block(seq, prev, 3, 0, &[&tx]);
                prev = block.view().hash();
                tip = failing_read_admit(&mut bc, &block);
            }
            bc.storage.failing_slot = mi;
            bc.storage.reads_left.set(u32::MAX);

            assert_eq!(
                bc.run_processing_pass(tip),
                Err(ProcessingError::Invalid {
                    block_idx: tip,
                    reason: ValidationReason::UtxoUnavailable,
                })
            );
            assert_eq!(
                bc.storage.attempts.get(),
                1 + resolver_reads,
                "the segment walk's read, plus {resolver_reads} by the resolver"
            );
        }
    }

    /// Story 6.11 AC3 / D2 — a set bit whose output the stored bytes do not
    /// hold means storage and RAM disagree: a local fault, never evidence
    /// against the spending block.
    #[test]
    fn utxo_bit_without_its_output_is_a_local_fault() {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        let mi = admit(&mut bc, &mint);
        bc.run_processing_pass(mi).expect("the mint derives");
        assert_eq!(bc.blocks.utxo_available(mi, 2), Some(false));
        bc.blocks.set_utxo_available(mi, 2, true);

        assert!(matches!(
            bc.resolve_and_spend_utxo(mi, 102, 101, 2, 0, false),
            Err(UtxoSpendError::StorageRead)
        ));
        assert_eq!(bc.blocks.utxo_available(mi, 2), Some(true), "nothing spent");
    }

    /// An override set declaring `max_block_utxo_output = 1` and the window
    /// [`TEST_W`].
    fn one_utxo_output_config_builder() -> ChainConfigPayloadBuilder {
        let mut builder = window_config_builder(TEST_W);
        builder
            .add_literal(parameter::MAX_BLOCK_UTXO_OUTPUT, &1u16.to_le_bytes())
            .ok()
            .expect("a two-byte literal is well-formed");
        builder
    }

    /// Story 6.11 AC5 / AC6.7 — the Tier-1 UTXO-output cap enforces the chain's
    /// value only once it is durably locked; a tentative one leaves the
    /// bitfield-width bound in force (FR9).
    #[test]
    fn tier1_utxo_output_cap_is_the_locked_value_only() {
        let two_outputs = utxo_mint_block([0xCD; 32]);
        let one_output = complex_tx_block(
            101,
            [0xCD; 32],
            3,
            0,
            &[&utxo_tx(101, &[], Some((1, 9)), &[Ok(9)])],
        );

        // Tentative: a stray chain-config block declares the cap of 1.
        let mut bc = new_unconfigured_test_chain();
        let stray = chain_config_block_from(500, [0xEE; 32], &mut one_utxo_output_config_builder());
        bc.tier1_admit(&stray.view(), &stray.view().hash(), 0)
            .expect("the stray is admitted");
        assert!(bc.chain_config.tentative_content().is_some());
        assert_eq!(
            bc.chain_config
                .active_configuration()
                .map(|config| config.max_utxo_outputs()),
            Some(1),
            "the tentative configuration really declares the cap of 1"
        );
        assert!(
            bc.tier1_admit(&two_outputs.view(), &two_outputs.view().hash(), 0)
                .is_ok(),
            "a tentative-only cap must not reject the block (FR9)"
        );

        // Locked on the same content: the cap is enforced and nothing is stored.
        let (crypto, storage, _) = test_backends();
        let mut chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        chain_config
            .load_durable(one_utxo_output_config_builder().build_signed(&crypto))
            .ok()
            .expect("legal content");
        let mut bc = new_chain(crypto, storage, chain_config, 5, 0);
        let stored = bc.blocks.len();
        assert_eq!(
            bc.tier1_admit(&two_outputs.view(), &two_outputs.view().hash(), 0),
            Err(AdmitError::Rejected(Tier1Failure::TooManyUtxoOutputs))
        );
        assert_eq!(bc.blocks.len(), stored, "not stored");
        assert!(
            bc.tier1_admit(&one_output.view(), &one_output.view().hash(), 0)
                .is_ok(),
            "exactly the cap is admitted"
        );
    }

    /// Story 6.11 D3 (DEC-133) — the FR3 pass holds a block to its candidate's
    /// own declared cap even while that configuration is only tentative: the
    /// preload made it the value the lock is about to commit, so a block that
    /// Tier 1 admitted under the bitfield-width bound cannot be adopted past it.
    #[test]
    fn fr3_pass_enforces_the_candidates_declared_utxo_output_cap() {
        let (mut bc, h100) = tentative_one_utxo_output_chain();
        let mint = utxo_mint_block(h100);
        let mi = admit(&mut bc, &mint);

        assert_eq!(
            bc.run_processing_pass(mi),
            Err(ProcessingError::Invalid {
                block_idx: mi,
                reason: ValidationReason::TooManyUtxoOutputs,
            })
        );
        assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false), "rolled back");
    }

    /// Story 6.11 D3 boundary — exactly the declared cap passes the FR6 step.
    #[test]
    fn fr3_pass_admits_exactly_the_declared_utxo_output_cap() {
        let (mut bc, h100) = tentative_one_utxo_output_chain();
        let tx = utxo_tx(101, &[], Some((1, 100)), &[Ok(100)]);
        let block = complex_tx_block(101, h100, 3, 0, &[&tx]);
        let bi = admit(&mut bc, &block);

        bc.run_processing_pass(bi).expect("one output, cap one");
        assert_eq!(bc.blocks.utxo_available(bi, 0), Some(true));
    }

    /// An unconfigured node holding, tentatively, a chain-config anchor at 99
    /// that declares `max_block_utxo_output = 1`, and the [`utxo_test_chain`]
    /// balance block at 100 above it. Returns the node and block 100's hash.
    fn tentative_one_utxo_output_chain() -> (TestChain, [u8; 32]) {
        let mut bc = new_unconfigured_test_chain();
        let cfg = chain_config_block_from(99, [0xAB; 32], &mut one_utxo_output_config_builder());
        admit(&mut bc, &cfg);
        assert!(
            bc.chain_config.tentative_content().is_some(),
            "tentative only"
        );
        let seed = balance_block(
            100,
            cfg.view().hash(),
            &[(1, 100, 0, 0xB1), (2, 0, 0, 0xB2), (3, 0, 0, 0xB3)],
            3,
        );
        admit(&mut bc, &seed);
        (bc, seed.view().hash())
    }

    /// Story 6.11 AC2 / AC4 end to end — deriving a block sets exactly one bit
    /// per UTXO output, which gives it the FR51 tail obligation; spending every
    /// output clears it.
    #[test]
    fn utxo_derivation_drives_the_tail_obligation() {
        let (mut bc, h100) = utxo_test_chain();
        let mint = utxo_mint_block(h100);
        let mi = admit(&mut bc, &mint);
        bc.run_processing_pass(mi).expect("the mint derives");
        assert_eq!(bc.blocks.utxo_available(mi, 0), Some(true));
        assert_eq!(bc.blocks.utxo_available(mi, 1), Some(true));
        assert_eq!(
            bc.blocks.utxo_available(mi, 2),
            Some(false),
            "two outputs only"
        );
        assert_eq!(
            classify_tail_drop(&bc.blocks, &bc.node_info, mi),
            Ok(TailObligation::Utxo)
        );

        let tx = utxo_tx(102, &[(101, 0, 60), (101, 1, 40)], None, &[Err((2, 100))]);
        let spend = complex_tx_block(102, mint.view().hash(), 3, 0, &[&tx]);
        let si = admit(&mut bc, &spend);
        bc.run_processing_pass(si).expect("both outputs spent");
        assert_eq!(bc.blocks.has_available_utxo(mi), Some(false));
        assert_eq!(
            classify_tail_drop(&bc.blocks, &bc.node_info, mi),
            Ok(TailObligation::None)
        );
    }

    /// Review patch — the lock-time `BlockTooLarge` rollback follows a pass that
    /// returned `Ok`, so it must clear the derived bits itself: a surviving
    /// ancestor of the offender may not keep advertising its outputs.
    #[test]
    fn fr9_lock_time_size_rollback_leaves_no_available_utxo_bit() {
        let mut bc = new_unconfigured_w4_chain();
        let base = balance_block(100, [0xAB; 32], &[(3, 0, 0, 0xB3)], 3);
        let one = utxo_tx(101, &[], None, &[Ok(5)]);
        let b101 = complex_tx_block(101, base.view().hash(), 3, 0, &[&one]);
        let three = utxo_tx(102, &[], None, &[Ok(5), Ok(6), Ok(7)]);
        let b102 = complex_tx_block(102, b101.view().hash(), 3, 0, &[&three]);
        let cfg =
            chain_config_block_from(103, b102.view().hash(), &mut small_limit_config_builder(W4));
        for small in [&base, &b101, &cfg] {
            assert!(small.len() <= SMALL_BLOCK_SIZE_LIMIT as usize);
        }
        assert!(b102.len() > SMALL_BLOCK_SIZE_LIMIT as usize);
        for block in [&base, &b101, &b102, &cfg] {
            let (outcome, _) = bc.receive_block(block.view(), 0);
            assert_eq!(outcome, ReceiveBlockOutcome::AcceptedSilently);
        }

        assert!(
            !bc.is_ready(),
            "the re-evaluation at the lock refuses the candidate"
        );
        assert!(
            bc.blocks.find(102, &b102.view().hash()).is_none(),
            "offender deleted"
        );
        let survivor = bc
            .blocks
            .find(101, &b101.view().hash())
            .expect("the offender's ancestor survives");
        assert_eq!(
            bc.blocks.has_available_utxo(survivor),
            Some(false),
            "no bit of the refused candidate survives"
        );
    }

    // ===================================================================
    // Story 6.0 — Ready-state active-head forward extension
    // ===================================================================

    /// Every chain of this section shares `TestChain`'s capacities; only the
    /// storage differs (the fault-injecting one of AC6).
    type Chain16<S> = Blockchain<Crypto, S, TestConfig, 16, 16, 16, 4, 16>;

    /// The FR54 currency of every genesis node in this section.
    const CURRENCY: u64 = 1_000_000_000;

    /// A node-#0 genesis node on `W = w`: Ready, with the complete projection
    /// the per-block step derived over #0 / #1 (D6). Returns it with the two
    /// genesis blocks.
    fn ready_genesis(w: u16) -> (TestChain, Block, Block) {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
        let genesis = bc
            .process_genesis(CURRENCY, window_config_builder(w).content())
            .ok()
            .expect("genesis succeeds");
        (bc, genesis.block_zero, genesis.block_one)
    }

    fn head_of<S: StorageTrait>(bc: &Chain16<S>) -> (u32, [u8; 32]) {
        let entry = bc.blocks.get(bc.active_chain_head_idx).expect("a head");
        (entry.sequence(), *entry.hash())
    }

    fn receive<S: StorageTrait>(bc: &mut Chain16<S>, block: &Block) -> ReceiveBlockOutcome {
        bc.receive_block(block.view(), 0).0
    }

    /// A registration of `new_node_id` by `initializer`, its key from
    /// `pk_byte` (the cross-key construction of [`registration_block`]).
    fn registration_tx(initializer: u32, new_node_id: u32, pk_byte: u8) -> Registration {
        let init_signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("init key");
        let new_signer = Crypto::new([pk_byte; PRIVATE_KEY_SIZE])
            .ok()
            .expect("new key");
        let new_pk = *new_signer.public_key().serialize();
        let mut new_key_sig = [0u8; 64];
        new_key_sig.copy_from_slice(&new_signer.sign(&new_pk).serialize()[..64]);
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
        Registration::new(
            0,
            initializer,
            new_node_id,
            50,
            1,
            &new_pk,
            &new_key_sig,
            &tx_sig,
        )
    }

    /// A transaction block by node #0 with `mined_amount`, its payload added
    /// by `add`.
    fn tx_block(
        seq: u32,
        prev: [u8; 32],
        mined: u32,
        add: impl FnOnce(&mut BlockBuilder),
    ) -> Block {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let header = BlockHeader {
            version: 1,
            sequence: seq,
            creator: 0,
            mined_amount: mined,
            payload_type: PAYLOAD_TYPE_TRANSACTION,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: prev,
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        add(&mut builder);
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// A node #0 → `receiver` transfer of `amount` (fee 1, vote 0).
    fn transfer_tx(seq: u32, receiver: u32, amount: u64) -> NodeTransfer {
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        NodeTransfer::new_signed(0, seq - 1, 0, receiver, amount, 1, 0, &signer)
    }

    fn transfer(seq: u32, prev: [u8; 32], receiver: u32, amount: u64) -> Block {
        let nt = transfer_tx(seq, receiver, amount);
        tx_block(seq, prev, 0, |b| {
            b.add_node_transfer(&nt).ok().expect("add transfer");
        })
    }

    fn register(seq: u32, prev: [u8; 32], new_node_id: u32, pk_byte: u8) -> Block {
        let reg = registration_tx(0, new_node_id, pk_byte);
        tx_block(seq, prev, 0, |b| {
            b.add_registration(&reg).ok().expect("add registration");
        })
    }

    /// Node #0's current `(balance, vote_count)` — a matching D9 snapshot.
    fn node_zero_snapshot<S: StorageTrait>(bc: &Chain16<S>) -> (u32, u64, u32, u8) {
        (
            0,
            bc.node_info.balance_of(0),
            bc.vote_engine.accumulated_vote_of(0),
            0,
        )
    }

    /// AC2 / AC10.4: the derived state of two nodes is identical — `node_info`,
    /// the vote engine, the whole block table (statuses, chain flags,
    /// available-UTXO bits), `chain_heads`, the head and the tail.
    fn assert_same_state<S: StorageTrait, T: StorageTrait>(
        a: &Chain16<S>,
        b: &Chain16<T>,
        what: &str,
    ) {
        assert!(a.node_info == b.node_info, "{what}: node_info");
        assert!(a.vote_engine == b.vote_engine, "{what}: votes");
        assert!(a.blocks == b.blocks, "{what}: block table");
        assert!(a.chain_heads == b.chain_heads, "{what}: chain_heads");
        assert_eq!(
            a.active_chain_head_idx, b.active_chain_head_idx,
            "{what}: head"
        );
        assert_eq!(
            a.snake_chain_tail_idx, b.snake_chain_tail_idx,
            "{what}: tail"
        );
        assert_eq!(a.lifecycle_phase, b.lifecycle_phase, "{what}: phase");
    }

    /// The durable slot `idx` holds the same bytes on both nodes.
    fn same_slot<S: StorageTrait, T: StorageTrait>(
        a: &Chain16<S>,
        b: &Chain16<T>,
        idx: u32,
    ) -> bool {
        match (a.storage.read_block(idx), b.storage.read_block(idx)) {
            (Ok(x), Ok(y)) => x.serialized_bytes() == y.serialized_bytes(),
            (Err(_), Err(_)) => true,
            _ => false,
        }
    }

    /// The reason the fallible half of the step gives for `block` as an
    /// extension of the head, run on a scratch entry that is removed again.
    /// `None` on success, whose effects are then inverted, so either way the
    /// node is left as it was.
    fn step_reason<S: StorageTrait>(
        bc: &mut Chain16<S>,
        block: &Block,
    ) -> Option<ValidationReason> {
        let view = block.view();
        let idx = bc.blocks.next_free_index().expect("a free slot");
        let head = bc.active_chain_head_idx;
        let head_hash = *bc.blocks.get(head).expect("head").hash();
        bc.blocks
            .insert_at(idx, BlockEntry::new(view.hash(), head, view.sequence()));
        let mut projection = Projection::COMPLETE;
        let reason = match bc.derive_block(&view, idx, Some(head_hash), &mut projection) {
            Ok(_) => {
                bc.invert_transactions(&view, idx, usize::MAX);
                None
            }
            Err(ProcessingError::Invalid { reason, .. }) => Some(reason),
            Err(other) => panic!("not a validation failure: {other:?}"),
        };
        bc.blocks.delete(idx);
        reason
    }

    /// The UTXO fixture on a genesis node: #2 registers node 1, #3 mints two
    /// UTXO outputs (60, 40) from node #0's balance. Returns the node and #3.
    fn utxo_genesis() -> (TestChain, Block) {
        let (mut bc, _, b1) = ready_genesis(16);
        let reg = register(2, b1.view().hash(), 1, 0xB1);
        assert_eq!(
            receive(&mut bc, &reg),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let mint_tx = utxo_tx(3, &[], Some((0, 100)), &[Ok(60), Ok(40)]);
        let mint = complex_tx_block(3, reg.view().hash(), 0, 0, &[&mint_tx]);
        assert_eq!(
            receive(&mut bc, &mint),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&bc).1, mint.view().hash());
        (bc, mint)
    }

    // --- Task 2.2: every inverse is exact (apply ∘ invert = identity) -------

    #[test]
    fn step_inverses_restore_the_derived_state_exactly() {
        // Node transfer, registration, and a complex transaction with a UTXO
        // spend, a balance input and a balance output — each applied by the
        // step and inverted, on a node that has a twin.
        let (mut bc, mint) = utxo_genesis();
        let (twin, _) = utxo_genesis();
        let (seq, prev) = (4, mint.view().hash());
        let nt = transfer_tx(seq, 1, 500);
        let reg = registration_tx(0, 2, 0xB2);
        let cx = utxo_tx(seq, &[(3, 1, 40)], Some((0, 10)), &[Err((1, 45))]);
        let blocks = [
            tx_block(seq, prev, 0, |b| {
                b.add_node_transfer(&nt).ok().expect("transfer");
            }),
            tx_block(seq, prev, 0, |b| {
                b.add_registration(&reg).ok().expect("registration");
            }),
            complex_tx_block(seq, prev, 0, 0, &[&cx]),
        ];
        for block in &blocks {
            assert_eq!(step_reason(&mut bc, block), None, "the block is valid");
            assert_same_state(&bc, &twin, "after apply and invert");
        }
    }

    // --- AC10.1: direct extension -------------------------------------------

    #[test]
    fn forward_extension_promotes_each_direct_extension() {
        let (mut bc, _, b1) = ready_genesis(16);
        let reg = register(2, b1.view().hash(), 1, 0xB1);
        let t3 = transfer(3, reg.view().hash(), 1, 100);
        let t4 = transfer(4, t3.view().hash(), 1, 50);
        for block in [&reg, &t3, &t4] {
            assert_eq!(
                receive(&mut bc, block),
                ReceiveBlockOutcome::AcceptedSilently
            );
            let idx = bc
                .blocks
                .find(block.view().sequence(), &block.view().hash())
                .expect("stored");
            assert_eq!(
                bc.current_active_head(),
                Some(idx),
                "D19: the head advances"
            );
            let entry = bc.blocks.get(idx).expect("entry");
            assert_eq!(entry.status(), BlockStatus::Active);
            assert!(entry.is_on_active_chain());
        }
        assert_eq!(bc.node_info.max_known_node_id(), 1);
        assert_eq!(bc.node_info.balance_of(1), 150);
        // Registration 50 + 1, transfers 101 + 51; every fee back to the
        // creator, node #0.
        assert_eq!(bc.node_info.balance_of(0), CURRENCY - 51 - 101 - 51 + 3);
        assert!(bc.is_ready());
    }

    // --- AC10.2: orphan continuation ----------------------------------------

    #[test]
    fn forward_extension_continues_over_a_stored_orphan() {
        let (mut bc, _, b1) = ready_genesis(16);
        let a = transfer(2, b1.view().hash(), 0, 7);
        let b = transfer(3, a.view().hash(), 0, 8);
        assert_eq!(receive(&mut bc, &b), ReceiveBlockOutcome::AcceptedSilently);
        let bi = bc.blocks.find(3, &b.view().hash()).expect("orphan stored");
        assert_eq!(
            bc.blocks.get(bi).map(|e| e.status()),
            Some(BlockStatus::Stored)
        );
        assert_eq!(head_of(&bc).0, 1, "the orphan does not move the head");

        assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(
            head_of(&bc),
            (3, b.view().hash()),
            "A at intake, B by continuation"
        );
        assert_eq!(
            bc.blocks.get(bi).map(|e| e.status()),
            Some(BlockStatus::Active)
        );
        assert!(!bc.chain_heads.has_stored_head());
        assert_eq!(bc.chain_heads.count(), 1, "no zombie entry for A");
    }

    // --- AC10.3: sibling choice (D5) ----------------------------------------

    #[test]
    fn forward_extension_takes_the_lowest_hash_sibling_on_an_equal_rank() {
        let (mut bc, _, b1) = ready_genesis(16);
        let a = transfer(2, b1.view().hash(), 0, 7);
        let c1 = transfer(3, a.view().hash(), 0, 8);
        let c2 = transfer(3, a.view().hash(), 0, 9);
        for c in [&c1, &c2] {
            assert_eq!(receive(&mut bc, c), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
        let (low, high) = if c1.view().hash() < c2.view().hash() {
            (&c1, &c2)
        } else {
            (&c2, &c1)
        };
        // Equal value, size and creator: the FR21 rank falls to the hash.
        assert_eq!(head_of(&bc), (3, low.view().hash()), "the lower hash wins");
        let hi = bc.blocks.find(3, &high.view().hash()).expect("loser kept");
        // Story 6.1: the loser is a side block the driver connected.
        assert_eq!(
            bc.blocks.get(hi).map(|e| e.status()),
            Some(BlockStatus::Connected)
        );
        assert!(
            bc.chain_heads.occupied_heads().any(|(h, _)| h == hi),
            "the loser is a tracked side head"
        );
        assert!(!bc.chain_heads.has_stored_head(), "and a Connected one");
    }

    // --- AC10.4: invalid direct extension (AC3, AC2) ------------------------

    /// Feeds `bad` to a node and asserts the AC3 refusal: `InvalidEvidence`,
    /// nothing stored, and every piece of derived state identical to a twin
    /// that never saw it (AC2). `reason` pins why, against a third twin.
    fn assert_refused_at_intake(
        build: impl Fn() -> TestChain,
        bad: &Block,
        reason: ValidationReason,
    ) {
        let mut bc = build();
        let twin = build();
        let mut probe = build();
        assert_eq!(step_reason(&mut probe, bad), Some(reason));
        assert_same_state(&probe, &twin, "the probe left nothing behind");
        let free = bc.blocks.next_free_index().expect("a free slot");
        assert_eq!(
            receive(&mut bc, bad),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_same_state(&bc, &twin, "refused extension");
        assert_eq!(bc.blocks.next_free_index(), Some(free), "no slot used");
        assert!(same_slot(&bc, &twin, free), "storage unchanged");
    }

    #[test]
    fn invalid_direct_extension_is_not_stored_and_leaves_no_trace() {
        let genesis = || ready_genesis(16).0;
        let (_, _, b1) = ready_genesis(16);
        let prev = b1.view().hash();
        // Insufficient balance after an earlier, valid transfer in the block.
        let ok = transfer_tx(2, 0, 10);
        let broke = transfer_tx(2, 0, CURRENCY);
        let overspend = tx_block(2, prev, 0, |b| {
            b.add_node_transfer(&ok).ok().expect("first");
            b.add_node_transfer(&broke).ok().expect("second");
        });
        assert_refused_at_intake(genesis, &overspend, ValidationReason::InsufficientBalance);

        // A duplicate key after an earlier registration's debit and seeding.
        let first = registration_tx(0, 1, 0xB1);
        let dup = registration_tx(0, 2, 0xB1);
        let duplicate = tx_block(2, prev, 0, |b| {
            b.add_registration(&first).ok().expect("first");
            b.add_registration(&dup).ok().expect("second");
        });
        assert_refused_at_intake(genesis, &duplicate, ValidationReason::DuplicatePublicKey);

        // A UTXO spend after an earlier input spent the same output.
        let utxo = || utxo_genesis().0;
        let (_, mint) = utxo_genesis();
        let spend = utxo_tx(4, &[(3, 0, 60)], None, &[Err((1, 60))]);
        let again = utxo_tx(4, &[(3, 0, 60)], None, &[Err((1, 60))]);
        let double = complex_tx_block(4, mint.view().hash(), 0, 0, &[&spend, &again]);
        assert_refused_at_intake(utxo, &double, ValidationReason::UtxoUnavailable);
    }

    // --- AC10.5: invalid stored child (AC4, AC5) ----------------------------

    #[test]
    fn invalid_stored_child_is_deleted_with_its_descendants() {
        let (mut bc, _, b1) = ready_genesis(16);
        let (mut twin, _, _) = ready_genesis(16);
        let a = transfer(2, b1.view().hash(), 0, 7);
        let bad = transfer(3, a.view().hash(), 0, CURRENCY);
        let below = transfer(4, bad.view().hash(), 0, 8);
        for block in [&below, &bad] {
            assert_eq!(
                receive(&mut bc, block),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert_eq!(bc.blocks.len(), 4, "both orphans stored");

        assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(
            receive(&mut twin, &a),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&bc), (2, a.view().hash()), "A stays the head");
        assert!(
            bc.blocks.find(3, &bad.view().hash()).is_none(),
            "child deleted"
        );
        assert!(
            bc.blocks.find(4, &below.view().hash()).is_none(),
            "with its descendant"
        );
        assert!(bc.is_ready(), "no FR5 recovery in Ready");
        // Nothing of the failed child reached the derived state.
        assert!(bc.node_info == twin.node_info);
        assert!(bc.vote_engine == twin.vote_engine);
    }

    // --- AC10.6: local failures (AC6) ---------------------------------------

    /// A backend that can fail reads of one slot and every block write.
    struct FaultyStorage {
        inner: MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        failing_read_slot: u32,
        fail_saves: bool,
    }

    impl StorageTrait for FaultyStorage {
        fn init(
            &mut self,
            private_key: [u8; PRIVATE_KEY_SIZE],
            own_node_id: u32,
            init_params: [u8; INIT_PARAMS_SIZE],
        ) -> Result<(), StorageError> {
            self.inner.init(private_key, own_node_id, init_params)
        }

        fn save_block(&mut self, idx: u32, block: &Block) -> Result<(), StorageError> {
            if self.fail_saves {
                return Err(StorageError::BackendIo { code: 7 });
            }
            self.inner.save_block(idx, block)
        }

        fn read_block_into(
            &self,
            idx: u32,
            out: &mut [u8; MAX_BLOCK_SIZE],
        ) -> Result<(), StorageError> {
            if idx == self.failing_read_slot {
                return Err(StorageError::BackendIo { code: 9 });
            }
            self.inner.read_block_into(idx, out)
        }

        fn capacity(&self) -> u32 {
            self.inner.capacity()
        }

        fn set_chain_configuration(&mut self, block: &Block) -> Result<(), StorageError> {
            self.inner.set_chain_configuration(block)
        }

        fn load_control_data(&mut self) -> Result<ControlPlaneData, StorageError> {
            self.inner.load_control_data()
        }
    }

    /// [`utxo_genesis`] on a [`FaultyStorage`] whose faults are disarmed.
    fn faulty_utxo_genesis() -> (Chain16<FaultyStorage>, Block) {
        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
        let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let storage = FaultyStorage {
            inner: initialized_storage([1u8; PRIVATE_KEY_SIZE]),
            failing_read_slot: NONE_REF,
            fail_saves: false,
        };
        let mut slot = core::mem::MaybeUninit::<Chain16<FaultyStorage>>::uninit();
        Chain16::<FaultyStorage>::init(&mut slot, crypto, storage, chain_config, 0, node_zero, 0);
        // SAFETY: `init` returned, so every field of `slot` is initialized.
        let mut bc = unsafe { slot.assume_init() };
        let genesis = bc
            .process_genesis(CURRENCY, window_config_builder(16).content())
            .ok()
            .expect("genesis");
        let reg = register(2, genesis.block_one.view().hash(), 1, 0xB1);
        assert_eq!(
            receive(&mut bc, &reg),
            ReceiveBlockOutcome::AcceptedSilently
        );
        // Its vote credits node #1 once, so a block of node #1 above it is
        // worth `I(1000)` (Story 6.3: the side-branch fixtures need an active
        // branch their small free values do not outrank).
        let mint_tx = utxo_tx_vote(1, 3, &[], Some((0, 100)), &[Ok(60), Ok(40)]);
        let mint = complex_tx_block(3, reg.view().hash(), 0, 0, &[&mint_tx]);
        assert_eq!(
            receive(&mut bc, &mint),
            ReceiveBlockOutcome::AcceptedSilently
        );
        (bc, mint)
    }

    #[test]
    fn read_failure_at_intake_stores_the_extension_and_retries_it() {
        let (mut bc, mint) = faulty_utxo_genesis();
        let (twin, _) = faulty_utxo_genesis();
        let mint_idx = bc.active_chain_head_idx;
        let tx = utxo_tx(4, &[(3, 1, 40)], None, &[Err((1, 40))]);
        let spend = complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]);

        bc.storage.failing_read_slot = mint_idx;
        assert_eq!(
            receive(&mut bc, &spend),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let si = bc
            .blocks
            .find(4, &spend.view().hash())
            .expect("stored, not blamed");
        assert_eq!(
            bc.blocks.get(si).map(|e| e.status()),
            Some(BlockStatus::Stored)
        );
        assert_eq!(bc.active_chain_head_idx, mint_idx, "head unchanged");
        assert!(bc.node_info == twin.node_info, "derived state unchanged");
        assert!(bc.vote_engine == twin.vote_engine);
        assert_eq!(
            bc.blocks.utxo_available(mint_idx, 1),
            Some(true),
            "bit restored"
        );

        // The fault clears; the next admission — any block — extends it.
        bc.storage.failing_read_slot = NONE_REF;
        let unrelated = node_transfer_block(9, 3, 8, 7);
        assert_eq!(
            receive(&mut bc, &unrelated),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(bc.active_chain_head_idx, si, "the retry extended the head");
        assert_eq!(bc.blocks.utxo_available(mint_idx, 1), Some(false));
        assert_eq!(bc.node_info.balance_of(1), 40);
    }

    #[test]
    fn save_failure_inverts_the_extension_and_is_unstorable() {
        let (mut bc, mint) = faulty_utxo_genesis();
        let (twin, _) = faulty_utxo_genesis();
        let tx = utxo_tx(4, &[(3, 1, 40)], Some((0, 5)), &[Err((1, 44))]);
        let spend = complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]);
        bc.storage.fail_saves = true;
        assert_eq!(
            receive(&mut bc, &spend),
            ReceiveBlockOutcome::Rejected(RejectReason::Unstorable)
        );
        assert_same_state(&bc, &twin, "save failure");
    }

    // --- AC10.7: the window path --------------------------------------------

    /// A genesis node on `W = 4` with #2 and #3 added: the window is full
    /// (`0..=3`), and its tail #0 is node #0's seed source (its registration).
    fn full_w4_genesis() -> (TestChain, Block) {
        let (mut bc, _, b1) = ready_genesis(4);
        let b2 = transfer(2, b1.view().hash(), 0, 7);
        let b3 = transfer(3, b2.view().hash(), 0, 8);
        for block in [&b2, &b3] {
            assert_eq!(
                receive(&mut bc, block),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert_eq!(bc.active_snake_chain_window(), Ok((0, 3)));
        (bc, b3)
    }

    fn snapshot_block<S: StorageTrait>(bc: &Chain16<S>, seq: u32, prev: [u8; 32]) -> Block {
        balance_block(
            seq,
            prev,
            &[node_zero_snapshot(bc)],
            bc.node_info.max_known_node_id(),
        )
    }

    #[test]
    fn window_extension_past_w_advances_and_binds() {
        // Binding `Invalid` at intake: dropping #0 needs a balance block (FR50).
        let (mut bc, b3) = full_w4_genesis();
        let (twin, _) = full_w4_genesis();
        let plain = transfer(4, b3.view().hash(), 0, 9);
        assert_eq!(
            receive(&mut bc, &plain),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_same_state(&bc, &twin, "binding refusal stores nothing");

        // A stored child failing its binding is deleted. The snapshot at #4
        // advances the tail to #1 (chain-config), so a transfer at #5 cannot
        // drop it (FR49) — admitted first as an orphan, judged by continuation.
        let replay = snapshot_block(&bc, 4, b3.view().hash());
        let child = transfer(5, replay.view().hash(), 0, 9);
        assert_eq!(
            receive(&mut bc, &child),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            receive(&mut bc, &replay),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&bc), (4, replay.view().hash()));
        assert_eq!(
            bc.active_snake_chain_window(),
            Ok((1, 4)),
            "the extension past W advanced the tail in the same step"
        );
        assert!(
            bc.blocks.find(0, &bc_genesis_hash()).is_none(),
            "#0 released"
        );
        assert!(
            bc.blocks.find(5, &child.view().hash()).is_none(),
            "child deleted"
        );
        let replay_idx = bc.active_chain_head_idx;
        assert!(
            bc.node_info.is_seed_source(replay_idx),
            "D9: the seed source moved"
        );
    }

    /// Block #0 of every genesis node in this section (it is deterministic).
    fn bc_genesis_hash() -> [u8; 32] {
        ready_genesis(16).1.view().hash()
    }

    /// AC10.7 — a classification failure is a local one: no mutation, no
    /// verdict. Since Story 6.11 the classification reads no storage, so its
    /// only failure is a tail naming an empty slot; that is reached here by
    /// corrupting the index and judging directly, since `receive_block`'s FR60
    /// window asserts the same invariant in debug builds.
    #[test]
    fn window_classification_failure_changes_nothing() {
        let (mut bc, b3) = full_w4_genesis();
        let (twin, _) = full_w4_genesis();
        let real_tail = bc.snake_chain_tail_idx;
        let replay = snapshot_block(&bc, 4, b3.view().hash());
        let view = replay.view();
        let idx = bc.blocks.next_free_index().expect("free");
        let head = bc.active_chain_head_idx;
        bc.blocks
            .insert_at(idx, BlockEntry::new(view.hash(), head, view.sequence()));
        bc.snake_chain_tail_idx = idx + 1; // an empty slot
        assert!(matches!(
            bc.judge_head_extension(&view, idx, bc.snake_chain_tail_idx),
            Extension::Local
        ));
        bc.snake_chain_tail_idx = real_tail;
        bc.blocks.delete(idx);
        assert_same_state(&bc, &twin, "classification failure");

        // With the tail readable again, the same block extends the head.
        assert_eq!(
            receive(&mut bc, &replay),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&bc), (4, replay.view().hash()));
    }

    // --- AC10.8: genesis-node equivalence (AC8) -----------------------------

    #[test]
    fn genesis_node_and_mesh_node_derive_the_same_state() {
        let (mut g, b0, b1) = ready_genesis(16);
        assert_eq!(
            g.blocks.get(0).map(|e| e.status()),
            Some(BlockStatus::Active)
        );
        assert_eq!(
            g.blocks.get(1).map(|e| e.status()),
            Some(BlockStatus::Active)
        );
        let mut m = new_unconfigured_test_chain();
        for block in [&b0, &b1] {
            assert_eq!(
                receive(&mut m, block),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert!(m.is_ready(), "the mesh node joined through FR3");
        let reg = register(2, b1.view().hash(), 1, 0xB1);
        let t3 = transfer(3, reg.view().hash(), 1, 100);
        for block in [&reg, &t3] {
            assert_eq!(
                receive(&mut g, block),
                ReceiveBlockOutcome::AcceptedSilently
            );
            assert_eq!(
                receive(&mut m, block),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert!(g.node_info == m.node_info, "node_info");
        assert!(g.vote_engine == m.vote_engine, "votes");
        for idx in 0..4 {
            let (a, b) = (g.blocks.get(idx).expect("g"), m.blocks.get(idx).expect("m"));
            assert_eq!(a.hash(), b.hash());
            assert_eq!(a.status(), b.status());
            assert_eq!(a.is_on_active_chain(), b.is_on_active_chain());
        }
        assert_eq!(head_of(&g), head_of(&m));
    }

    // --- AC10.9: FR3 / restart / double-run equivalence (AC9) ---------------

    /// The AC9 sequence on a genesis node: a registration, a transfer, a mined
    /// UTXO mint, a spend, and a matching balance block. Returns the node and
    /// the blocks in chain order, #0 first.
    fn extended_genesis() -> (TestChain, [Block; 7]) {
        let (mut bc, b0, b1) = ready_genesis(16);
        let reg = register(2, b1.view().hash(), 1, 0xB1);
        receive(&mut bc, &reg);
        let t3 = transfer(3, reg.view().hash(), 1, 100);
        receive(&mut bc, &t3);
        let mint_tx = utxo_tx(4, &[], Some((0, 100)), &[Ok(60), Ok(40)]);
        let mint = complex_tx_block(4, t3.view().hash(), 0, 25, &[&mint_tx]);
        receive(&mut bc, &mint);
        let spend_tx = utxo_tx(5, &[(4, 0, 60)], None, &[Err((1, 59))]);
        let spend = complex_tx_block(5, mint.view().hash(), 0, 0, &[&spend_tx]);
        receive(&mut bc, &spend);
        let snap = snapshot_block(&bc, 6, spend.view().hash());
        receive(&mut bc, &snap);
        assert_eq!(
            head_of(&bc),
            (6, snap.view().hash()),
            "every block extended"
        );
        (bc, [b0, b1, reg, t3, mint, spend, snap])
    }

    #[test]
    fn forward_extension_matches_fr3_restart_and_replay() {
        let (a, blocks) = extended_genesis();
        assert_eq!(a.blocks.utxo_available(4, 0), Some(false), "spent");
        assert_eq!(a.blocks.utxo_available(4, 1), Some(true), "unspent");

        // (1) A fresh node receiving the same blocks while Collecting reaches
        // Ready through FR3 over all of them: orphans first, genesis last.
        let mut b = new_unconfigured_test_chain();
        for block in blocks.iter().rev() {
            assert_eq!(
                receive(&mut b, block),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert!(b.is_ready());
        assert_eq!(head_of(&b), head_of(&a));
        assert_eq!(
            b.node_info.max_known_node_id(),
            a.node_info.max_known_node_id()
        );
        for node in 0..16 {
            assert_eq!(b.node_info.balance_of(node), a.node_info.balance_of(node));
            assert_eq!(
                b.node_info.public_key_of(node),
                a.node_info.public_key_of(node)
            );
            assert_eq!(
                b.vote_engine.accumulated_vote_of(node),
                a.vote_engine.accumulated_vote_of(node)
            );
        }
        for block in &blocks {
            let view = block.view();
            let ai = a.blocks.find(view.sequence(), &view.hash()).expect("a");
            let bi = b.blocks.find(view.sequence(), &view.hash()).expect("b");
            let (ea, eb) = (a.blocks.get(ai).expect("a"), b.blocks.get(bi).expect("b"));
            assert_eq!(ea.status(), eb.status(), "#{}", view.sequence());
            assert_eq!(ea.is_on_active_chain(), eb.is_on_active_chain());
            for bit in 0..16 {
                assert_eq!(ea.utxo_available(bit), eb.utxo_available(bit));
            }
            assert_eq!(
                a.node_info.is_seed_source(ai),
                b.node_info.is_seed_source(bi),
                "seed source #{}",
                view.sequence()
            );
        }

        // (2) Restart of A rebuilds the same state from its own slots.
        let (a, _) = extended_genesis();
        let (reference, _) = extended_genesis();
        let mut restarted = restart(a);
        let _ = restarted.initialize_from_storage(0);
        assert!(restarted.is_ready());
        assert!(
            restarted.node_info == reference.node_info,
            "restart node_info"
        );
        assert!(
            restarted.vote_engine == reference.vote_engine,
            "restart votes"
        );
        assert_eq!(head_of(&restarted), head_of(&reference));
        for idx in 0..7 {
            let (x, y) = (
                restarted.blocks.get(idx).expect("restarted"),
                reference.blocks.get(idx).expect("reference"),
            );
            assert_eq!(x.status(), y.status());
            assert_eq!(x.is_on_active_chain(), y.is_on_active_chain());
            for bit in 0..16 {
                assert_eq!(x.utxo_available(bit), y.utxo_available(bit));
            }
        }

        // (3) The same admission sequence twice gives the same state.
        let (twice, _) = extended_genesis();
        assert_same_state(&twice, &reference, "double run");
    }

    // --- AC10.10: chain_heads cache and eviction protection (AC7) -----------

    #[test]
    fn promoted_head_has_current_caches() {
        let (mut bc, _, b1) = ready_genesis(16);
        let a = transfer(2, b1.view().hash(), 0, 7);
        receive(&mut bc, &a);
        let head = bc.active_chain_head_idx;
        assert!(
            bc.chain_heads
                .occupied_heads()
                .any(|(h, anchor)| h == head && anchor == head),
            "the head's entry anchors on the head itself, not the old head"
        );
    }

    // --- AC10.11: balance block (D9) ----------------------------------------

    /// A balance block by node #0 with `mined_amount`.
    fn mined_balance_block(
        seq: u32,
        prev: [u8; 32],
        entries: &[(u32, u64, u32, u8)],
        max_node_id: u32,
        mined: u32,
    ) -> Block {
        use moonblokz_chain_types::NodeInfo;
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let real_key = *signer.public_key().serialize();
        let header = BlockHeader {
            version: 1,
            sequence: seq,
            creator: 0,
            mined_amount: mined,
            payload_type: PAYLOAD_TYPE_BALANCE,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: prev,
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        for &(owner, balance, vote_count, _) in entries {
            let ni = NodeInfo::new(owner, balance, vote_count, &real_key);
            builder.add_node_info(&ni).ok().expect("add node info");
        }
        builder
            .set_max_node_id(max_node_id)
            .ok()
            .expect("max node id");
        builder.build_signed(&signer).ok().expect("build signed")
    }

    #[test]
    fn balance_block_repeats_the_pre_state_in_ready() {
        // Two nodes: #0 (the creator) and #1, registered at #2. A transfer at
        // #3 gives #1 a vote so the snapshot has a non-trivial vote count.
        let build = || {
            let (mut bc, _, b1) = ready_genesis(16);
            let reg = register(2, b1.view().hash(), 1, 0xB1);
            receive(&mut bc, &reg);
            let nt = NodeTransfer::new_signed(
                1,
                2,
                0,
                1,
                10,
                1,
                0,
                &Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key"),
            );
            let t3 = tx_block(3, reg.view().hash(), 0, |b| {
                b.add_node_transfer(&nt).ok().expect("transfer");
            });
            receive(&mut bc, &t3);
            (bc, t3)
        };
        let (mut bc, t3) = build();
        let prev = t3.view().hash();
        let (owner, balance, votes, _) = node_zero_snapshot(&bc);
        assert!(bc.vote_engine.accumulated_vote_of(1) > 0, "precondition");

        // Each mismatching field of a seeded entry is Invalid (FR50).
        for entry in [
            (owner, balance - 1, votes, 0),
            (owner, balance, votes + 1, 0),
            // Node #1's key is `pubkey(0xB1)`; the builder writes node #0's.
            (
                1,
                bc.node_info.balance_of(1),
                bc.vote_engine.accumulated_vote_of(1),
                0,
            ),
        ] {
            let bad = mined_balance_block(4, prev, &[entry], 1, 3);
            assert_eq!(
                step_reason(&mut bc, &bad),
                Some(ValidationReason::BalanceSnapshotMismatch)
            );
        }
        // An entry for a node that does not exist is Invalid in Ready.
        let ghost = mined_balance_block(4, prev, &[(2, 0, 0, 0)], 1, 3);
        assert_eq!(
            step_reason(&mut bc, &ghost),
            Some(ValidationReason::NodeIdOutOfRange)
        );

        // A mismatch as a stored child is deleted, derived state untouched.
        let (mut twin, _) = build();
        let mut bad_child_chain = build().0;
        let filler = transfer(4, prev, 0, 7);
        let bad = mined_balance_block(5, filler.view().hash(), &[(owner, 0, votes, 0)], 1, 3);
        receive(&mut bad_child_chain, &bad);
        receive(&mut bad_child_chain, &filler);
        receive(&mut twin, &filler);
        assert!(
            bad_child_chain.blocks.find(5, &bad.view().hash()).is_none(),
            "deleted"
        );
        assert!(bad_child_chain.node_info == twin.node_info);
        assert!(bad_child_chain.vote_engine == twin.vote_engine);

        // The matching snapshot is accepted: the entries leave balances and
        // votes as they were; only the block-level effects apply.
        let good = mined_balance_block(4, prev, &[(owner, balance, votes, 0)], 1, 3);
        let vote_one = bc.vote_engine.accumulated_vote_of(1);
        assert_eq!(
            receive(&mut bc, &good),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&bc), (4, good.view().hash()));
        assert_eq!(
            bc.node_info.balance_of(0),
            balance + 3,
            "the creator credit"
        );
        assert_eq!(
            bc.vote_engine.accumulated_vote_of(0),
            0,
            "the creator reset"
        );
        assert!(
            bc.vote_engine.accumulated_vote_of(1) >= vote_one,
            "only interest applies to the listed-or-not others"
        );
        let gi = bc.active_chain_head_idx;
        assert!(
            bc.node_info.is_seed_source(gi),
            "node #0's seed source moved"
        );
    }

    #[test]
    fn balance_block_snapshot_is_checked_in_fr3() {
        // A genesis-anchored FR3 pass over a balance block whose snapshot
        // disagrees deletes it (FR5); the matching one is adopted.
        let (g, b0, b1) = ready_genesis(16);
        let (owner, balance, votes, _) = node_zero_snapshot(&g);
        for (entry_balance, adopted) in [(balance + 1, false), (balance, true)] {
            let snap = balance_block(2, b1.view().hash(), &[(owner, entry_balance, votes, 0)], 0);
            let mut m = new_unconfigured_test_chain();
            for block in [&snap, &b1, &b0] {
                receive(&mut m, block);
            }
            assert!(m.is_ready());
            assert_eq!(m.blocks.find(2, &snap.view().hash()).is_some(), adopted);
            assert_eq!(head_of(&m).0, if adopted { 2 } else { 1 });
        }
        // A window-anchored pass seeds an unseeded entry (floor seeding).
        let (mut bc, _) = utxo_test_chain();
        let tip = (0..16u32)
            .find(|&i| bc.blocks.get(i).is_some_and(|e| e.sequence() == 100))
            .expect("#100");
        assert_eq!(bc.run_processing_pass(tip).map(|_| ()), Ok(()));
        assert!(bc.node_info.is_seeded(1));
        assert_eq!(bc.node_info.balance_of(1), 100);
    }

    // --- AC10.12: complete context in Ready (D3) ----------------------------

    #[test]
    fn ready_has_no_trust_zone() {
        let (mut bc, _, b1) = ready_genesis(16);
        let prev = b1.view().hash();
        // An unseeded creator.
        let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
        let header = BlockHeader {
            version: 1,
            sequence: 2,
            creator: 5,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_TRANSACTION,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: prev,
            signature: [0u8; 64],
        };
        let nt = transfer_tx(2, 0, 1);
        let mut builder = BlockBuilder::new().header(header);
        builder.add_node_transfer(&nt).ok().expect("transfer");
        let by_stranger = builder.build_signed(&signer).ok().expect("build");
        assert_eq!(
            step_reason(&mut bc, &by_stranger),
            Some(ValidationReason::UnseededActor)
        );
        // An initializer that is not seeded (here: does not exist).
        let foreign = transfer_block(2, prev, 7, 0, 1, 1, 0);
        assert_eq!(
            step_reason(&mut bc, &foreign),
            Some(ValidationReason::UnseededActor)
        );
        // As a stored child, it is deleted.
        let a = transfer(2, prev, 0, 7);
        let child = transfer_block(3, a.view().hash(), 7, 0, 1, 1, 0);
        receive(&mut bc, &child);
        receive(&mut bc, &a);
        assert_eq!(head_of(&bc), (2, a.view().hash()));
        assert!(bc.blocks.find(3, &child.view().hash()).is_none());
    }

    /// DEC-134 — a `parent_ref` into a freed slot is the node's own index
    /// defect: the pass reports `MissingBlock`, the recovery deletes nothing,
    /// unlinks the dangling reference, and the block becomes a Stored
    /// tail-point that FR19 asks its real parent for.
    #[test]
    fn missing_block_repairs_the_index_and_deletes_nothing() {
        let mut bc = new_test_chain();
        let genesis = node_transfer_block(0, 0, 0, 0);
        bc.tier1_admit(&genesis.view(), &genesis.view().hash(), 0)
            .expect("genesis admitted");
        let b1 = transfer_block(1, genesis.view().hash(), 1, 2, 100, 1, 0);
        bc.tier1_admit(&b1.view(), &b1.view().hash(), 0)
            .expect("b1 admitted");
        let b2 = transfer_block(2, b1.view().hash(), 1, 2, 100, 1, 0);
        let bi2 = bc
            .tier1_admit(&b2.view(), &b2.view().hash(), 0)
            .expect("b2 admitted");
        // The defect: b2 names a slot that holds no block.
        let freed = bc.blocks.next_free_index().expect("free");
        bc.blocks.set_parent_ref(bi2, NONE_REF);
        bc.blocks.set_parent_ref(bi2, freed);

        bc.set_lifecycle_phase(LifecyclePhase::Processing);
        let err = bc
            .run_processing_pass(bi2)
            .expect_err("the walk meets the freed slot");
        assert_eq!(err, ProcessingError::MissingBlock);
        bc.recover_from_failed_pass(err, bi2);

        assert_eq!(bc.blocks.len(), 3, "nothing deleted");
        assert_eq!(bc.current_phase(), LifecyclePhase::Collecting);
        assert_eq!(
            bc.blocks.get(bi2).map(|e| e.parent_ref()),
            Some(NONE_REF),
            "unlinked"
        );
        assert!(
            (0..4).any(|slot| bc.chain_heads.stored_head_tail(slot) == Some(bi2)),
            "b2 is a Stored tail-point"
        );
        let (outcome, _) = bc.on_tick(u64::MAX / 2);
        match outcome {
            TickOutcome::SendParentRecoveryRequest(req) => {
                assert_eq!(
                    req.missing_parent_hash(),
                    &b1.view().hash(),
                    "asks for its parent"
                );
                assert_eq!(req.claimed_parent_sequence(), 1);
            }
            _ => panic!("a parent-recovery request is due"),
        }
    }

    // --- Code review 2026-10-18 -------------------------------------------

    /// Review patch — a registration by a not-yet-seeded initializer (a
    /// window-anchored pass, before its seed source) still pays its fee to a
    /// seeded creator, so the creator's balance stays exact for D9.
    #[test]
    fn registration_fee_reaches_the_creator_when_the_initializer_is_unseeded() {
        let mut bc = new_test_chain();
        let cfg_hash = admit_chain_config_anchor(&mut bc, 99, [0xAB; 32]);
        // Node 0 (the creator) is listed; node 4 exists but is not.
        let seed = balance_block(100, cfg_hash, &[(0, 1_000, 0, 0)], 4);
        admit(&mut bc, &seed);
        let reg = registration_block(101, seed.view().hash(), 4, 5, 0xC5);
        let tip = admit(&mut bc, &reg);
        assert_eq!(bc.run_processing_pass(tip).map(|_| ()), Ok(()));
        assert!(
            !bc.node_info.is_seeded(4),
            "precondition: unseeded initializer"
        );
        assert_eq!(
            bc.node_info.balance_of(0),
            1_001,
            "the fee reached the creator"
        );
    }

    /// Review patch — a complex transaction that fails after a UTXO spend, a
    /// balance-input debit and a balance-output credit is inverted exactly.
    #[test]
    fn partially_applied_complex_transaction_is_inverted_exactly() {
        let (mut bc, mint) = utxo_genesis();
        let (twin, _) = utxo_genesis();
        // Node 9 does not exist: the second output fails its range check.
        let cx = utxo_tx(4, &[(3, 0, 60)], Some((0, 10)), &[Err((1, 5)), Err((9, 5))]);
        let block = complex_tx_block(4, mint.view().hash(), 0, 0, &[&cx]);
        assert_eq!(
            step_reason(&mut bc, &block),
            Some(ValidationReason::NodeIdOutOfRange)
        );
        assert_same_state(&bc, &twin, "partial complex inversion");
    }

    /// Review patch — a credit that would overflow the creator's balance is
    /// `BalanceOverflow`, and nothing of the block remains applied.
    #[test]
    fn creator_credit_overflow_is_invalid() {
        let build = || {
            let (crypto, storage, chain_config) = test_backends();
            let mut bc = new_chain(crypto, storage, chain_config, 0, 0);
            let genesis = bc
                .process_genesis(u64::MAX, window_config_builder(16).content())
                .ok()
                .expect("genesis succeeds");
            (bc, genesis.block_one)
        };
        let (mut bc, b1) = build();
        let (twin, _) = build();
        // A self-transfer pays its fee of 1 back to node #0, the creator,
        // whose balance is then `u64::MAX - 1`; `mined_amount = 2` overflows.
        let nt = transfer_tx(2, 0, 1);
        let block = tx_block(2, b1.view().hash(), 2, |b| {
            b.add_node_transfer(&nt).ok().expect("transfer");
        });
        assert_eq!(
            step_reason(&mut bc, &block),
            Some(ValidationReason::BalanceOverflow)
        );
        assert_same_state(&bc, &twin, "overflow refusal");
    }

    /// DEC-138 — the vote apply runs before `chain_heads` learns of a direct
    /// extension. A local refusal there (no vote parameters) keeps the block,
    /// written and Stored, tracked as a head, with the derivation inverted.
    #[test]
    fn local_vote_refusal_after_the_write_keeps_the_extension_stored() {
        let (mut bc, _, b1) = ready_genesis(16);
        let (twin, _, _) = ready_genesis(16);
        // An engine that holds no FR37 parameters (the test oracle's state).
        bc.vote_engine = VoteEngine::new();
        let a = transfer(2, b1.view().hash(), 0, 7);
        assert_eq!(receive(&mut bc, &a), ReceiveBlockOutcome::AcceptedSilently);
        let ai = bc.blocks.find(2, &a.view().hash()).expect("stored");
        assert_eq!(
            bc.blocks.get(ai).map(|e| e.status()),
            Some(BlockStatus::Stored)
        );
        assert_eq!(head_of(&bc).0, 1, "the head did not move");
        assert!(
            bc.chain_heads.occupied_heads().any(|(h, _)| h == ai),
            "tracked as a head"
        );
        assert!(
            bc.node_info == twin.node_info,
            "the derivation was inverted"
        );
    }

    // ===================================================================
    // Story 6.1 — FR21 branch value and side-block Tier 2
    // ===================================================================

    /// `block` rebuilt with header `consumed_votes` — its FR21 value — and
    /// re-signed by node #0. Transaction and chain-config payloads. On the
    /// active chain the value must be real (I-09, Story 6.2): use [`alt`] or
    /// [`real_on`] there; `revalue` serves side blocks, which get no Tier 3.
    fn revalue(block: &Block, consumed_votes: u32) -> Block {
        let view = block.view();
        resign(block, view.creator(), consumed_votes, 1)
    }

    /// `block`'s payload under a header by `creator` (signed with the key
    /// `[key; 32]`) in the normal vote form, worth `consumed_votes`.
    fn resign(block: &Block, creator: u32, consumed_votes: u32, key: u8) -> Block {
        let view = block.view();
        let signer = Crypto::new([key; PRIVATE_KEY_SIZE]).ok().expect("test key");
        let header = BlockHeader {
            version: view.version(),
            sequence: view.sequence(),
            creator,
            mined_amount: view.mined_amount(),
            payload_type: view.payload_type(),
            consumed_votes,
            first_voted_node: creator,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: view.previous_hash().try_into().expect("32 bytes"),
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        if let Some(txs) = view.transactions() {
            for tx in txs.iter() {
                builder
                    .add_transaction_bytes(tx.as_bytes())
                    .ok()
                    .expect("transaction");
            }
        } else {
            builder
                .set_chain_config_payload(view.payload())
                .ok()
                .expect("chain-config payload");
        }
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// A node #0 self-transfer of `amount` at `seq`, worth `value` — a free
    /// header value, so for side blocks only (see [`revalue`]).
    fn valued(seq: u32, prev: [u8; 32], value: u32, amount: u64) -> Block {
        revalue(&transfer(seq, prev, 0, amount), value)
    }

    // ===================================================================
    // Story 6.2 — real vote headers for active-chain fixtures (I-09)
    // ===================================================================

    /// Node #1's key byte wherever these fixtures register it.
    const NODE_ONE_KEY: u8 = 0xB1;

    /// `I(av)`: FR37 step 1 under the test configuration (`vote_scale` 1000,
    /// `vote_interest` 5, so the bump is `min(⌊av / 200⌋, 1000)`) — the
    /// post-interest, pre-credit snapshot a block's `consumed_votes` carries
    /// (DEC-156).
    fn vote_snapshot(av: u32) -> u32 {
        av + (av / 200).min(1000)
    }

    /// The FR21 value of `block`: its header `consumed_votes`.
    fn v(block: &Block) -> u64 {
        u64::from(block.view().consumed_votes())
    }

    /// `n` node-#0 self-transfers at `seq` whose `vote` names `target`, their
    /// amounts from `salt` (distinct transactions).
    fn votes_for(seq: u32, target: u32, n: u32, salt: u64) -> impl FnOnce(&mut BlockBuilder) {
        move |b| {
            let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("test key");
            for i in 0..n {
                let nt = NodeTransfer::new_signed(
                    target,
                    seq - 1,
                    0,
                    0,
                    salt + u64::from(i),
                    1,
                    0,
                    &signer,
                );
                b.add_node_transfer(&nt).ok().expect("add vote");
            }
        }
    }

    /// An active-chain block by node `creator` (#0 or #1) carrying its real
    /// FR21 value on a chain whose creators alternate between #0 and #1, each
    /// block crediting only the next creator. `received` is the number of
    /// credits the previous block gave `creator` — its whole accumulated vote,
    /// since its own last block reset it — so `consumed_votes =
    /// I(1000 · received)` (= `1005 · received` while `received ≤ 200`, below
    /// the interest cap). The block casts `out` credits
    /// for the other node (or, with `out == 0`, one for its own creator, which
    /// the reset wipes). `register` puts node #1's registration first.
    fn alt(
        seq: u32,
        prev: [u8; 32],
        creator: u32,
        received: u32,
        out: u32,
        salt: u64,
        register: bool,
    ) -> Block {
        let other = 1 - creator;
        let template = tx_block(seq, prev, 0, |b| {
            if register {
                b.add_registration(&registration_tx(0, 1, NODE_ONE_KEY))
                    .ok()
                    .expect("add registration");
            }
            if out == 0 {
                votes_for(seq, creator, 1, salt)(b);
            } else {
                votes_for(seq, other, out, salt)(b);
            }
        });
        let key = if creator == 0 { 1 } else { NODE_ONE_KEY };
        resign(&template, creator, vote_snapshot(1000 * received), key)
    }

    /// `block` as `creator`'s (signed with `key`), worth its real FR21 value on
    /// `state` — the chain whose active head is the block's parent (I-09).
    fn real_on<
        C: CryptoTrait,
        S: StorageTrait,
        G: ChainConfigTrait,
        const N: usize,
        const L: u32,
        const B: usize,
        const H: usize,
        const U: usize,
    >(
        state: &Blockchain<C, S, G, N, L, B, H, U>,
        block: &Block,
        creator: u32,
        key: u8,
    ) -> Block {
        let av = state.vote_engine.accumulated_vote_of(creator);
        resign(block, creator, vote_snapshot(av), key)
    }

    /// FR21 by brute force: the values of `head`'s ancestry above `S_tail`,
    /// read back from storage block by block.
    fn brute_value<
        C: CryptoTrait,
        S: StorageTrait,
        G: ChainConfigTrait,
        const N: usize,
        const L: u32,
        const B: usize,
        const H: usize,
        const U: usize,
    >(
        bc: &Blockchain<C, S, G, N, L, B, H, U>,
        head: u32,
    ) -> u64 {
        let tail = bc
            .blocks
            .get(bc.snake_chain_tail_idx)
            .expect("a tail")
            .sequence();
        let mut sum = 0;
        let mut cur = head;
        loop {
            let entry = bc.blocks.get(cur).expect("on the path");
            if entry.sequence() <= tail {
                return sum;
            }
            let mut buf = [0u8; MAX_BLOCK_SIZE];
            sum += u64::from(
                bc.view_retained(cur, &mut buf)
                    .expect("readable")
                    .consumed_votes(),
            );
            cur = entry.parent_ref();
        }
    }

    fn slot<
        C: CryptoTrait,
        S: StorageTrait,
        G: ChainConfigTrait,
        const N: usize,
        const L: u32,
        const B: usize,
        const H: usize,
        const U: usize,
    >(
        bc: &Blockchain<C, S, G, N, L, B, H, U>,
        block: &Block,
    ) -> u32 {
        let view = block.view();
        bc.blocks
            .find(view.sequence(), &view.hash())
            .expect("retained")
    }

    fn status_of<S: StorageTrait>(bc: &Chain16<S>, block: &Block) -> Option<BlockStatus> {
        let view = block.view();
        bc.blocks
            .find(view.sequence(), &view.hash())
            .and_then(|idx| bc.blocks.get(idx))
            .map(|entry| entry.status())
    }

    /// The window-anchored W4 segment `100..=103` with the values 2 (the
    /// chain-config anchor), 3, 5, 7, Ready through FR3. Returns the node and
    /// the four blocks.
    fn valued_w4() -> (W4Chain, [Block; 4]) {
        let mut bc = new_w4_chain();
        let anchor = revalue(&w4_config_anchor_block(100, [0xAB; 32]), 2);
        let b101 = revalue(&linked_transfer_block(101, anchor.view().hash()), 3);
        let b102 = revalue(&linked_transfer_block(102, b101.view().hash()), 5);
        let b103 = revalue(&linked_transfer_block(103, b102.view().hash()), 7);
        for blk in [&anchor, &b101, &b102, &b103] {
            bc.tier1_admit(&blk.view(), &blk.view().hash(), 0)
                .expect("admitted");
        }
        bc.drive_dominant_chain_acquisition();
        assert!(bc.is_ready(), "precondition: the segment validated");
        (bc, [anchor, b101, b102, b103])
    }

    /// AC10.1 / AC3 — seeding at every Ready entry: the genesis node holds 0
    /// (its block #1 carries no value), a genesis-anchored mesh join sums
    /// `(#0, #1]`, a window-anchored FR3 join sums its window — each equal to
    /// the brute force.
    #[test]
    fn branch_value_is_seeded_at_every_ready_entry() {
        let (genesis, _, _) = ready_genesis(16);
        assert_eq!(genesis.active_branch_value, 0);
        assert_eq!(
            genesis.active_branch_value,
            brute_value(&genesis, genesis.active_chain_head_idx)
        );
        // A genesis-anchored mesh join over #0..#3, orphans first: #1 and #2
        // are node #0's (worth 0), #3 node #1's after 3 credits (real values,
        // I-09).
        let (_, b0, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 3, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 3, 0, 8, false);
        let mut mesh = new_unconfigured_test_chain();
        for blk in [&a3, &a2, &b1, &b0] {
            assert_eq!(
                receive(&mut mesh, blk),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert!(mesh.is_ready());
        assert_eq!(head_of(&mesh), (3, a3.view().hash()));
        assert_eq!(v(&a3), 3015);
        assert_eq!(
            mesh.active_branch_value,
            v(&b1) + v(&a2) + v(&a3),
            "#1..#3 count, #0 is S_tail"
        );
        assert_eq!(
            mesh.active_branch_value,
            brute_value(&mesh, mesh.active_chain_head_idx)
        );
        let (w4, _) = valued_w4();
        assert_eq!(w4.active_branch_value, 3 + 5 + 7, "the anchor is S_tail");
        assert_eq!(
            w4.active_branch_value,
            brute_value(&w4, w4.active_chain_head_idx)
        );
    }

    /// AC10.3 / AC5 / AC9 — a tail advance subtracts the block that becomes
    /// `S_tail`, from the active value and from a side head forked at it; a
    /// fresh node reaching Ready through FR3 over the same blocks holds the
    /// same values.
    #[test]
    fn tail_advance_subtracts_the_new_tail_everywhere() {
        let (mut a, [anchor, b101, b102, b103]) = valued_w4();
        // A fork at #101, judged before its write (D4) and valued by the walk.
        let side = revalue(&salted_linked_block(102, b101.view().hash(), 6), 13);
        assert_eq!(
            a.receive_block(side.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
        let si = slot(&a, &side);
        assert_eq!(
            a.blocks.get(si).map(|e| e.status()),
            Some(BlockStatus::Connected)
        );
        assert_eq!(a.chain_heads.branch_value_of(si), Some(3 + 13));
        assert_eq!(a.chain_heads.branch_value_of(si), Some(brute_value(&a, si)));

        // Dropping the chain-config anchor needs a chain-config extension.
        let b104 = real_on(&a, &w4_config_anchor_block(104, b103.view().hash()), 0, 1);
        extend_active_head(&mut a, &b104, 0);
        assert_eq!(a.active_snake_chain_window(), Ok((101, 104)));
        assert_eq!(
            a.active_branch_value,
            5 + 7 + v(&b104),
            "#101 left the sum, #100 never was in it"
        );
        assert_eq!(
            a.active_branch_value,
            brute_value(&a, a.active_chain_head_idx)
        );
        assert_eq!(a.chain_heads.branch_value_of(si), Some(13));
        assert_eq!(a.chain_heads.branch_value_of(si), Some(brute_value(&a, si)));

        // A fresh node, orphans first, reaches the same values through FR3 —
        // on `101..=104`, already `W` long, so the anchor is never needed.
        let _ = anchor;
        let mut b = new_w4_chain();
        for blk in [&side, &b104, &b103, &b102, &b101] {
            assert_eq!(
                b.receive_block(blk.view(), 0).0,
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert!(b.is_ready());
        assert_eq!(b.active_branch_value, a.active_branch_value);
        let bs = slot(&b, &side);
        assert_eq!(
            b.blocks.get(bs).map(|e| e.status()),
            Some(BlockStatus::Connected)
        );
        assert_eq!(b.chain_heads.branch_value_of(bs), Some(13));
    }

    /// A genesis node on a [`FaultyStorage`] whose faults are disarmed, on
    /// `W = w`.
    fn faulty_genesis(w: u16) -> (Chain16<FaultyStorage>, Block) {
        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
        let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let storage = FaultyStorage {
            inner: initialized_storage([1u8; PRIVATE_KEY_SIZE]),
            failing_read_slot: NONE_REF,
            fail_saves: false,
        };
        let mut slot = core::mem::MaybeUninit::<Chain16<FaultyStorage>>::uninit();
        Chain16::<FaultyStorage>::init(&mut slot, crypto, storage, chain_config, 0, node_zero, 0);
        // SAFETY: `init` returned, so every field of `slot` is initialized.
        let mut bc = unsafe { slot.assume_init() };
        let genesis = bc
            .process_genesis(CURRENCY, window_config_builder(w).content())
            .ok()
            .expect("genesis");
        (bc, genesis.block_one)
    }

    /// AC10.3 / AC5 — the new tail's value is read before anything changes: a
    /// failed read is a local failure, and the next admission extends.
    #[test]
    fn failed_new_tail_read_is_a_local_failure() {
        let (mut bc, b1) = faulty_genesis(4);
        let b2 = alt(2, b1.view().hash(), 0, 0, 2, 7, true);
        let b3 = alt(3, b2.view().hash(), 1, 2, 0, 8, false);
        for blk in [&b2, &b3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        let before = bc.active_branch_value;
        let snapshot = snapshot_block(&bc, 4, b3.view().hash());
        bc.storage.failing_read_slot = 1; // #1 becomes the tail
        assert_eq!(
            receive(&mut bc, &snapshot),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&bc), (3, b3.view().hash()), "not extended");
        assert_eq!(status_of(&bc, &snapshot), Some(BlockStatus::Stored));
        assert_eq!(bc.active_branch_value, before);
        assert_eq!(bc.active_snake_chain_window(), Ok((0, 3)));

        bc.storage.failing_read_slot = NONE_REF;
        let unrelated = node_transfer_block(3, 3, 2, 7);
        assert_eq!(
            receive(&mut bc, &unrelated),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            head_of(&bc),
            (4, snapshot.view().hash()),
            "the retry extended"
        );
        assert_eq!(bc.active_snake_chain_window(), Ok((1, 4)));
        assert_eq!(v(&b3), 2010);
        assert_eq!(bc.active_branch_value, v(&b2) + v(&b3) + v(&snapshot));
        assert_eq!(
            bc.active_branch_value,
            brute_value(&bc, bc.active_chain_head_idx)
        );
    }

    /// AC10.2 / AC4 — event (i) for both entry points: a direct extension, and
    /// a continuation over a stored orphan.
    #[test]
    fn branch_value_follows_direct_and_continuation_extensions() {
        let (mut bc, _, b1) = ready_genesis(16);
        let b2 = alt(2, b1.view().hash(), 0, 0, 5, 7, true);
        assert_eq!(receive(&mut bc, &b2), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(bc.active_branch_value, v(&b2));
        let b3 = alt(3, b2.view().hash(), 1, 5, 3, 8, false);
        let b4 = alt(4, b3.view().hash(), 0, 3, 7, 9, false);
        assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(receive(&mut bc, &b3), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (4, b4.view().hash()));
        assert_eq!((v(&b3), v(&b4)), (5025, 3015), "distinct real values");
        assert_eq!(bc.active_branch_value, v(&b2) + v(&b3) + v(&b4));
        assert_eq!(
            bc.active_branch_value,
            brute_value(&bc, bc.active_chain_head_idx)
        );
    }

    /// Two siblings of `parent` (node #0's, which gave node #1 `credits`) at
    /// `seq`: node #1's, worth its real `I(1000 · credits)`, and node #0's side
    /// block with the free value `low`, where the higher-valued one has the
    /// higher hash — so the hash alone would pick the other. Returns
    /// `(high, low)`.
    fn ranked_pair(seq: u32, parent: [u8; 32], credits: u32, low: u32) -> (Block, Block) {
        for amount in 10..200 {
            let h = alt(seq, parent, 1, credits, 0, amount, false);
            let l = valued(seq, parent, low, amount + 1000);
            if h.view().hash() > l.view().hash() {
                return (h, l);
            }
        }
        panic!("no pair found");
    }

    /// AC10.6 / AC8 — the continuation's sibling choice is the FR21 rank: the
    /// higher value wins over a lower hash, and on an equal value the larger
    /// block wins. The other sibling becomes a Connected side head.
    #[test]
    fn sibling_choice_follows_the_fr21_rank() {
        let (mut bc, _, b1) = ready_genesis(16);
        let parent = alt(2, b1.view().hash(), 0, 0, 9, 7, true);
        let (high, low) = ranked_pair(3, parent.view().hash(), 9, 4);
        for blk in [&low, &high, &parent] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(head_of(&bc), (3, high.view().hash()), "value before hash");
        let li = slot(&bc, &low);
        assert_eq!(status_of(&bc, &low), Some(BlockStatus::Connected));
        assert_eq!(bc.chain_heads.branch_value_of(li), Some(v(&parent) + 4));
        assert_eq!(
            bc.chain_heads.branch_value_of(li),
            Some(brute_value(&bc, li))
        );

        // Equal value: the larger block wins, even with the higher hash.
        // `large` is node #1's real block (two transactions); `small` a side
        // block with the same free value.
        let (mut bc, _, b1) = ready_genesis(16);
        let parent = alt(2, b1.view().hash(), 0, 0, 6, 7, true);
        let prev = parent.view().hash();
        let (large, small) = (0..200)
            .find_map(|amount| {
                let large = resign(
                    &tx_block(3, prev, 0, |b| {
                        votes_for(3, 1, 2, amount)(b);
                    }),
                    1,
                    vote_snapshot(6000),
                    NODE_ONE_KEY,
                );
                let small = valued(3, prev, vote_snapshot(6000), amount + 1000);
                (large.view().hash() > small.view().hash()).then_some((large, small))
            })
            .expect("a pair");
        for blk in [&small, &large, &parent] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(head_of(&bc), (3, large.view().hash()), "size before hash");
        // Chosen by rank, not left over by a Tier 3 refusal of `small`.
        assert_eq!(status_of(&bc, &small), Some(BlockStatus::Connected));
        assert_eq!(
            bc.chain_heads.branch_value_of(slot(&bc, &small)),
            Some(v(&parent) + v(&small))
        );
    }

    /// AC8 (code review 2026-10-20) — an unreadable sibling is a local
    /// failure, never a choice: the continuation stops with both siblings
    /// Stored, and ranks them once the fault clears.
    #[test]
    fn unreadable_sibling_stops_the_continuation() {
        let (mut bc, b1) = faulty_genesis(16);
        let parent = alt(2, b1.view().hash(), 0, 0, 9, 7, true);
        let (high, low) = ranked_pair(3, parent.view().hash(), 9, 4);
        for blk in [&low, &high] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        bc.storage.failing_read_slot = slot(&bc, &high);
        assert_eq!(
            receive(&mut bc, &parent),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            head_of(&bc),
            (2, parent.view().hash()),
            "the continuation stopped"
        );
        assert_eq!(status_of(&bc, &high), Some(BlockStatus::Stored));
        assert_eq!(
            status_of(&bc, &low),
            Some(BlockStatus::Stored),
            "not taken instead"
        );

        bc.storage.failing_read_slot = NONE_REF;
        let unrelated = node_transfer_block(9, 3, 8, 7);
        assert_eq!(
            receive(&mut bc, &unrelated),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            head_of(&bc),
            (3, high.view().hash()),
            "ranked after the fault"
        );
        let li = slot(&bc, &low);
        assert_eq!(status_of(&bc, &low), Some(BlockStatus::Connected));
        assert_eq!(
            bc.chain_heads.branch_value_of(li),
            Some(brute_value(&bc, li))
        );
    }

    /// AC10.4 / AC10.12 / D4 — side blocks with a Connected or Active parent
    /// are judged before their write: a fork from an older active block, the
    /// extension of a Connected side head (incremental, no read of it), and a
    /// fork from an interior Connected block — each Connected and valued as
    /// the brute force; the active value is untouched.
    #[test]
    fn side_blocks_are_judged_before_their_write_and_valued() {
        let (mut bc, b1) = faulty_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 2, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 2, 0, 8, false);
        for blk in [&a2, &a3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        let active = bc.active_branch_value;
        assert_eq!(active, v(&a2) + v(&a3));

        let f3 = valued(3, a2.view().hash(), 9, 20);
        assert_eq!(receive(&mut bc, &f3), ReceiveBlockOutcome::AcceptedSilently);
        let fi = slot(&bc, &f3);
        assert_eq!(status_of(&bc, &f3), Some(BlockStatus::Connected));
        assert_eq!(bc.chain_heads.branch_value_of(fi), Some(v(&a2) + 9));
        assert_eq!(
            bc.chain_heads.branch_value_of(fi),
            Some(brute_value(&bc, fi))
        );

        // The extension reads nothing of itself: its slot's reads fail.
        let f4 = valued(4, f3.view().hash(), 4, 21);
        bc.storage.failing_read_slot = bc.blocks.next_free_index().expect("a slot");
        assert_eq!(receive(&mut bc, &f4), ReceiveBlockOutcome::AcceptedSilently);
        bc.storage.failing_read_slot = NONE_REF;
        let f4i = slot(&bc, &f4);
        assert_eq!(status_of(&bc, &f4), Some(BlockStatus::Connected));
        assert_eq!(bc.chain_heads.branch_value_of(f4i), Some(v(&a2) + 9 + 4));
        assert_eq!(
            bc.chain_heads.branch_value_of(f4i),
            Some(brute_value(&bc, f4i))
        );

        // f3 is interior now: a second child of it is a fork, walked.
        let g4 = valued(4, f3.view().hash(), 6, 22);
        assert_eq!(receive(&mut bc, &g4), ReceiveBlockOutcome::AcceptedSilently);
        let gi = slot(&bc, &g4);
        assert_eq!(status_of(&bc, &g4), Some(BlockStatus::Connected));
        assert_eq!(bc.chain_heads.branch_value_of(gi), Some(v(&a2) + 9 + 6));
        assert_eq!(
            bc.chain_heads.branch_value_of(gi),
            Some(brute_value(&bc, gi))
        );
        assert_eq!(
            bc.active_branch_value, active,
            "side blocks leave the active value"
        );
        assert_eq!(head_of(&bc), (3, a3.view().hash()));
    }

    /// [`faulty_utxo_genesis`] with one more active block, so the mint at #3
    /// is an older active block a side branch can fork from. Returns the node,
    /// the mint and #4.
    fn utxo_side_fixture() -> (Chain16<FaultyStorage>, Block, Block) {
        let (mut bc, mint) = faulty_utxo_genesis();
        // Node #1's, credited once by the mint: worth `I(1000)` = 1005 (I-09),
        // above the free values the side blocks of these Tier 2 tests carry,
        // so none of them is switched to (Story 6.3).
        let b4 = real_on(&bc, &transfer(4, mint.view().hash(), 0, 7), 1, NODE_ONE_KEY);
        assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
        (bc, mint, b4)
    }

    /// A side block at `seq` on `prev` spending `(3, index)` with the declared
    /// `amount` into one UTXO output.
    fn side_spend(seq: u32, prev: [u8; 32], index: u8, amount: u64) -> Block {
        let tx = utxo_tx(seq, &[(3, index, amount)], None, &[Ok(amount)]);
        complex_tx_block(seq, prev, 0, 0, &[&tx])
    }

    /// AC10.7 / AC10.12 — a side block failing Tier 2 at intake is refused and
    /// nothing is stored: a declared amount other than the output's, an output
    /// index beyond the referenced block's outputs, and a fork from an interior
    /// Connected block.
    #[test]
    fn side_block_failing_tier2_at_intake_is_not_stored() {
        for (index, amount) in [(0, 61), (5, 60)] {
            let (mut bc, mint, _) = utxo_side_fixture();
            let (twin, _, _) = utxo_side_fixture();
            let bad = side_spend(4, mint.view().hash(), index, amount);
            let free = bc.blocks.next_free_index().expect("a free slot");
            assert_eq!(
                receive(&mut bc, &bad),
                ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
            );
            assert_same_state(&bc, &twin, "refused side block");
            assert_eq!(bc.blocks.next_free_index(), Some(free), "no slot used");
            assert!(same_slot(&bc, &twin, free), "storage unchanged");
        }

        // A fork from an interior Connected block is refused the same way.
        let (mut bc, mint, _) = utxo_side_fixture();
        let p4 = valued(4, mint.view().hash(), 4, 30);
        let p5 = valued(5, p4.view().hash(), 5, 31);
        for blk in [&p4, &p5] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        let free = bc.blocks.next_free_index().expect("a free slot");
        let bad = side_spend(5, p4.view().hash(), 0, 61);
        assert_eq!(
            receive(&mut bc, &bad),
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
        assert_eq!(bc.blocks.next_free_index(), Some(free), "no slot used");

        // The matching amount passes: Connected, no bit touched.
        let (mut bc, mint, _) = utxo_side_fixture();
        let good = side_spend(4, mint.view().hash(), 0, 60);
        assert_eq!(
            receive(&mut bc, &good),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(status_of(&bc, &good), Some(BlockStatus::Connected));
        assert_eq!(bc.blocks.utxo_available(slot(&bc, &mint), 0), Some(true));
    }

    /// AC6 / D4 — a local failure inside the pre-store Tier 2 is no evidence:
    /// the block is stored Stored, and the driver connects it once the fault
    /// clears.
    #[test]
    fn tier2_read_failure_at_intake_is_retried_by_the_driver() {
        let (mut bc, mint, _) = utxo_side_fixture();
        let good = side_spend(4, mint.view().hash(), 0, 60);
        bc.storage.failing_read_slot = slot(&bc, &mint);
        assert_eq!(
            receive(&mut bc, &good),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            status_of(&bc, &good),
            Some(BlockStatus::Stored),
            "not blamed"
        );

        bc.storage.failing_read_slot = NONE_REF;
        let unrelated = node_transfer_block(9, 3, 8, 7);
        assert_eq!(
            receive(&mut bc, &unrelated),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let gi = slot(&bc, &good);
        assert_eq!(status_of(&bc, &good), Some(BlockStatus::Connected));
        assert_eq!(
            bc.chain_heads.branch_value_of(gi),
            Some(brute_value(&bc, gi))
        );
    }

    /// AC10.5 / AC10.7 / D8 — an orphan side chain stored before its Tier 2
    /// could run: its parent's arrival connects it, the driver finds the
    /// failing block, deletes it with its descendants, and values the entry
    /// retargeted onto the surviving Connected parent. The active state is
    /// untouched and the node stays Ready. Each failure kind: a declared amount
    /// other than the output's, an output index beyond it, a reference more
    /// than `W` back.
    #[test]
    fn driver_deletes_a_failing_side_block_and_values_the_retarget() {
        for (index, amount) in [(0, 61), (5, 60)] {
            let (mut bc, mint, _) = utxo_side_fixture();
            let (twin, _, _) = utxo_side_fixture();
            let p4 = valued(4, mint.view().hash(), 4, 30);
            let bad5 = revalue(&side_spend(5, p4.view().hash(), index, amount), 5);
            let c6 = valued(6, bad5.view().hash(), 6, 31);
            for blk in [&c6, &bad5, &p4] {
                assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
            }
            assert_eq!(status_of(&bc, &bad5), None, "deleted");
            assert_eq!(status_of(&bc, &c6), None, "with its descendant");
            let pi = slot(&bc, &p4);
            assert_eq!(status_of(&bc, &p4), Some(BlockStatus::Connected));
            assert_eq!(
                bc.chain_heads.branch_value_of(pi),
                Some(brute_value(&bc, pi))
            );
            assert!(bc.is_ready());
            assert!(bc.node_info == twin.node_info);
            assert!(bc.vote_engine == twin.vote_engine);
            assert_eq!(bc.active_branch_value, twin.active_branch_value);
            for bit in 0..2 {
                assert_eq!(
                    bc.blocks.utxo_available(slot(&bc, &mint), bit),
                    twin.blocks.utxo_available(slot(&twin, &mint), bit),
                    "active available-UTXO bits untouched"
                );
            }
        }

        // A reference more than `W` back, on the W4 window.
        let (mut bc, [_, b101, _, _]) = valued_w4();
        let p102 = revalue(&salted_linked_block(102, b101.view().hash(), 6), 13);
        let tx = utxo_tx(103, &[(97, 0, 50)], None, &[Ok(50)]);
        let far = complex_tx_block(103, p102.view().hash(), 0, 0, &[&tx]);
        for blk in [&far, &p102] {
            assert_eq!(
                bc.receive_block(blk.view(), 0).0,
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert!(
            bc.blocks.find(103, &far.view().hash()).is_none(),
            "deleted by the driver"
        );
        let pi = slot(&bc, &p102);
        assert_eq!(
            bc.blocks.get(pi).map(|e| e.status()),
            Some(BlockStatus::Connected)
        );
        assert_eq!(
            bc.chain_heads.branch_value_of(pi),
            Some(brute_value(&bc, pi))
        );

        // A valid orphan chain connects whole.
        let (mut bc, mint, _) = utxo_side_fixture();
        let p4 = valued(4, mint.view().hash(), 4, 30);
        let q5 = valued(5, p4.view().hash(), 5, 31);
        let q6 = valued(6, q5.view().hash(), 6, 32);
        for blk in [&q6, &q5, &p4] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        for blk in [&p4, &q5, &q6] {
            assert_eq!(status_of(&bc, blk), Some(BlockStatus::Connected));
        }
        let qi = slot(&bc, &q6);
        assert_eq!(
            bc.chain_heads.branch_value_of(qi),
            Some(brute_value(&bc, qi))
        );
    }

    /// AC10.8 / D6 — a UTXO reference below `S_tail` but within `W` is trusted
    /// pre-window history (DEC-129); more than `W` back it is evidence.
    #[test]
    fn side_reference_below_the_tail_within_w_is_trusted() {
        let (mut bc, [_, b101, _, _]) = valued_w4();
        let tx = utxo_tx(102, &[(99, 0, 50)], None, &[Ok(50)]);
        let trusted = complex_tx_block(102, b101.view().hash(), 0, 0, &[&tx]);
        assert_eq!(
            bc.receive_block(trusted.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
        let ti = slot(&bc, &trusted);
        assert_eq!(
            bc.blocks.get(ti).map(|e| e.status()),
            Some(BlockStatus::Connected)
        );

        let tx = utxo_tx(102, &[(97, 0, 50)], None, &[Ok(50)]);
        let too_far = complex_tx_block(102, b101.view().hash(), 0, 0, &[&tx]);
        assert_eq!(
            bc.receive_block(too_far.view(), 0).0,
            ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
        );
    }

    /// AC10.9 — a read failure during the side walk changes nothing; the next
    /// admission connects the branch.
    #[test]
    fn side_walk_read_failure_is_retried() {
        let (mut bc, mint, _) = utxo_side_fixture();
        let p4 = valued(4, mint.view().hash(), 4, 30);
        let q5 = valued(5, p4.view().hash(), 5, 31);
        assert_eq!(receive(&mut bc, &q5), ReceiveBlockOutcome::AcceptedSilently);
        bc.storage.failing_read_slot = slot(&bc, &q5);
        assert_eq!(receive(&mut bc, &p4), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(status_of(&bc, &p4), Some(BlockStatus::Connected));
        assert_eq!(
            status_of(&bc, &q5),
            Some(BlockStatus::Stored),
            "left pending"
        );

        bc.storage.failing_read_slot = NONE_REF;
        let unrelated = node_transfer_block(9, 3, 8, 7);
        assert_eq!(
            receive(&mut bc, &unrelated),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let qi = slot(&bc, &q5);
        assert_eq!(status_of(&bc, &q5), Some(BlockStatus::Connected));
        assert_eq!(
            bc.chain_heads.branch_value_of(qi),
            Some(brute_value(&bc, qi))
        );
    }

    /// AC10.11 / AC9.3 — two admission orders of one block set hold the same
    /// values and statuses; a restart rebuilds them.
    #[test]
    fn branch_values_are_order_independent_and_survive_a_restart() {
        let build = |order: &[usize]| {
            let (mut bc, _, b1) = ready_genesis(16);
            let a2 = alt(2, b1.view().hash(), 0, 0, 2, 7, true);
            let a3 = alt(3, a2.view().hash(), 1, 2, 3, 8, false);
            let a4 = alt(4, a3.view().hash(), 0, 3, 4, 9, false);
            let a5 = alt(5, a4.view().hash(), 1, 4, 0, 10, false);
            let f3 = valued(3, a2.view().hash(), 9, 20);
            let f4 = valued(4, f3.view().hash(), 6, 21);
            let blocks = [a2, a3, a4, a5, f3, f4];
            for &i in order {
                assert_eq!(
                    receive(&mut bc, &blocks[i]),
                    ReceiveBlockOutcome::AcceptedSilently
                );
            }
            (bc, blocks)
        };
        let (x, blocks) = build(&[0, 1, 2, 3, 4, 5]);
        // The side branch before the active extensions, child first.
        let (y, _) = build(&[0, 1, 5, 4, 2, 3]);
        assert_eq!(x.active_branch_value, y.active_branch_value);
        assert_eq!(
            x.active_branch_value,
            brute_value(&x, x.active_chain_head_idx)
        );
        for blk in &blocks {
            assert_eq!(status_of(&x, blk), status_of(&y, blk));
            let (xi, yi) = (slot(&x, blk), slot(&y, blk));
            if x.blocks.get(xi).map(|e| e.status()) == Some(BlockStatus::Connected) {
                assert_eq!(
                    x.chain_heads.branch_value_of(xi),
                    y.chain_heads.branch_value_of(yi)
                );
            }
        }
        let f4 = &blocks[5];
        let fi = slot(&x, f4);
        assert_eq!(x.chain_heads.branch_value_of(fi), Some(brute_value(&x, fi)));

        let reference_active = x.active_branch_value;
        let reference_side = x.chain_heads.branch_value_of(fi);
        let mut restarted = restart(x);
        let _ = restarted.initialize_from_storage(0);
        assert!(restarted.is_ready());
        assert_eq!(restarted.active_branch_value, reference_active);
        let ri = slot(&restarted, f4);
        assert_eq!(
            restarted.blocks.get(ri).map(|e| e.status()),
            Some(BlockStatus::Connected)
        );
        assert_eq!(restarted.chain_heads.branch_value_of(ri), reference_side);
    }
    // ===================================================================
    // Story 6.2 — FR22 re-evaluation, FR28 two-stage scoring, I-09, D6
    // ===================================================================

    /// A transaction block with explicit vote header fields, signed with
    /// `[key; 32]` — deviation blocks and malformed headers.
    #[allow(clippy::too_many_arguments)]
    fn headed(
        seq: u32,
        prev: [u8; 32],
        creator: u32,
        key: u8,
        consumed: u32,
        first_voted: u32,
        recorded: u32,
        add: impl FnOnce(&mut BlockBuilder),
    ) -> Block {
        let signer = Crypto::new([key; PRIVATE_KEY_SIZE]).ok().expect("key");
        let header = BlockHeader {
            version: 1,
            sequence: seq,
            creator,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_TRANSACTION,
            consumed_votes: consumed,
            first_voted_node: first_voted,
            consumed_votes_from_first_voted_node: recorded,
            previous_hash: prev,
            signature: [0u8; 64],
        };
        let mut builder = BlockBuilder::new().header(header);
        add(&mut builder);
        builder.build_signed(&signer).ok().expect("build signed")
    }

    /// The FR22 decision observed through the FR23 switch (Story 6.3): a
    /// winner with a forged value (a free header, [`valued`]) is attempted,
    /// refused by the replay's I-09 check and deleted with its descendants —
    /// the block is gone while the active head stayed.
    fn attempted<S: StorageTrait>(bc: &Chain16<S>, block: &Block) -> bool {
        status_of(bc, block).is_none()
    }

    /// A genesis node on `W = 16` with `a2` (node #0's, registering node #1
    /// and crediting it once) and `a3` (node #1's, worth 1005).
    fn two_creator_chain() -> (TestChain, Block, Block, Block) {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
        for blk in [&a2, &a3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(bc.active_branch_value, 1005);
        (bc, b1, a2, a3)
    }

    /// AC10.1 / AC10.2 / AC2; Story 6.3 AC11.1 — trigger (i): a side
    /// extension that outranks the active branch is switched to; a lower one
    /// is not. The real-header branch `g3`, `g4` (node #1 then node #0, the
    /// `alt` alternation from `a2`) wins only with `g4`; a forged-value fork
    /// from an older active block (#1) is attempted and deleted.
    #[test]
    fn fr22_side_extension_and_fork_that_outrank_switch() {
        let (mut bc, b1, a2, a3) = two_creator_chain();
        let a3i = slot(&bc, &a3);
        // `g3` ties `a3` (both worth 1005, one transaction): a higher hash
        // keeps it below the active tip.
        let g3 = (20..400)
            .map(|salt| alt(3, a2.view().hash(), 1, 1, 1, salt, false))
            .find(|g| g.view().len() == a3.view().len() && g.view().hash() > a3.view().hash())
            .expect("a same-size sibling with a higher hash");
        assert_eq!(receive(&mut bc, &g3), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(status_of(&bc, &g3), Some(BlockStatus::Connected));
        assert_eq!(head_of(&bc), (3, a3.view().hash()), "a tie lost by hash");
        // EXTEND past the active value: `g4` (node #0, credited once by
        // `g3`) is worth 1005 more.
        let g4 = alt(4, g3.view().hash(), 0, 1, 0, 21, false);
        assert_eq!(receive(&mut bc, &g4), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (4, g4.view().hash()), "switched");
        assert_eq!(bc.active_branch_value, v(&g3) + v(&g4));
        assert_eq!(status_of(&bc, &a3), Some(BlockStatus::Connected));
        assert_eq!(status_of(&bc, &g3), Some(BlockStatus::Active));
        assert_eq!(
            bc.chain_heads.branch_value_of(a3i),
            Some(v(&a3)),
            "the old head keeps the old active value (FR21 (iv))"
        );
        // The comparison itself (AC4): the active head and no candidate.
        assert_eq!(
            bc.switch_target([Some(bc.active_chain_head_idx), None]),
            None
        );
        assert_eq!(bc.switch_target([None, None]), None);
        // FORK from an older active block (#1) with a forged value: the
        // comparison picks it, the replay refuses it (I-09), and the active
        // chain stays.
        let f2 = valued(2, b1.view().hash(), 5000, 22);
        assert_eq!(receive(&mut bc, &f2), ReceiveBlockOutcome::AcceptedSilently);
        assert!(attempted(&bc, &f2));
        assert_eq!(head_of(&bc), (4, g4.view().hash()));
    }

    /// AC10.1 / D4 — on an equal value the larger tip wins: a smaller side
    /// tip is not compared up whatever its hash, a larger one is (its forged
    /// value is then refused by the replay, Story 6.3).
    #[test]
    fn fr22_equal_value_goes_to_the_larger_tip() {
        // The active tip `a3` carries two transactions.
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 1, 2, 8, false);
        for blk in [&a2, &a3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        let tip = a3.view();
        for lower_hash in [true, false] {
            let smaller = (100..400)
                .map(|amount| valued(3, a2.view().hash(), 1005, amount))
                .find(|blk| (blk.view().hash() < tip.hash()) == lower_hash)
                .expect("a one-transaction sibling");
            assert!(smaller.view().len() < tip.len());
            assert_eq!(
                receive(&mut bc, &smaller),
                ReceiveBlockOutcome::AcceptedSilently
            );
            assert!(
                !attempted(&bc, &smaller),
                "smaller, lower hash: {lower_hash}"
            );
        }
        let larger = revalue(
            &tx_block(3, a2.view().hash(), 0, votes_for(3, 0, 3, 500)),
            1005,
        );
        assert!(larger.view().len() > tip.len());
        assert_eq!(
            receive(&mut bc, &larger),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert!(attempted(&bc, &larger));
        assert_eq!(head_of(&bc), (3, a3.view().hash()));
    }

    /// AC10.1 / D4 — on an equal value and size the lower tip hash wins,
    /// whatever the creators: node #0's side tip loses to node #1's active
    /// tip when its hash is higher (the old creator criterion would pick it).
    /// The winner's forged value is refused by the replay (Story 6.3).
    #[test]
    fn fr22_tie_goes_to_the_lower_hash_not_the_creator() {
        for want_lower in [true, false] {
            let (mut bc, _, a2, a3) = two_creator_chain();
            let tip = a3.view();
            let side = (100..400)
                .map(|amount| valued(3, a2.view().hash(), 1005, amount))
                .find(|blk| {
                    let view = blk.view();
                    view.len() == tip.len() && (view.hash() < tip.hash()) == want_lower
                })
                .expect("a same-size sibling");
            assert_eq!(
                receive(&mut bc, &side),
                ReceiveBlockOutcome::AcceptedSilently
            );
            assert_eq!(
                attempted(&bc, &side),
                want_lower,
                "lower hash: {want_lower}"
            );
            assert_eq!(head_of(&bc), (3, a3.view().hash()));
        }
    }

    /// AC10.3 / AC10.4 / AC9 — trigger (ii): orphan side heads connected by
    /// their parent's arrival; of two, the higher-ranked is the target, in
    /// any arrival order. Trigger (v): a Tier 2 deletion's retarget onto a
    /// Connected block that outranks. Each target's forged value is refused
    /// by the replay (Story 6.3), which deletes it and nothing below it.
    #[test]
    fn fr22_connected_orphans_and_the_retarget_reach_the_seam() {
        let run = |order: &[usize]| {
            let (mut bc, _, a2, a3) = two_creator_chain();
            let m3 = valued(3, a2.view().hash(), 0, 30);
            let p4 = valued(4, m3.view().hash(), 100, 31);
            let q4 = valued(4, m3.view().hash(), 2000, 32);
            for &i in order {
                let blk = [&m3, &p4, &q4][i];
                assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
            }
            assert_eq!(head_of(&bc), (3, a3.view().hash()));
            (
                attempted(&bc, &q4),
                attempted(&bc, &p4),
                status_of(&bc, &m3),
            )
        };
        for order in [[1, 2, 0], [2, 1, 0], [0, 1, 2]] {
            assert_eq!(
                run(&order),
                (true, false, Some(BlockStatus::Connected)),
                "order {order:?}"
            );
        }

        // The retarget: `bad5` waits for `p4`, so `p4`'s own entry merges
        // away; the driver deletes `bad5` and values the entry it retargets
        // onto `p4`, which the comparison then picks.
        let (mut bc, mint, _) = utxo_side_fixture();
        let p4 = valued(4, mint.view().hash(), 5000, 30);
        let bad5 = revalue(&side_spend(5, p4.view().hash(), 0, 61), 5);
        for blk in [&bad5, &p4] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(status_of(&bc, &bad5), None, "deleted");
        assert!(attempted(&bc, &p4));
    }

    /// AC10.5 / AC10.11 — Ready entry compares the side heads it values: a
    /// mesh join through FR3 onto `#0..#4` with a heavier side fork `f3`, and
    /// again after a restart, whose rebuild also marks the active blocks'
    /// signatures verified. `f3`'s forged value is refused by the replay each
    /// time (Story 6.3); the restart resurrects its lazily freed bytes (R3).
    #[test]
    fn fr22_ready_entry_and_restart_compare_side_heads() {
        let (_, b0, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 1, 1, 8, false);
        let a4 = alt(4, a3.view().hash(), 0, 1, 0, 9, false);
        let f3 = valued(3, a2.view().hash(), 5000, 20);
        let mut mesh = new_unconfigured_test_chain();
        for blk in [&f3, &a4, &a3, &a2, &b1, &b0] {
            assert_eq!(
                receive(&mut mesh, blk),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert!(mesh.is_ready());
        assert_eq!(head_of(&mesh), (4, a4.view().hash()));
        assert!(attempted(&mesh, &f3));

        let mut restarted = restart(mesh);
        let _ = restarted.initialize_from_storage(0);
        assert!(restarted.is_ready());
        assert_eq!(head_of(&restarted), (4, a4.view().hash()));
        assert!(attempted(&restarted, &f3));
        for blk in [&a2, &a3, &a4] {
            let idx = slot(&restarted, blk);
            assert!(
                restarted
                    .blocks
                    .get(idx)
                    .is_some_and(|entry| entry.is_signature_verified()),
                "the rebuild marked #{}",
                blk.view().sequence()
            );
        }
    }

    /// AC10.6 / AC3 / D3 — on the matured W4 window `[100, 103]` a heavier
    /// side branch shorter than the window is not admissible; extended to
    /// cover it, it is. The late case: once the head has moved on, a branch
    /// at the old head sequence waits for its own extension. The window is
    /// window-anchored with no balance block (`C = S_head`) and its tail is
    /// the root, so the switch the comparison picks is not admitted (Story
    /// 6.3 AC1, DEC-167, DEC-204): nothing changes.
    #[test]
    fn fr22_admissibility_follows_the_w4_window() {
        let (mut bc, [_, b101, _, b103]) = valued_w4();
        let s102 = valued(102, b101.view().hash(), 999, 6);
        assert_eq!(
            bc.receive_block(s102.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
        let si = slot(&bc, &s102);
        assert!(bc.chain_heads.branch_value_of(si) > Some(bc.active_branch_value));
        assert_eq!(
            bc.switch_target([Some(si), None]),
            None,
            "segment [100, 102] < W"
        );
        let s103 = valued(103, s102.view().hash(), 1, 7);
        assert_eq!(
            bc.receive_block(s103.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
        let s3 = slot(&bc, &s103);
        assert_eq!(bc.switch_target([Some(s3), None]), Some(s3));
        assert_eq!(bc.complete_from_sequence, 103);
        assert_eq!(
            bc.blocks.get(bc.active_chain_head_idx).map(|e| *e.hash()),
            Some(b103.view().hash()),
            "not admitted: nothing changed"
        );
        assert_eq!(
            bc.blocks.get(s3).map(|e| e.status()),
            Some(BlockStatus::Connected)
        );

        // The late case (D3; AC10.10): the head moved on to #104, so a branch
        // at #103 is one short until it reaches #104.
        let (mut bc, [_, _, b102, b103]) = valued_w4();
        let b104 = real_on(&bc, &w4_config_anchor_block(104, b103.view().hash()), 0, 1);
        extend_active_head(&mut bc, &b104, 0);
        assert_eq!(bc.active_snake_chain_window(), Ok((101, 104)));
        let n103 = valued(103, b102.view().hash(), 500, 8);
        assert_eq!(
            bc.receive_block(n103.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
        let n3 = slot(&bc, &n103);
        assert_eq!(
            bc.switch_target([Some(n3), None]),
            None,
            "not admissible yet"
        );
        let n104 = valued(104, n103.view().hash(), 0, 9);
        assert_eq!(
            bc.receive_block(n104.view(), 0).0,
            ReceiveBlockOutcome::AcceptedSilently
        );
        let n4 = slot(&bc, &n104);
        assert_eq!(bc.switch_target([Some(n4), None]), Some(n4));
        assert_eq!(
            bc.blocks.get(n4).map(|e| e.status()),
            Some(BlockStatus::Connected),
            "not admitted"
        );
    }

    /// AC10.7 / AC7 — the non-triggers compare nothing. A winning fork whose
    /// switch hit a local fault (its own block cannot be read back by the
    /// pre-pass; Story 6.3 AC6: kept, nothing deleted) stays a side head that
    /// would be attempted if compared — its forged value would be refused and
    /// deleted. Active extensions, direct and by continuation, leave it
    /// alone; a zero-valued side block compares only itself.
    #[test]
    fn fr22_non_triggers_compare_nothing() {
        let (mut bc, b1) = faulty_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        let f2 = valued(2, b1.view().hash(), 5000, 20);
        // `f2` is valued from the view in hand; the switch's pre-pass must
        // read it back.
        bc.storage.failing_read_slot = bc.blocks.next_free_index().expect("a free slot");
        assert_eq!(receive(&mut bc, &f2), ReceiveBlockOutcome::AcceptedSilently);
        bc.storage.failing_read_slot = NONE_REF;
        assert_eq!(status_of(&bc, &f2), Some(BlockStatus::Connected), "kept");
        assert_eq!(head_of(&bc), (2, a2.view().hash()));
        let a3 = alt(3, a2.view().hash(), 1, 1, 1, 8, false);
        assert_eq!(receive(&mut bc, &a3), ReceiveBlockOutcome::AcceptedSilently);
        let a4 = alt(4, a3.view().hash(), 0, 1, 1, 9, false);
        let a5 = alt(5, a4.view().hash(), 1, 1, 0, 10, false);
        for blk in [&a5, &a4] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(head_of(&bc), (5, a5.view().hash()));
        let fi = slot(&bc, &f2);
        let fv = bc.chain_heads.branch_value_of(fi).expect("valued");
        assert!(fv > bc.active_branch_value, "it would still win");
        assert!(!attempted(&bc, &f2), "active extensions compare nothing");
        // A side block worth 0 (a replay-like value, FR22 (b)) is an ordinary
        // trigger (i): it cannot win, and it does not compare `f2`.
        let zero = valued(3, a2.view().hash(), 0, 23);
        assert_eq!(
            receive(&mut bc, &zero),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert!(!attempted(&bc, &zero), "a zero-valued side block");
        assert!(!attempted(&bc, &f2));
    }

    /// AC10.8 / D4 — the comparison reads nothing: a value-and-size tie is
    /// decided by hash while the active tip's slot fails every read. The
    /// tying block extends a Connected side head, which is valued with no
    /// read either (Story 6.1 D4). The switch the comparison then calls must
    /// read that tip to undo it: a local failure, kept with nothing deleted
    /// (Story 6.3 AC6).
    #[test]
    fn fr22_comparison_reads_nothing() {
        let (mut bc, b1) = faulty_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
        let g2 = valued(2, b1.view().hash(), 5, 20);
        for blk in [&a2, &a3, &g2] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert!(!attempted(&bc, &g2));
        let tip = a3.view();
        let side = (100..400)
            .map(|amount| valued(3, g2.view().hash(), 1000, amount))
            .find(|blk| blk.view().len() == tip.len() && blk.view().hash() < tip.hash())
            .expect("a same-size extension with a lower hash");
        bc.storage.failing_read_slot = slot(&bc, &a3);
        assert_eq!(
            receive(&mut bc, &side),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let si = slot(&bc, &side);
        assert_eq!(
            bc.chain_heads.branch_value_of(si),
            Some(bc.active_branch_value)
        );
        assert_eq!(
            bc.switch_target([Some(si), None]),
            Some(si),
            "decided without a read"
        );
        assert_eq!(status_of(&bc, &side), Some(BlockStatus::Connected), "kept");
        assert_eq!(head_of(&bc), (3, a3.view().hash()));
    }

    /// AC10.13 (first negative check) — the comparison runs after the
    /// continuation: a fork that outranks the active branch at its intake but
    /// not once the same admission's continuation promotes a pending child
    /// (left Stored by a read fault) does not switch.
    #[test]
    fn fr22_compares_after_the_continuation() {
        let (mut bc, mint) = faulty_utxo_genesis();
        let b4 = alt(4, mint.view().hash(), 0, 0, 5, 7, false);
        assert_eq!(receive(&mut bc, &b4), ReceiveBlockOutcome::AcceptedSilently);
        let tx = utxo_tx(5, &[(3, 1, 40)], None, &[Err((1, 40))]);
        // Node #1: credited once by the mint and five times by `b4`.
        let c5 = resign(
            &complex_tx_block(5, b4.view().hash(), 0, 0, &[&tx]),
            1,
            vote_snapshot(vote_snapshot(1000) + 5000),
            NODE_ONE_KEY,
        );
        bc.storage.failing_read_slot = slot(&bc, &mint);
        assert_eq!(receive(&mut bc, &c5), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(
            status_of(&bc, &c5),
            Some(BlockStatus::Stored),
            "a local failure"
        );
        bc.storage.failing_read_slot = NONE_REF;

        let x = valued(4, mint.view().hash(), 3000, 40);
        assert_eq!(receive(&mut bc, &x), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (5, c5.view().hash()), "the continuation ran");
        assert_eq!(bc.active_branch_value, v(&b4) + v(&c5));
        let xv = bc
            .chain_heads
            .branch_value_of(slot(&bc, &x))
            .expect("x is a valued side head");
        assert!(xv < bc.active_branch_value);
        assert!(!attempted(&bc, &x));
    }

    /// AC10.9 / AC5 — I-09 at Ready intake: each inconsistent vote header is
    /// `Rejected(InvalidEvidence)` with nothing stored; the correct deviation
    /// is accepted and penalizes the top; the credits it gave the top and
    /// itself are wiped. Node #1 (3000) is the top after `a2`.
    #[test]
    fn i09_vote_headers_are_verified_at_ready_intake() {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 3, 7, true);
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(bc.vote_engine.top_creator(), Some(1));
        let prev = a2.view().hash();
        let refused = [
            // A normal block counting its own credit (the old definition).
            headed(
                3,
                prev,
                1,
                NODE_ONE_KEY,
                3015 + 1000,
                1,
                0,
                votes_for(3, 1, 1, 40),
            ),
            // A normal block with a wrong value.
            headed(3, prev, 1, NODE_ONE_KEY, 2000, 1, 0, votes_for(3, 0, 1, 41)),
            // The normal form with a deviation field (Tier 1 form).
            headed(3, prev, 1, NODE_ONE_KEY, 3015, 1, 5, votes_for(3, 0, 1, 42)),
            // A deviation naming a node that is not the top.
            headed(3, prev, 0, 1, 0, 5, 10, votes_for(3, 0, 1, 43)),
            // A deviation with a wrong snapshot of the top.
            headed(3, prev, 0, 1, 0, 1, 3000, votes_for(3, 0, 1, 44)),
            // A deviation counting its own credit (AR-005).
            headed(3, prev, 0, 1, 1000, 1, 3015, votes_for(3, 0, 1, 45)),
            // A deviation above the top's snapshot (Tier 1 form).
            headed(3, prev, 0, 1, 4000, 1, 3015, votes_for(3, 0, 1, 46)),
        ];
        for (i, bad) in refused.iter().enumerate() {
            let free = bc.blocks.next_free_index();
            assert_eq!(
                receive(&mut bc, bad),
                ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
                "case {i}"
            );
            assert_eq!(
                bc.blocks.next_free_index(),
                free,
                "case {i}: nothing stored"
            );
        }
        let d3 = headed(3, prev, 0, 1, 0, 1, 3015, |b| {
            votes_for(3, 0, 1, 47)(b);
            votes_for(3, 1, 1, 48)(b);
        });
        assert_eq!(receive(&mut bc, &d3), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (3, d3.view().hash()));
        assert_eq!(bc.vote_engine.accumulated_vote_of(1), 0, "the penalty");
        assert_eq!(bc.vote_engine.accumulated_vote_of(0), 0, "the reset");
    }

    /// AC10.9 — in the FR3 pass an inconsistent vote header is evidence: a
    /// mesh join deletes it and goes Ready on the valid prefix.
    #[test]
    fn i09_mismatch_in_the_fr3_pass_is_deleted() {
        let (_, b0, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 3, 7, true);
        let prev = a2.view().hash();
        let bad = [
            // A wrong normal value.
            headed(3, prev, 1, NODE_ONE_KEY, 2000, 1, 0, votes_for(3, 0, 1, 50)),
            // A deviation naming a node that is not the top.
            headed(3, prev, 0, 1, 0, 2, 10, votes_for(3, 0, 1, 51)),
            // A deviation with a wrong snapshot of the top.
            headed(3, prev, 0, 1, 0, 1, 3000, votes_for(3, 0, 1, 52)),
            // A deviation counting its own credit (AR-005).
            headed(3, prev, 0, 1, 1000, 1, 3015, votes_for(3, 0, 1, 53)),
        ];
        for (i, bad3) in bad.iter().enumerate() {
            let mut mesh = new_unconfigured_test_chain();
            for blk in [bad3, &a2, &b1, &b0] {
                assert_eq!(
                    receive(&mut mesh, blk),
                    ReceiveBlockOutcome::AcceptedSilently,
                    "case {i}"
                );
            }
            assert!(mesh.is_ready(), "case {i}");
            assert_eq!(head_of(&mesh), (2, a2.view().hash()), "case {i}");
            assert!(
                mesh.blocks.find(3, &bad3.view().hash()).is_none(),
                "case {i}: deleted"
            );
        }
    }

    /// AC6 — the header vote form is Tier 1 in every phase: a Collecting node
    /// refuses a malformed header and stores nothing.
    #[test]
    fn header_vote_form_is_refused_while_collecting() {
        let mut bc = new_unconfigured_test_chain();
        assert!(!bc.is_ready());
        for bad in [
            headed(5, [0x33; 32], 0, 1, 10, 1, 5, votes_for(5, 0, 1, 60)),
            headed(5, [0x33; 32], 0, 1, 0, 0, 7, votes_for(5, 0, 1, 61)),
        ] {
            let free = bc.blocks.next_free_index();
            assert_eq!(
                receive(&mut bc, &bad),
                ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
            );
            assert_eq!(bc.blocks.next_free_index(), free, "nothing stored");
        }
    }

    /// AC10.11 / D6 — branch-independent keys beyond node #0: a node seeded at
    /// or below `S_tail` (by its seed-source block's sequence) and a node whose
    /// seed source was released are judged at intake; a node seeded inside the
    /// window is not. A direct head extension and a good orphan by node #0 are
    /// stored marked.
    #[test]
    fn branch_independent_keys_beyond_node_zero() {
        let (mut bc, b0, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        let key = |byte: u8| {
            *Crypto::new([byte; PRIVATE_KEY_SIZE])
                .ok()
                .expect("key")
                .public_key()
                .serialize()
        };
        // Test seeding (white box): node 5 at #0, which is `S_tail`; node 6
        // with its source released; node 7 at #2, inside the window.
        let (b0i, a2i) = (slot(&bc, &b0), slot(&bc, &a2));
        bc.node_info.seed_node(5, &key(0x55), 0, b0i);
        bc.node_info
            .seed_node(6, &key(0x56), 0, SEED_SOURCE_RELEASED);
        bc.node_info.seed_node(7, &key(0x57), 0, a2i);
        // Worth 0, below the larger active tip `a2` (also 0): these intake
        // tests do not reach a chain switch (Story 6.3).
        let side = |creator: u32, signer: u8, salt: u64| {
            resign(&valued(2, b1.view().hash(), 0, salt), creator, 0, signer)
        };
        for (creator, salt) in [(5, 30), (6, 31)] {
            let free = bc.blocks.next_free_index();
            assert_eq!(
                receive(&mut bc, &side(creator, 0x77, salt)),
                ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence),
                "node {creator}: forged"
            );
            assert_eq!(bc.blocks.next_free_index(), free);
            let good = side(creator, 0x50 + creator as u8, salt + 10);
            assert_eq!(
                receive(&mut bc, &good),
                ReceiveBlockOutcome::AcceptedSilently
            );
            let gi = slot(&bc, &good);
            assert!(
                bc.blocks.get(gi).is_some_and(|e| e.is_signature_verified()),
                "node {creator}: marked"
            );
        }
        let inside = side(7, 0x77, 40);
        assert_eq!(
            receive(&mut bc, &inside),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let ii = slot(&bc, &inside);
        assert!(
            bc.blocks
                .get(ii)
                .is_some_and(|e| !e.is_signature_verified())
        );

        // Node #0: a direct head extension and a good orphan, each marked.
        let a3 = alt(3, a2.view().hash(), 0, 0, 0, 41, false);
        assert_eq!(receive(&mut bc, &a3), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (3, a3.view().hash()));
        let orphan = transfer(9, [0x44; 32], 0, 5);
        assert_eq!(
            receive(&mut bc, &orphan),
            ReceiveBlockOutcome::AcceptedSilently
        );
        for blk in [&a3, &orphan] {
            let idx = slot(&bc, blk);
            assert!(
                bc.blocks
                    .get(idx)
                    .is_some_and(|e| e.is_signature_verified())
            );
        }
    }

    /// AC10.10 / FR28 — the two-stage scoring end to end. With `av(u) = 3000`
    /// above `av(x) = 0`: an active deviation `d` loses to the late normal block
    /// `n` of the top creator; with `n` active first, `d` does not win. The
    /// credits `d` carries do not count. With `av(u) = av(x) = 0` the values
    /// tie and the FR21 tie-break decides.
    #[test]
    fn fr28_two_stage_scoring_end_to_end() {
        let setup = |out: u32| {
            let (mut bc, _, b1) = ready_genesis(16);
            let a2 = alt(2, b1.view().hash(), 0, 0, out, 7, true);
            assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
            (bc, a2)
        };
        let deviation = |a2: &Block| {
            headed(
                3,
                a2.view().hash(),
                0,
                1,
                0,
                1,
                3015,
                votes_for(3, 1, 2, 60),
            )
        };
        let normal = |a2: &Block| alt(3, a2.view().hash(), 1, 3, 0, 61, false);

        let (mut bc, a2) = setup(3);
        let (d, n) = (deviation(&a2), normal(&a2));
        assert_eq!(receive(&mut bc, &d), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(
            head_of(&bc),
            (3, d.view().hash()),
            "the deviation is active at once"
        );
        assert_eq!(receive(&mut bc, &n), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(v(&n), 3015);
        assert_eq!(
            head_of(&bc),
            (3, n.view().hash()),
            "the late normal block wins: switched (Story 6.3)"
        );
        assert_eq!(status_of(&bc, &d), Some(BlockStatus::Connected));

        let (mut bc, a2) = setup(3);
        let (d, n) = (deviation(&a2), normal(&a2));
        assert_eq!(receive(&mut bc, &n), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(receive(&mut bc, &d), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(status_of(&bc, &d), Some(BlockStatus::Connected));
        assert_eq!(
            head_of(&bc),
            (3, n.view().hash()),
            "the deviation does not overtake"
        );

        // The tie: the all-zero state, node #0 on top; node #1 deviates. Both
        // are worth 0 and carry one transaction, so the hash decides: pinned
        // for each order of the two hashes.
        for n_lower in [true, false] {
            let (mut bc, a2) = setup(0);
            assert_eq!(bc.vote_engine.top_creator(), Some(0));
            let d = headed(
                3,
                a2.view().hash(),
                1,
                NODE_ONE_KEY,
                0,
                0,
                0,
                votes_for(3, 1, 1, 70),
            );
            let n = (71..400)
                .map(|salt| alt(3, a2.view().hash(), 0, 0, 0, salt, false))
                .find(|n| {
                    n.view().len() == d.view().len()
                        && (n.view().hash() < d.view().hash()) == n_lower
                })
                .expect("a same-size normal block");
            assert_eq!(receive(&mut bc, &d), ReceiveBlockOutcome::AcceptedSilently);
            assert_eq!(receive(&mut bc, &n), ReceiveBlockOutcome::AcceptedSilently);
            let winner = if n_lower { &n } else { &d };
            assert_eq!(
                head_of(&bc),
                (3, winner.view().hash()),
                "n has the lower hash: {n_lower}"
            );
        }
    }

    /// AC10.11 / AC6 / D6 — Ready intake: a bad creator signature under a
    /// branch-independent key is refused before the write, for a fork and for
    /// an orphan; a good one is stored marked verified; a key that is not
    /// branch-independent (node #1, registered inside the window) is not
    /// judged and carries no mark. The header vote form is refused at Tier 1.
    #[test]
    fn ready_intake_checks_branch_independent_signatures() {
        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        let forged_fork = resign(&valued(3, b1.view().hash(), 500, 20), 0, 500, 0x77);
        let forged_orphan = resign(&transfer(9, [0x55; 32], 0, 5), 0, 0, 0x77);
        let bad_form = headed(3, b1.view().hash(), 0, 1, 10, 1, 5, votes_for(3, 0, 1, 21));
        for bad in [&forged_fork, &forged_orphan, &bad_form] {
            let free = bc.blocks.next_free_index();
            assert_eq!(
                receive(&mut bc, bad),
                ReceiveBlockOutcome::Rejected(RejectReason::InvalidEvidence)
            );
            assert_eq!(bc.blocks.next_free_index(), free, "nothing stored");
        }
        let good = valued(3, b1.view().hash(), 500, 22);
        assert_eq!(
            receive(&mut bc, &good),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let gi = slot(&bc, &good);
        assert!(bc.blocks.get(gi).is_some_and(|e| e.is_signature_verified()));
        // Node #1 on a branch forked below its registration: its key is not
        // branch-independent, so a bad signature is not judged at intake.
        // Worth 0, below the larger active tip `a2`: no chain switch (Story
        // 6.3), which would refuse it (node #1 is registered in `a2`).
        let unjudged = resign(&valued(2, b1.view().hash(), 0, 23), 1, 0, 0x77);
        assert_eq!(
            receive(&mut bc, &unjudged),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let ui = slot(&bc, &unjudged);
        assert!(
            bc.blocks
                .get(ui)
                .is_some_and(|e| !e.is_signature_verified())
        );
        assert!(!BlockEntry::new([0; 32], NONE_REF, 1).is_signature_verified());
    }

    /// AC10.11 / D6 — verify once: a Stored child marked verified is promoted
    /// by the continuation without its signature being checked again (here a
    /// bad one, so a re-check would delete it); unmarked, it is deleted. The
    /// freed slot's next occupant starts unmarked.
    #[test]
    fn a_verified_block_is_not_verified_again() {
        for marked in [true, false] {
            let (mut bc, _, b1) = ready_genesis(16);
            let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
            let bad3 = resign(
                &alt(3, a2.view().hash(), 1, 1, 0, 8, false),
                1,
                vote_snapshot(1000),
                0x77,
            );
            assert_eq!(
                receive(&mut bc, &bad3),
                ReceiveBlockOutcome::AcceptedSilently
            );
            let bi = slot(&bc, &bad3);
            assert!(
                bc.blocks
                    .get(bi)
                    .is_some_and(|e| !e.is_signature_verified())
            );
            if marked {
                assert!(bc.blocks.mark_signature_verified(bi));
            }
            assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
            if marked {
                assert_eq!(head_of(&bc), (3, bad3.view().hash()), "not re-verified");
            } else {
                assert_eq!(head_of(&bc), (2, a2.view().hash()));
                assert_eq!(status_of(&bc, &bad3), None, "verified, refused, deleted");
                assert_eq!(bc.blocks.next_free_index(), Some(bi));
                let next = resign(&valued(3, [0x66; 32], 0, 24), 1, 0, NODE_ONE_KEY);
                assert_eq!(
                    receive(&mut bc, &next),
                    ReceiveBlockOutcome::AcceptedSilently
                );
                assert!(
                    bc.blocks
                        .get(bi)
                        .is_some_and(|e| !e.is_signature_verified())
                );
            }
        }
    }

    // ===================================================================
    // Story 6.3 — FR23 reversible chain switch
    // ===================================================================

    /// AC10 / AC11 — `a`'s derived state equals `b`'s for every block `b`
    /// holds (matched by sequence and hash, since slots differ): `node_info`,
    /// the vote engine, the active value and the window, and per block its
    /// status, chain flag and available-UTXO bits, ignoring the one-way
    /// signature mark (DEC-157). Every block only `a` holds is off the active
    /// chain with no bit set (no phantom bits, 6.11).
    fn assert_same_projection<S: StorageTrait, T: StorageTrait>(
        a: &Chain16<S>,
        b: &Chain16<T>,
        what: &str,
    ) {
        // `node_info` per node: seed sources are slots, so they are compared
        // as the blocks they name.
        let source = |bc_blocks: &BlockTable<16>, src: Option<u32>| match src {
            Some(idx) if idx != SEED_SOURCE_RELEASED => {
                bc_blocks.get(idx).map(|e| Some((e.sequence(), *e.hash())))
            }
            other => Some(other.map(|_| (u32::MAX, [0u8; 32]))),
        };
        assert_eq!(
            a.node_info.max_known_node_id(),
            b.node_info.max_known_node_id(),
            "{what}: watermark"
        );
        for node in 0..16u32 {
            assert_eq!(
                a.node_info.balance_of(node),
                b.node_info.balance_of(node),
                "{what}: balance {node}"
            );
            assert_eq!(
                a.node_info.public_key_of(node),
                b.node_info.public_key_of(node),
                "{what}: key {node}"
            );
            assert_eq!(
                source(&a.blocks, a.node_info.seed_source_of(node)),
                source(&b.blocks, b.node_info.seed_source_of(node)),
                "{what}: seed source {node}"
            );
        }
        assert!(a.vote_engine == b.vote_engine, "{what}: votes");
        assert_eq!(
            a.active_branch_value, b.active_branch_value,
            "{what}: value"
        );
        let hash_of = |bc_blocks: &BlockTable<16>, idx: u32| bc_blocks.get(idx).map(|e| *e.hash());
        assert_eq!(
            hash_of(&a.blocks, a.active_chain_head_idx),
            hash_of(&b.blocks, b.active_chain_head_idx),
            "{what}: head"
        );
        assert_eq!(
            hash_of(&a.blocks, a.snake_chain_tail_idx),
            hash_of(&b.blocks, b.snake_chain_tail_idx),
            "{what}: tail"
        );
        let mut matched = [false; 16];
        for idx in 0..16u32 {
            let Some(eb) = b.blocks.get(idx) else {
                continue;
            };
            let ai = a
                .blocks
                .find(eb.sequence(), eb.hash())
                .unwrap_or_else(|| panic!("{what}: #{} missing", eb.sequence()));
            matched[ai as usize] = true;
            let ea = a.blocks.get(ai).expect("found");
            assert_eq!(
                ea.status(),
                eb.status(),
                "{what}: status of #{}",
                eb.sequence()
            );
            assert_eq!(
                ea.is_on_active_chain(),
                eb.is_on_active_chain(),
                "{what}: flag of #{}",
                eb.sequence()
            );
            for bit in 0..AVAILABLE_UTXO_BYTES * 8 {
                assert_eq!(
                    a.blocks.utxo_available(ai, bit),
                    b.blocks.utxo_available(idx, bit),
                    "{what}: bit {bit} of #{}",
                    eb.sequence()
                );
            }
        }
        for idx in 0..16u32 {
            if let Some(ea) = a.blocks.get(idx)
                && !matched[idx as usize]
            {
                assert!(
                    !ea.is_on_active_chain(),
                    "{what}: extra #{} off chain",
                    ea.sequence()
                );
                assert_eq!(
                    a.blocks.has_available_utxo(idx),
                    Some(false),
                    "{what}: extra #{} holds no bit",
                    ea.sequence()
                );
            }
        }
    }

    /// [`two_creator_chain`] on a [`FailingReadStorage`] node, unarmed.
    fn failing_two_creator_chain() -> (Chain16<FailingReadStorage>, Block, Block, Block) {
        let (mut bc, b1) = failing_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
        for blk in [&a2, &a3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        (bc, b1, a2, a3)
    }

    /// [`two_creator_chain`] on a [`FaultyStorage`] node.
    fn faulty_two_creator_chain() -> (Chain16<FaultyStorage>, Block, Block, Block) {
        let (mut bc, b1) = faulty_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
        for blk in [&a2, &a3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        (bc, b1, a2, a3)
    }

    /// A genesis node on `W = w` over a [`FailingReadStorage`], unarmed.
    fn failing_genesis(w: u16) -> (Chain16<FailingReadStorage>, Block) {
        let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
        let chain_config = empty_chain_config(TestChain::BUILD_LIMITS);
        let node_zero = *crypto.public_key().serialize();
        let storage = FailingReadStorage {
            inner: initialized_storage([1u8; PRIVATE_KEY_SIZE]),
            failing_slot: NONE_REF,
            reads_left: core::cell::Cell::new(0),
            attempts: core::cell::Cell::new(0),
        };
        let mut slot = core::mem::MaybeUninit::<Chain16<FailingReadStorage>>::uninit();
        Chain16::<FailingReadStorage>::init(
            &mut slot,
            crypto,
            storage,
            chain_config,
            0,
            node_zero,
            0,
        );
        // SAFETY: `init` returned, so every field of `slot` is initialized.
        let mut bc = unsafe { slot.assume_init() };
        let genesis = bc
            .process_genesis(CURRENCY, window_config_builder(w).content())
            .ok()
            .expect("genesis");
        (bc, genesis.block_one)
    }

    /// On [`two_creator_chain`], `s3`: node #1's sibling of `a3`, worth the
    /// same 1005 but larger (three credits for node #0), so it wins.
    fn heavier_sibling(a2: &Block) -> Block {
        alt(3, a2.view().hash(), 1, 1, 3, 40, false)
    }

    /// AC11.1 / AC10 — depth 1 and depth 2: the switch lands on the state a
    /// fresh node derives on the new chain alone; the abandoned blocks are
    /// Connected, off the chain, with no bit; the old head keeps the old
    /// active value; the replayed blocks carry the signature mark.
    #[test]
    fn fr23_switch_matches_a_fresh_node_on_the_new_chain() {
        let (mut bc, _, a2, a3) = two_creator_chain();
        let s3 = heavier_sibling(&a2);
        assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (3, s3.view().hash()));
        assert_eq!(status_of(&bc, &a3), Some(BlockStatus::Connected));
        assert_eq!(bc.chain_heads.branch_value_of(slot(&bc, &a3)), Some(1005));
        assert!(
            bc.blocks
                .get(slot(&bc, &s3))
                .is_some_and(|e| e.is_signature_verified())
        );
        let (mut fresh, _, b1) = ready_genesis(16);
        for blk in [&a2, &s3] {
            assert_eq!(
                receive(&mut fresh, blk),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert_same_projection(&bc, &fresh, "depth 1");
        let _ = b1;

        // Depth 2: `g3` ties `a3` and loses by hash; `g4` makes it win.
        let (mut bc, _, a2, a3) = two_creator_chain();
        let g3 = (20..400)
            .map(|salt| alt(3, a2.view().hash(), 1, 1, 1, salt, false))
            .find(|g| g.view().len() == a3.view().len() && g.view().hash() > a3.view().hash())
            .expect("a same-size sibling with a higher hash");
        let g4 = alt(4, g3.view().hash(), 0, 1, 0, 21, false);
        for blk in [&g3, &g4] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(head_of(&bc), (4, g4.view().hash()));
        let (mut fresh, _, _) = ready_genesis(16);
        for blk in [&a2, &g3, &g4] {
            assert_eq!(
                receive(&mut fresh, blk),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert_same_projection(&bc, &fresh, "depth 2");
    }

    /// AC2 — the committed-block undo is the exact inverse of the per-block
    /// step, for every block kind: applied as a head extension and undone,
    /// the node equals a twin that never saw the block; genesis #1 undone and
    /// re-applied equals itself.
    #[test]
    fn fr23_undo_inverts_every_block_kind() {
        fn check<S: StorageTrait, T: StorageTrait>(
            mut bc: Chain16<S>,
            twin: &Chain16<T>,
            block: &Block,
            what: &str,
        ) {
            assert_eq!(
                receive(&mut bc, block),
                ReceiveBlockOutcome::AcceptedSilently,
                "{what}"
            );
            assert_eq!(head_of(&bc).1, block.view().hash(), "{what}: applied");
            let idx = bc.active_chain_head_idx;
            assert_eq!(bc.undo_active_head(), Ok(()), "{what}: undone");
            assert_eq!(
                bc.blocks.get(idx).map(|e| e.status()),
                Some(BlockStatus::Connected)
            );
            assert_same_projection(&bc, twin, what);
        }
        // A registration (node #0's `a2`).
        let (bc, _, b1) = ready_genesis(16);
        let (twin, _, _) = ready_genesis(16);
        check(
            bc,
            &twin,
            &alt(2, b1.view().hash(), 0, 0, 1, 7, true),
            "registration",
        );
        // A transfer crediting its creator a fee (node #1's `a3`).
        let (bc, _, a2, _) = {
            let (mut bc, _, b1) = ready_genesis(16);
            let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
            assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
            (bc, (), a2, ())
        };
        let twin = {
            let (mut twin, _, _) = ready_genesis(16);
            assert_eq!(
                receive(&mut twin, &a2),
                ReceiveBlockOutcome::AcceptedSilently
            );
            twin
        };
        check(
            bc,
            &twin,
            &alt(3, a2.view().hash(), 1, 1, 2, 8, false),
            "creator credit",
        );
        // A balance block: node #0's seed source moves back to #0.
        let (bc, _, b1) = ready_genesis(16);
        let (twin, _, _) = ready_genesis(16);
        let snapshot = snapshot_block(&bc, 2, b1.view().hash());
        check(bc, &twin, &snapshot, "balance");
        // A deviation (node #0 on node #1's top rank, fr28's `d`).
        let setup = || {
            let (mut bc, _, b1) = ready_genesis(16);
            let a2 = alt(2, b1.view().hash(), 0, 0, 3, 7, true);
            assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
            (bc, a2)
        };
        let ((bc, a2), (twin, _)) = (setup(), setup());
        let d = headed(
            3,
            a2.view().hash(),
            0,
            1,
            0,
            1,
            3015,
            votes_for(3, 1, 2, 60),
        );
        check(bc, &twin, &d, "deviation");
        // A complex block spending a UTXO into two outputs.
        let (bc, mint) = faulty_utxo_genesis();
        let (twin, _) = faulty_utxo_genesis();
        let tx = utxo_tx(4, &[(3, 0, 60)], None, &[Ok(30), Ok(30)]);
        check(
            bc,
            &twin,
            &complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]),
            "utxo",
        );

        // Genesis #1: undone, then re-applied by the same step.
        let (mut bc, _, b1) = ready_genesis(16);
        let (twin, _, _) = ready_genesis(16);
        let idx = slot(&bc, &b1);
        assert_eq!(bc.undo_active_head(), Ok(()));
        let tail = bc.snake_chain_tail_idx;
        match bc.apply_stored_child(idx, tail) {
            ChildStep::Applied {
                advance: None,
                value,
            } => bc.promote_replayed(idx, value),
            _ => panic!("genesis #1 re-applies"),
        }
        assert_same_projection(&bc, &twin, "genesis #1");
    }

    /// AC11.3 / FR39 — the replay resolves UTXO references against the chain
    /// it builds: a shared output the abandoned branch spent is spendable on
    /// the new one, and the abandoned branch's outputs leave no bit; an
    /// output that exists only on the abandoned branch is unresolvable, so
    /// the block spending it is refused, the original chain restored and the
    /// block deleted.
    #[test]
    fn fr23_replay_resolves_utxo_against_the_new_chain() {
        // `o4`: node #1 spends (3, 0) into one output (worth 1005).
        let spend = |outputs: &[Result<u64, (u32, u64)>]| {
            let tx = utxo_tx(4, &[(3, 0, 60)], None, outputs);
            move |mint: &Block| complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx])
        };
        let (mut bc, mint) = faulty_utxo_genesis();
        let o4 = resign(
            &spend(&[Ok(60)])(&mint),
            1,
            vote_snapshot(1000),
            NODE_ONE_KEY,
        );
        assert_eq!(receive(&mut bc, &o4), ReceiveBlockOutcome::AcceptedSilently);
        let (mi, oi) = (slot(&bc, &mint), slot(&bc, &o4));
        assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false));
        assert_eq!(bc.blocks.utxo_available(oi, 0), Some(true));
        // `n4` spends the same (3, 0) into two outputs: same value, larger.
        let n4 = resign(
            &spend(&[Ok(30), Ok(30)])(&mint),
            1,
            vote_snapshot(1000),
            NODE_ONE_KEY,
        );
        assert_eq!(receive(&mut bc, &n4), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (4, n4.view().hash()));
        let ni = slot(&bc, &n4);
        assert_eq!(bc.blocks.utxo_available(mi, 0), Some(false), "spent by n4");
        assert_eq!(bc.blocks.utxo_available(mi, 1), Some(true));
        assert_eq!(
            bc.blocks.has_available_utxo(oi),
            Some(false),
            "o4 holds no bit"
        );
        assert_eq!(bc.blocks.utxo_available(ni, 0), Some(true));
        assert_eq!(bc.blocks.utxo_available(ni, 1), Some(true));

        // An output only the abandoned branch holds: `x5` spends (4, 0),
        // which on its own branch is `x4`, a block without outputs.
        let (mut bc, mint) = faulty_utxo_genesis();
        let (mut twin, _) = faulty_utxo_genesis();
        let o4 = resign(
            &spend(&[Ok(60)])(&mint),
            1,
            vote_snapshot(1000),
            NODE_ONE_KEY,
        );
        for node in [&mut bc] {
            assert_eq!(receive(node, &o4), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(
            receive(&mut twin, &o4),
            ReceiveBlockOutcome::AcceptedSilently
        );
        let x4 = resign(
            &tx_block(4, mint.view().hash(), 0, votes_for(4, 0, 1, 90)),
            1,
            vote_snapshot(1000),
            NODE_ONE_KEY,
        );
        let tx = utxo_tx(5, &[(4, 0, 60)], None, &[Ok(60)]);
        let x5 = resign(
            &complex_tx_block(5, x4.view().hash(), 0, 0, &[&tx]),
            0,
            vote_snapshot(1000),
            1,
        );
        for blk in [&x5, &x4] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(head_of(&bc), (4, o4.view().hash()), "restored");
        assert_eq!(status_of(&bc, &x5), None, "refused and deleted");
        assert_eq!(status_of(&bc, &x4), Some(BlockStatus::Connected));
        assert_eq!(
            bc.chain_heads.branch_value_of(slot(&bc, &x4)),
            Some(brute_value(&bc, slot(&bc, &x4)))
        );
        assert_same_projection(&bc, &twin, "restored after a bad reference");
    }

    /// AC11.4 / D4 — switching back over a balance block restores each
    /// listed owner's previous seed source: node #0 its registration in #0,
    /// node #1 its registration block; a node no block names is released.
    #[test]
    fn fr23_seed_sources_are_restored_by_the_backward_scan() {
        let (mut bc, b0, b1) = ready_genesis(16);
        let b0i = slot(&bc, &b0);
        assert_eq!(bc.node_info.seed_source_of(0), Some(b0i));
        let r2 = register(2, b1.view().hash(), 1, NODE_ONE_KEY);
        assert_eq!(receive(&mut bc, &r2), ReceiveBlockOutcome::AcceptedSilently);
        let r2i = slot(&bc, &r2);
        let (_, balance0, vote0, _) = node_zero_snapshot(&bc);
        let s3 = {
            use moonblokz_chain_types::NodeInfo;
            let key = |byte: u8| {
                *Crypto::new([byte; PRIVATE_KEY_SIZE])
                    .ok()
                    .expect("key")
                    .public_key()
                    .serialize()
            };
            let header = BlockHeader {
                version: 1,
                sequence: 3,
                creator: 0,
                mined_amount: 0,
                payload_type: PAYLOAD_TYPE_BALANCE,
                consumed_votes: 0,
                first_voted_node: 0,
                consumed_votes_from_first_voted_node: 0,
                previous_hash: r2.view().hash(),
                signature: [0u8; 64],
            };
            let mut builder = BlockBuilder::new().header(header);
            for (owner, balance, vote, byte) in [(0, balance0, vote0, 1), (1, 0, 0, NODE_ONE_KEY)] {
                builder
                    .add_node_info(&NodeInfo::new(owner, balance, vote, &key(byte)))
                    .ok()
                    .expect("add node info");
            }
            builder.set_max_node_id(1).ok().expect("max node id");
            let signer = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().expect("key");
            builder.build_signed(&signer).ok().expect("build signed")
        };
        assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
        let s3i = slot(&bc, &s3);
        assert_eq!(bc.node_info.seed_source_of(0), Some(s3i));
        assert_eq!(bc.node_info.seed_source_of(1), Some(s3i));
        // A larger sibling of `s3` (worth 0 as well) wins.
        let n3 = tx_block(3, r2.view().hash(), 0, votes_for(3, 0, 3, 80));
        assert_eq!(receive(&mut bc, &n3), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (3, n3.view().hash()));
        assert_eq!(bc.node_info.seed_source_of(0), Some(b0i));
        assert_eq!(bc.node_info.seed_source_of(1), Some(r2i));
        let (mut fresh, _, _) = ready_genesis(16);
        for blk in [&r2, &n3] {
            assert_eq!(
                receive(&mut fresh, blk),
                ReceiveBlockOutcome::AcceptedSilently
            );
        }
        assert_same_projection(&bc, &fresh, "seed sources");
        // No block below names node 9: released.
        let mut out = [NONE_REF];
        assert_eq!(
            bc.previous_seed_sources(bc.active_chain_head_idx, &[9], &mut out),
            Ok(())
        );
        assert_eq!(out, [SEED_SOURCE_RELEASED]);
    }

    /// AC11.5 / DEC-147 — registration-key uniqueness on the new branch: a key
    /// the shared chain registered is refused at the replay; a key only the
    /// abandoned branch registered is free.
    #[test]
    fn fr23_replay_checks_key_uniqueness_on_the_new_branch() {
        let (mut bc, _, a2, a3) = two_creator_chain();
        let (twin, _, _, _) = two_creator_chain();
        let dup = resign(
            &tx_block(3, a2.view().hash(), 0, |b| {
                b.add_registration(&registration_tx(0, 2, NODE_ONE_KEY))
                    .ok()
                    .expect("add registration");
            }),
            1,
            vote_snapshot(1000),
            NODE_ONE_KEY,
        );
        assert!(dup.view().len() > a3.view().len());
        assert_eq!(
            receive(&mut bc, &dup),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(
            status_of(&bc, &dup),
            None,
            "a duplicate key on its own branch"
        );
        assert_same_projection(&bc, &twin, "duplicate key");

        let (mut bc, _, b1) = ready_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
        for blk in [&a2, &a3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        let n2 = alt(2, b1.view().hash(), 0, 0, 1, 99, true);
        let n3 = alt(3, n2.view().hash(), 1, 1, 3, 98, false);
        for blk in [&n3, &n2] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(
            head_of(&bc),
            (3, n3.view().hash()),
            "the abandoned key is free"
        );
    }

    /// AC11.6 / AC6 — exact evidence at the first, a middle and the last new
    /// block: the original chain is restored exactly, the offender goes with
    /// its descendants, and the entry retargeted onto its parent carries the
    /// parent's value.
    #[test]
    fn fr23_evidence_restores_and_deletes_the_offender() {
        for bad in 0..3 {
            let (mut bc, _, a2, a3) = two_creator_chain();
            let (twin, _, _, _) = two_creator_chain();
            let forge = |i: usize, block: Block, creator: u32, key: u8| {
                if i == bad {
                    resign(&block, creator, block.view().consumed_votes() + 7, key)
                } else {
                    block
                }
            };
            let x3 = forge(
                0,
                alt(3, a2.view().hash(), 1, 1, 1, 50, false),
                1,
                NODE_ONE_KEY,
            );
            let x4 = forge(1, alt(4, x3.view().hash(), 0, 1, 1, 51, false), 0, 1);
            let x5 = forge(
                2,
                alt(5, x4.view().hash(), 1, 1, 0, 52, false),
                1,
                NODE_ONE_KEY,
            );
            let blocks = [&x3, &x4, &x5];
            for blk in [&x5, &x4, &x3] {
                assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
            }
            assert_eq!(head_of(&bc), (3, a3.view().hash()), "bad #{}", bad + 3);
            for (i, blk) in blocks.iter().enumerate() {
                if i >= bad {
                    assert_eq!(status_of(&bc, blk), None, "bad #{}: deleted", bad + 3);
                } else {
                    assert_eq!(status_of(&bc, blk), Some(BlockStatus::Connected));
                }
            }
            if bad > 0 {
                let pi = slot(&bc, blocks[bad - 1]);
                assert_eq!(
                    bc.chain_heads.branch_value_of(pi),
                    Some(brute_value(&bc, pi)),
                    "bad #{}: the retarget's value",
                    bad + 3
                );
            }
            assert_same_projection(&bc, &twin, "after evidence");
        }
    }

    /// AC11.6 / AC6 — local failures restore with no deletion: a read in the
    /// backward walk, in the forward replay (a UTXO output below the common
    /// ancestor) and in the seed-source scan. The candidate switches at its
    /// next trigger. A save never happens: the switch writes nothing.
    #[test]
    fn fr23_local_failures_keep_the_candidate() {
        // Backward walk: `a3` reads once (`s3`'s FORK valuation), then
        // fails for the undo.
        let (mut bc, _, a2, a3) = failing_two_creator_chain();
        let s3 = heavier_sibling(&a2);
        bc.storage.failing_slot = slot(&bc, &a3);
        bc.storage.reads_left.set(1);
        assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (3, a3.view().hash()));
        assert_eq!(status_of(&bc, &s3), Some(BlockStatus::Connected), "kept");
        assert_eq!(bc.storage.attempts.get(), 2, "valued, then the undo failed");
        bc.storage.failing_slot = NONE_REF;
        let si = slot(&bc, &s3);
        assert_eq!(
            bc.switch_toward(si),
            SwitchOutcome::Switched,
            "at the next try"
        );
        assert_eq!(head_of(&bc), (3, s3.view().hash()));

        // No durable write: with every save failing, a switch still succeeds.
        let (mut bc, _, a2, a3) = faulty_two_creator_chain();
        let s3 = heavier_sibling(&a2);
        bc.storage.failing_read_slot = slot(&bc, &a3);
        // The FORK valuation cannot read `a3`: `s3` stays Stored, uncompared.
        assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
        bc.storage.failing_read_slot = NONE_REF;
        let unrelated = transfer(9, [0x33; 32], 0, 3);
        bc.storage.fail_saves = false;
        assert_eq!(
            receive(&mut bc, &unrelated),
            ReceiveBlockOutcome::AcceptedSilently
        );
        if head_of(&bc).1 != s3.view().hash() {
            bc.storage.fail_saves = true;
            let si = slot(&bc, &s3);
            assert_eq!(bc.switch_toward(si), SwitchOutcome::Switched);
            bc.storage.fail_saves = false;
        }
        assert_eq!(head_of(&bc), (3, s3.view().hash()));

        // Forward replay: `n4` spends from the mint, which cannot be read.
        let (mut bc, mint) = faulty_utxo_genesis();
        let o4 = real_on(&bc, &transfer(4, mint.view().hash(), 0, 7), 1, NODE_ONE_KEY);
        assert_eq!(receive(&mut bc, &o4), ReceiveBlockOutcome::AcceptedSilently);
        let tx = utxo_tx_vote(1, 4, &[(3, 0, 60)], None, &[Ok(60)]);
        let n4 = complex_tx_block(4, mint.view().hash(), 0, 0, &[&tx]);
        assert_eq!(receive(&mut bc, &n4), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(status_of(&bc, &n4), Some(BlockStatus::Connected));
        let n5 = resign(
            &transfer(5, n4.view().hash(), 0, 9),
            1,
            vote_snapshot(vote_snapshot(1000) + 1000),
            NODE_ONE_KEY,
        );
        bc.storage.failing_read_slot = slot(&bc, &mint);
        assert_eq!(receive(&mut bc, &n5), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (4, o4.view().hash()), "kept");
        assert_eq!(status_of(&bc, &n5), Some(BlockStatus::Connected));
        bc.storage.failing_read_slot = NONE_REF;
        // `n5`'s transfer credited node #0 once.
        let n6 = resign(
            &transfer(6, n5.view().hash(), 0, 10),
            0,
            vote_snapshot(1000),
            1,
        );
        assert_eq!(receive(&mut bc, &n6), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(
            head_of(&bc),
            (6, n6.view().hash()),
            "switched at the next trigger"
        );

        // Seed-source scan: #0 cannot be read.
        let (mut bc, b1) = faulty_genesis(16);
        let a2 = snapshot_block(&bc, 2, b1.view().hash());
        assert_eq!(receive(&mut bc, &a2), ReceiveBlockOutcome::AcceptedSilently);
        let n2 = tx_block(2, b1.view().hash(), 0, votes_for(2, 0, 3, 81));
        bc.storage.failing_read_slot = 0;
        assert_eq!(receive(&mut bc, &n2), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (2, a2.view().hash()), "kept");
        assert_eq!(status_of(&bc, &n2), Some(BlockStatus::Connected));
        assert_eq!(bc.node_info.seed_source_of(0), Some(slot(&bc, &a2)));
    }

    /// AC11.6 / AC6 — a restore failure: the third read of `a3` fails while
    /// the original chain is re-applied, so the head stops at `a2` with an exact
    /// state, `a3` is a Connected head with the old value, and nothing of the
    /// original chain is deleted. A later switch toward `a3`'s extension has
    /// its common ancestor at the head: a forward replay only.
    #[test]
    fn fr23_restore_failure_stops_at_the_highest_block_reached() {
        let (mut bc, b1) = failing_genesis(16);
        let a2 = alt(2, b1.view().hash(), 0, 0, 1, 7, true);
        let a3 = alt(3, a2.view().hash(), 1, 1, 0, 8, false);
        for blk in [&a2, &a3] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        let forged = resign(&heavier_sibling(&a2), 1, 2000, NODE_ONE_KEY);
        assert_eq!(
            receive(&mut bc, &forged),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(status_of(&bc, &forged), None, "attempted once, deleted");
        // A second forgery, now with `a3` readable once (the undo) only.
        let forged = resign(&heavier_sibling(&a2), 1, 2001, NODE_ONE_KEY);
        bc.storage.failing_slot = slot(&bc, &a3);
        // `a3` is read for the FORK valuation and for the undo; the restore's
        // re-read fails.
        bc.storage.reads_left.set(2);
        assert_eq!(
            receive(&mut bc, &forged),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(head_of(&bc), (2, a2.view().hash()), "stopped at a2");
        assert_eq!(status_of(&bc, &a3), Some(BlockStatus::Connected));
        assert_eq!(
            status_of(&bc, &forged),
            None,
            "the offender is still deleted"
        );
        assert_eq!(bc.chain_heads.branch_value_of(slot(&bc, &a3)), Some(1005));
        let (mut fresh, _, _) = ready_genesis(16);
        assert_eq!(
            receive(&mut fresh, &a2),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_same_projection(&bc, &fresh, "exact at a2");

        bc.storage.failing_slot = NONE_REF;
        // `a3` credited only its own creator, so node #0's `a4` is worth 0.
        let a4 = alt(4, a3.view().hash(), 0, 0, 0, 9, false);
        assert_eq!(receive(&mut bc, &a4), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (4, a4.view().hash()));
    }

    /// AC11.7 / D3 — on W4 (`#0, #1, b2, b3`, tail not advanced) the new
    /// branch from `b2` crosses `W`: its replay advances a virtual tail past
    /// #0, #1 and finally `b2`, the common ancestor. A failure after the
    /// first advance restores the original branch exactly — impossible had
    /// the advances released their blocks, since releasing `b2` deletes the
    /// branches forked at it. On success the commit releases all three and
    /// the abandoned branch with `b2`. A block skipping its due replay (the
    /// chain-config replay #1 needs) is exact evidence.
    #[test]
    fn fr23_tail_advances_wait_for_the_commit() {
        // Every block is node #0's and worth 0; `n6` drops `b2`, which holds
        // no obligation, and makes the tip larger than `b3`.
        let branch = |bc: &TestChain, b2: &Block, last_is_replay: bool| {
            let n3 = transfer(3, b2.view().hash(), 0, 51);
            let n4 = snapshot_block(bc, 4, n3.view().hash());
            let n5 = if last_is_replay {
                w4_config_anchor_block(5, n4.view().hash())
            } else {
                tx_block(5, n4.view().hash(), 0, votes_for(5, 0, 3, 52))
            };
            let n6 = tx_block(6, n5.view().hash(), 0, votes_for(6, 0, 3, 53));
            [n3, n4, n5, n6]
        };
        let (_, _, b1) = ready_genesis(4);
        let b2 = transfer(2, b1.view().hash(), 0, 7);
        for last_is_replay in [false, true] {
            let (mut bc, b3) = full_w4_genesis();
            let (twin, _) = full_w4_genesis();
            let blocks = branch(&bc, &b2, last_is_replay);
            assert!(blocks[3].view().len() > b3.view().len());
            for blk in [&blocks[3], &blocks[2], &blocks[1], &blocks[0]] {
                assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
            }
            if last_is_replay {
                assert_eq!(head_of(&bc), (6, blocks[3].view().hash()));
                assert_eq!(bc.active_snake_chain_window(), Ok((3, 6)));
                assert_eq!(status_of(&bc, &b3), None, "released with b2's forks");
                let (mut fresh, _, _) = ready_genesis(4);
                assert_eq!(
                    receive(&mut fresh, &b2),
                    ReceiveBlockOutcome::AcceptedSilently
                );
                for blk in &blocks {
                    assert_eq!(
                        receive(&mut fresh, blk),
                        ReceiveBlockOutcome::AcceptedSilently
                    );
                }
                assert_same_projection(&bc, &fresh, "committed");
            } else {
                assert_eq!(head_of(&bc), (3, b3.view().hash()), "restored");
                assert_eq!(bc.active_snake_chain_window(), Ok((0, 3)));
                assert_eq!(status_of(&bc, &blocks[2]), None, "skipped replay: deleted");
                assert_eq!(status_of(&bc, &blocks[3]), None, "with its descendant");
                assert_eq!(status_of(&bc, &blocks[1]), Some(BlockStatus::Connected));
                assert_same_projection(&bc, &twin, "restored after the advances");
            }
        }
    }

    /// AC11.8 / DEC-204 — once the tail has advanced, a heavier admissible
    /// fork inside `H` is not switched to: its replayed block would drop a
    /// released block. Nothing changes and nothing is read.
    #[test]
    fn fr23_no_switch_once_the_tail_has_advanced() {
        let (mut bc, b3) = full_w4_genesis();
        let (mut twin, _) = full_w4_genesis();
        let r4 = snapshot_block(&bc, 4, b3.view().hash());
        for node in [&mut bc, &mut twin] {
            assert_eq!(receive(node, &r4), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(bc.active_snake_chain_window(), Ok((1, 4)));
        let s4 = tx_block(4, b3.view().hash(), 0, votes_for(4, 0, 3, 60));
        assert_eq!(receive(&mut bc, &s4), ReceiveBlockOutcome::AcceptedSilently);
        let si = slot(&bc, &s4);
        assert_eq!(bc.switch_target([Some(si), None]), Some(si), "it would win");
        assert_eq!(bc.switch_toward(si), SwitchOutcome::NotAdmitted);
        assert_same_projection(&bc, &twin, "not admitted");
    }

    /// AC11.9 / D5 — the pre-pass: a bad signature by a creator registered at
    /// or below the common ancestor is deleted before anything is touched (no
    /// read of the old head beyond its FORK valuation); one by a creator
    /// registered above it is refused by the replay instead, which restores
    /// and deletes it.
    #[test]
    fn fr23_signature_prepass() {
        let (mut bc, _, a2, a3) = failing_two_creator_chain();
        let bad = resign(&heavier_sibling(&a2), 1, vote_snapshot(1000), 0x77);
        bc.storage.failing_slot = slot(&bc, &a3);
        bc.storage.reads_left.set(1);
        assert_eq!(
            receive(&mut bc, &bad),
            ReceiveBlockOutcome::AcceptedSilently
        );
        assert_eq!(status_of(&bc, &bad), None, "deleted by the pre-pass");
        assert_eq!(head_of(&bc), (3, a3.view().hash()));
        assert_eq!(
            bc.storage.attempts.get(),
            1,
            "only the FORK valuation read a3"
        );
        bc.storage.failing_slot = NONE_REF;

        let (mut bc, b1, _, a3) = two_creator_chain();
        let (twin, _, _, _) = two_creator_chain();
        let n2 = alt(2, b1.view().hash(), 0, 0, 1, 55, true);
        let n3 = resign(
            &alt(3, n2.view().hash(), 1, 1, 3, 56, false),
            1,
            vote_snapshot(1000),
            0x77,
        );
        for blk in [&n3, &n2] {
            assert_eq!(receive(&mut bc, blk), ReceiveBlockOutcome::AcceptedSilently);
        }
        assert_eq!(head_of(&bc), (3, a3.view().hash()));
        assert_eq!(status_of(&bc, &n3), None, "refused by the replay");
        let n2i = slot(&bc, &n2);
        assert!(
            bc.blocks
                .get(n2i)
                .is_some_and(|e| e.is_signature_verified())
        );
        assert_same_projection(&bc, &twin, "after the replay's refusal");
    }

    /// AC10 — switch, then restart: FR2 picks a sequence-3 tip by hash, and
    /// the restart's comparison switches to the heavier one again.
    #[test]
    fn fr23_switch_survives_a_restart() {
        let (mut bc, _, a2, _) = two_creator_chain();
        let s3 = heavier_sibling(&a2);
        assert_eq!(receive(&mut bc, &s3), ReceiveBlockOutcome::AcceptedSilently);
        assert_eq!(head_of(&bc), (3, s3.view().hash()));
        let mut restarted = restart(bc);
        let _ = restarted.initialize_from_storage(0);
        assert!(restarted.is_ready());
        assert_eq!(head_of(&restarted), (3, s3.view().hash()));
    }
}
