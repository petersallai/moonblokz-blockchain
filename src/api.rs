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
    Block, BlockBuilder, BlockHeader, BlockView, HEADER_SIZE, MAX_BLOCK_SIZE, MAX_PAYLOAD_SIZE,
    NodeTransfer, PAYLOAD_TYPE_BALANCE, PAYLOAD_TYPE_CHAIN_CONFIG, PAYLOAD_TYPE_TRANSACTION,
    REGISTRATION_SIZE, Registration, TransactionView,
};
use moonblokz_configuration::{BuildLimits, ChainConfigTrait, limits_are_expressible};
use moonblokz_crypto::{
    CryptoTrait, PUBLIC_KEY_SIZE, PublicKeyTrait, SIGNATURE_SIZE, SignatureTrait,
};
use moonblokz_storage::StorageTrait;
use moonblokz_vote::{VoteEngine, VoteEngineError};

use crate::blocks::{BlockEntry, BlockTable, NONE_REF, SPENT_BITS_BYTES};
use crate::chain_heads::ChainHeadsTable;
use crate::intake::classify_block;
use crate::lifecycle::is_legal_transition;
use crate::node_info::NodeInfoState;
use crate::prng::Prng;
use crate::spent_bits::resolve_utxo_bit;
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

/// Why an FR59 restart refused the durable store (architecture §3.6: a failed
/// precondition is a `Rejected` outcome, never a panic).
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum RestartRejectReason {
    /// Durable blocks are present but the control plane could not be read, so the
    /// configuration those blocks were validated under cannot be established.
    ControlPlaneUnreadable,
    /// The control plane holds a chain-config block that cannot be used — its
    /// envelope does not frame, or the configuration module refused its content.
    /// Continuing would run the chain under a configuration nobody committed to.
    ChainConfigUnusable,
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
///   `moonblokz_configuration`'s trait, read through the `ActiveConfig` handle
///   at the moment each value is needed (FR56); this crate never names a
///   concrete implementation.
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
    /// Block-creator signature invalid against the creator's derived key.
    CreatorSignatureInvalid,
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
    /// A complex tx UTXO input does not resolve against the candidate window
    /// (no matching transaction, or `output_index` out of bounds).
    UtxoUnresolvable,
    /// A complex tx UTXO input references an output whose spent-bit is already 1.
    UtxoAlreadySpent,
    /// A `payload_type=3` block's config content is not byte-identical to the
    /// configuration this node holds — the durable-locked one when the FR8 lock
    /// is engaged, otherwise the tentatively-loaded one (Story 5.9).
    ChainConfigMismatch,
    /// FR8/AC3: the candidate segment carries **no** chain-config block in scope.
    /// Not evidence against any single block — a segment that names no
    /// configuration cannot satisfy FR6 chain-config compliance at all — so the
    /// FR5 deletion target is the candidate head, the same fallback the
    /// no-`block_idx` variants take.
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
    /// A balance-only complex transaction's total balance inputs are less than its
    /// total balance outputs (money creation). The UTXO-value side of this
    /// invariant is validated with the Story-7.1 UTXO cache (see Dev Notes).
    InsufficientTransactionInputs,
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
    //   `generic_const_exprs` feature). Story 5.8 settled the ownership instead
    //   of the sizing: the *chain's* value is a configuration parameter read
    //   through the handle, and the *build's* capacity is stated once to the
    //   configuration module in `BUILD_LIMITS` (`SPENT_BITS_BYTES * 8`), which
    //   is where the two are now reconciled. Epic 7 gives `spent_bits` its
    //   semantics.
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
    /// This build's capacities, stated for the configuration module's §6
    /// acceptance checks — the two bounds that crate cannot derive because the
    /// capacities live here (specification §6, `BuildLimits`).
    ///
    /// Hand this to `ChainConfiguration::new` rather than restating the numbers
    /// at the construction site: the module keeps no copy of them, so the two §6
    /// checks read exactly what this constant says, and drift between the
    /// blockchain's arrays and the module's bounds stays unrepresentable.
    ///
    /// - `utxo_unspent_bits` — `SPENT_BITS_BYTES * 8`, the per-block spent-bit
    ///   width of `BlockEntry` (Story 4.1 fixes the field at 32 bytes).
    /// - `snake_chain_length_max` — `SNAKE_CHAIN_LENGTH`. Before Story 5.11 the
    ///   window length *is* the capacity; 5.11 changes the value passed here,
    ///   not this seam.
    pub const BUILD_LIMITS: BuildLimits = BuildLimits {
        utxo_unspent_bits: (SPENT_BITS_BYTES * 8) as u16,
        snake_chain_length_max: {
            assert!(
                SNAKE_CHAIN_LENGTH <= u16::MAX as u32,
                "SNAKE_CHAIN_LENGTH must fit the configuration module's u16 capacity"
            );
            SNAKE_CHAIN_LENGTH as u16
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
            (&raw mut (*p)._snake_chain_tail_idx).write(0);
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
            blocks: BlockTable::new(),
            chain_heads: ChainHeadsTable::new(),
            node_info: NodeInfoState::new(),
            vote_engine: VoteEngine::new(),
            last_parent_request_emit_timestamp: 0,
            active_chain_head_idx: NONE_REF,
            tentative_config_block_idx: NONE_REF,
            _snake_chain_tail_idx: 0,
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
        // projections are Epic 7.)

        // Block #0 — active-chain anchor (no parent).
        self.storage
            .save_block(0, &block_0)
            .map_err(|_| GenesisRejectReason::StorageSaveFailed)?;
        let mut entry_0 = BlockEntry::new(block_0.hash(), NONE_REF, 0);
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
            .map_err(|_| GenesisRejectReason::StorageSaveFailed)?;
        // The durable chain-configuration seam (FR54): the blockchain owns the
        // storage handle, so the durable commit is made here rather than by the
        // configuration module (configuration specification §8.2).
        self.storage
            .set_chain_configuration(&block_1)
            .map_err(|_| GenesisRejectReason::StorageSaveFailed)?;
        // Every durable write has succeeded: promote the tentative to FR54's
        // set-once lock. `promote_durable` can only fail with `NotLoaded` or
        // `DurableLocked`, and the load above plus the guard at the top of this
        // method rule both out.
        self.chain_config
            .promote_durable()
            .map_err(|_| GenesisRejectReason::InitialChainConfigRejected)?;
        // The engine was constructed on the inert baseline while the module held
        // no configuration (see `vote_parameters`); it now has FR37 values.
        self.reset_vote_engine();
        let block_1_prev_hash = block_0.hash();
        let mut entry_1 = BlockEntry::new(block_1.hash(), 0, 1);
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
    /// Carries a `NextCall` per AR4 (a state-changing init step).
    pub fn initialize_from_storage(&mut self, now: u64) -> CallResult<InitOutcome> {
        // Step 1 — the durable footprint, read exactly once.
        //
        // A store whose control plane was never initialized is indistinguishable
        // from a fresh node, so it is only an error when blocks are actually
        // present: then the node would be rebuilding a chain without knowing the
        // configuration those blocks were accepted under.
        let control = match self.storage.load_control_data() {
            Ok(control) => control,
            Err(_) => {
                return if self.durable_block_count() == 0 {
                    (InitOutcome::StartedCollecting, NextCall::Idle)
                } else {
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
        if let Some(config_block) = control.chain_configuration.as_ref() {
            let bytes = config_block.serialized_bytes();
            // The control plane stores the block zero-padded to the slot width
            // and records no length, exactly like a block slot, so the payload
            // has to come from the recovered exact length — never from
            // `serialized_bytes().len()`.
            let Some(payload) = Self::exact_view(bytes).map(|view| view.payload()) else {
                return (
                    InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable),
                    NextCall::Idle,
                );
            };
            if self.chain_config.load_durable(payload).is_err() {
                return (
                    InitOutcome::Rejected(RestartRejectReason::ChainConfigUnusable),
                    NextCall::Idle,
                );
            }
            self.reset_vote_engine();
        }

        // Step 3 — rebuild the tree, its linkage and its heads.
        let rebuilt = self.rebuild_block_tree_from_storage(now);
        if rebuilt == 0 {
            // Nothing to resume. This is the fresh-join shape even when the
            // control plane is initialized.
            return (InitOutcome::StartedCollecting, NextCall::Idle);
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

    /// Number of durable slots that read back as blocks. Used only to tell a
    /// never-initialized store apart from a populated one whose control plane is
    /// unreadable.
    fn durable_block_count(&self) -> usize {
        let limit = self.durable_scan_limit();
        (0..limit)
            .filter(|idx| self.storage.read_block(*idx).is_ok())
            .count()
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
    /// block, the FR8 lock re-runs its mismatch cleanup, and FR19 eviction
    /// re-fires under capacity pressure — so the node still converges. What is
    /// **not** claimed is that the rebuilt tree equals the pre-shutdown tree.
    fn rebuild_block_tree_from_storage(&mut self, now: u64) -> usize {
        let limit = self.durable_scan_limit();
        let mut admitted = 0usize;

        // Pass 1 — materialize every readable slot at its own index. Parent
        // linkage is deliberately left unresolved: durable slot order is not
        // topological, so a parent may live at a higher index than its child.
        for idx in 0..limit {
            let Ok(padded) = self.storage.read_block(idx) else {
                continue;
            };
            let Some(view) = Self::exact_view(padded.serialized_bytes()) else {
                continue;
            };
            let hash = view.hash();
            let sequence = view.sequence();
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
        for idx in 0..limit {
            if self.blocks.get(idx).is_none() {
                continue;
            }
            let Ok(padded) = self.storage.read_block(idx) else {
                continue;
            };
            let Some(view) = Self::exact_view(padded.serialized_bytes()) else {
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
        self.chain_heads.rebuild_from_blocks(&mut self.blocks, now);

        admitted
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
        for idx in 0..limit {
            let is_config = self
                .blocks
                .get(idx)
                .is_some_and(|entry| entry.payload_type() == PAYLOAD_TYPE_CHAIN_CONFIG);
            if !is_config {
                continue;
            }
            let Ok(padded) = self.storage.read_block(idx) else {
                continue;
            };
            let Some(view) = Self::exact_view(padded.serialized_bytes()) else {
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

        if let Err(e) = self.storage.save_block(idx, &owned) {
            let _ = e;
            // The durable write is the one step after the load that can still
            // fail. Undo the load rather than keep a configuration whose block
            // was never persisted: on the next boot the block is not there, so a
            // node that kept it would be deriving from a configuration it can no
            // longer justify (and FR49 replay could not reproduce).
            if loads_tentative {
                self.chain_config.discard_tentative();
            }
            return Err(AdmitError::StorageSaveFailed);
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
        if is_genesis {
            entry.set_on_active_chain(true);
        }
        self.blocks.insert_at(idx, entry);
        if is_genesis {
            self.active_chain_head_idx = idx;
        }
        // FR8 provenance (AC8): record which retained block supplied the
        // tentative content, now that it has a slot. Written only on the path
        // that actually loaded, so it always names a live block.
        if loads_tentative {
            self.tentative_config_block_idx = idx;
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
        (outcome, self.next_parent_recovery_call())
    }

    /// The FR2→FR3→FR6→FR4 acquisition spine: while a candidate segment
    /// qualifies, reconstruct and validate it, and either transition to `Ready`
    /// or recover per FR5 and fall back to `Collecting`.
    ///
    /// Extracted from [`Self::receive_block`] so the FR59 restart
    /// ([`Self::initialize_from_storage`]) drives **the identical** loop rather
    /// than a parallel copy of it. FR59 requires a restart to reuse "the
    /// identical acquisition / reconstruction / validation code paths as a fresh
    /// join (no separate restart-only logic)"; sharing the body is what makes
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
                Ok(()) => {
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
                            // abort-path spent-bit rollback. Abandoning the
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
                                self.blocks.clear_spent_bits(idx as u32);
                            }
                            self.set_lifecycle_phase(LifecyclePhase::Collecting);
                            break;
                        }
                        // FR6 passed over the full candidate → FR4 Ready
                        // transition: atomically promote every candidate block
                        // Stored→Active (the Epic-4-deferred FR9 Tier-3
                        // driver) and establish the active head.
                        self.promote_candidate_active(candidate_tip_idx);
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
                        self.promote_candidate_active(candidate_tip_idx);
                    }
                    // Processing→Ready. The FR40-series ready-only surface
                    // becomes live (its query bodies remain Epic 7/10
                    // `todo!()` — reachable, but this story wires no caller).
                    self.set_lifecycle_phase(LifecyclePhase::Ready);
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
                            // The re-evaluation returns the same tip. The only
                            // tree change an adopt makes is deleting an
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
                    // `SNAKE_CHAIN_LENGTH` (a large piece having just connected)
                    // still clears the threshold after losing its tip.
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
                    // block commits.
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
    /// - the marked segment's UTXO spent-bits are **already** back at their
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
    /// **earliest** offender. Every other variant (`MarkOverflow`,
    /// `MissingBlock`, `StorageRead`, `Vote(_)`) is not evidence against a
    /// specific block, so the target is the candidate head — FR5's explicit
    /// "delete exactly one block, the candidate chain's head" fallback, which is
    /// what makes `Vote(_)` carrying no `block_idx` safe. `ValidationReason` is
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
    /// because FR2 accepts a genesis-anchored segment at any length. The node
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
    /// spent-bits instead of restoring them.
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

        // Step 2 — exact offender, else the candidate-head fallback.
        let target = match err {
            ProcessingError::Invalid { block_idx, .. } => block_idx,
            ProcessingError::MarkOverflow
            | ProcessingError::MissingBlock
            | ProcessingError::StorageRead
            | ProcessingError::Vote(_) => candidate_tip_idx,
        };

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
        // **Ordered after the spent-bit baseline below, not before it.** The FR5
        // recovery documents itself as relying on this pass having zeroed the
        // marked segment's spent-bits at entry and re-zeroed them on its abort
        // path; an early return above that baseline would leave bits from an
        // earlier uncommitted pass set and quietly break that contract.
        //
        // AC5 (spent-bit lifecycle): establish the clean all-zero baseline for the
        // marked segment's spent-bits at entry — matching the `node_info` /
        // `vote_engine` reset above — so the pass is idempotent on re-entry and the
        // failure rollback below restores exactly this baseline (not the whole
        // vector against an unknown prior state). For the MVP join/reconstruct flow
        // the marked blocks are freshly-admitted `Stored` blocks (spent-bits already
        // 0); the reset makes the reusable primitive self-consistent for a
        // re-derivation over a candidate whose blocks are NOT shared with an
        // already-active chain (fresh join, the Story-5.10 restart, and the Epic-6
        // deep-zone reconstruction of a *new* branch). A chain-switch that
        // re-derives over blocks shared with the active chain must operate on a
        // working copy instead (owned by Epic 6): a failed re-derivation here would
        // zero a shared block's committed spent-bits rather than restore them.
        for slot in marked.iter().take(count) {
            self.blocks.clear_spent_bits(*slot);
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
        // bounds that to the single head deletion FR5 intends.
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
        if !genesis_anchored
            && floor_balance_idx != NONE_REF
            && let Ok(floor_block) = self.storage.read_block(floor_balance_idx)
        {
            // Trim the zero-padded read-back to the exact stored length before
            // parsing, exactly as the forward walk does.
            let full = floor_block.serialized_bytes();
            let n = match self.blocks.get(floor_balance_idx).map(|e| e.len() as usize) {
                Some(len) if len > 0 && len <= full.len() => len,
                _ => full.len(),
            };
            if let Ok(view) = BlockView::from_bytes(&full[..n])
                && let Some(payload) = view.balances()
            {
                self.node_info.set_max_known_node_id(payload.max_node_id());
            }
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
                roster_bounded,
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
    // The per-block context (indices, the marked segment, and the two anchor-kind
    // flags) is passed as flat parameters rather than bundled into a struct: they
    // are all read-only scalars threaded straight through from `run_processing_pass`,
    // and a wrapper would add indirection without clarifying the single call site.
    #[allow(clippy::too_many_arguments)]
    fn validate_and_derive_block(
        &mut self,
        view: BlockView<'_>,
        idx: u32,
        prev_hash: Option<[u8; 32]>,
        saw_balance_block: &mut bool,
        marked: &[u32; MAX_BLOCKS],
        genesis_anchored: bool,
        roster_bounded: bool,
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
        // (a) size ≤ chain-config limit — but only once that limit is durably
        // locked (FR9). While the configuration is merely tentative this yields
        // the structural ceiling, so the check cannot produce `Invalid` and
        // cannot delete; the enforcement is re-run against the real limit at the
        // durable lock, which is one of the two moments FR9 names.
        if view.len() > self.enforceable_block_size_limit() as usize {
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
            // non-derivable creator past block #0 is exact evidence of invalidity,
            // not a trusted pre-seed block (AC2/AC4 genesis-anchored). Uses
            // `!is_genesis_zero` — the same "only block #0 is bootstrap-exempt"
            // predicate as the tx-level actor checks below (block #1's config
            // creator is node #0, which resolves to the trust anchor, never `None`).
            None if genesis_anchored && !is_genesis_zero => {
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
                        // FR6 node-existence bound: the initializer (input) and the
                        // receiver (output) must name nodes that can exist
                        // (`id <= max_known_node_id`) — checkable even when unseeded
                        // (a pre-window node's *existence* is still range-bounded).
                        if roster_bounded && !is_genesis_zero {
                            self.check_node_id_in_range(init).map_err(&invalid)?;
                            self.check_node_id_in_range(nt.receiver())
                                .map_err(&invalid)?;
                        }
                        // State-dependent FR6 checks apply once the initializer is
                        // derivable (past its pre-seed zone). The intrinsic
                        // invariants (no-self-vote, anchor-before-block) are decided
                        // from the block bytes alone and are owned by the Tier-1
                        // intake gate (`staged_validation`), which every admitted
                        // block passed before it could reach this pass — so they are
                        // not re-checked here.
                        if !is_genesis_zero && self.node_info.is_seeded(init) {
                            self.check_vote_target(vote).map_err(&invalid)?;
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
                        let node_id = reg.new_node_id();
                        let init = reg.initializer();
                        // [A] Genesis-anchored: the registering initializer must be
                        // an existing (seeded) node; unseeded ⇒ invalid (block #0's
                        // node-#0 self-registration is the FR54 bootstrap exception).
                        if genesis_anchored && !is_genesis_zero && !self.node_info.is_seeded(init) {
                            return Err(invalid(ValidationReason::UnseededActor));
                        }
                        // FR6 node-existence bound: the registering initializer must
                        // name an existing node (`id <= max_known_node_id`), checkable
                        // even when unseeded. (`new_node_id` is the id being *created*
                        // — bounded by the monotonicity check, not this range check.)
                        if roster_bounded && !is_genesis_zero {
                            self.check_node_id_in_range(init).map_err(&invalid)?;
                        }
                        // FR6 registration monotonicity: `new_node_id ==
                        // pre-block-position watermark + 1`, checked against the
                        // running watermark so within-block registrations form a
                        // stride-1 sequence. Waived for genesis block #0
                        // (`new_node_id == 0`, FR54(h)). Reads the incremental
                        // watermark, which is authoritative only once established —
                        // from block #0 on a genesis-anchored candidate, or from the
                        // first balance block on a window-anchored one; before that
                        // (window-anchored pre-first-balance region) it is trusted
                        // (AC4), matching the vote-target existence floor.
                        if !is_genesis_zero {
                            if genesis_anchored || *saw_balance_block {
                                let expected = self.node_info.max_known_node_id().wrapping_add(1);
                                if node_id != expected {
                                    return Err(invalid(ValidationReason::RegistrationWatermark));
                                }
                            }
                            // No-self-vote is intrinsic and owned by the Tier-1 gate
                            // (checked at admission); not re-checked here.
                            if self.node_info.is_seeded(init) {
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
                        // [E] FR6 registration uniqueness: `new_public_key` must not
                        // already be held by a seeded/registered node on the
                        // candidate (within-block earlier registrations are seeded
                        // in tx order, so a same-block collision is caught too).
                        // Checked before any state mutation below, so a rejection
                        // leaves no dirty watermark/roster.
                        if self.node_info.key_is_registered(reg.new_public_key()) {
                            return Err(invalid(ValidationReason::DuplicatePublicKey));
                        }
                        // Advance the watermark for an in-range id (genesis #0 does
                        // not advance it — FR54(h)); then register the roster entry.
                        if !is_genesis_zero && (node_id as usize) < MAX_NODES {
                            let advanced = self.node_info.max_known_node_id().max(node_id);
                            self.node_info.set_max_known_node_id(advanced);
                        }
                        self.node_info
                            .register_node(node_id, reg.new_public_key(), idx);
                    } else if let Some(cx) = tx.as_complex() {
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
                                // FR6 node-existence bound: the balance-input
                                // initializer (input side) must name an existing node,
                                // checkable even when unseeded.
                                if roster_bounded && !is_genesis_zero {
                                    self.check_node_id_in_range(binit).map_err(&invalid)?;
                                }
                                // No-self-vote and anchor-before-block are intrinsic,
                                // owned by the Tier-1 gate (checked at admission);
                                // only the state-dependent checks run here.
                                if !is_genesis_zero && self.node_info.is_seeded(binit) {
                                    self.check_vote_target(vote).map_err(&invalid)?;
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
                                // FR6 node-existence bound: the balance-output
                                // receiver (output side) must name an existing node,
                                // checkable even when unseeded.
                                if roster_bounded && !is_genesis_zero {
                                    self.check_node_id_in_range(bo.receiver())
                                        .map_err(&invalid)?;
                                }
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
                            return Err(invalid(ValidationReason::InsufficientTransactionInputs));
                        }
                        total_fees = total_fees.saturating_add(in_sum.saturating_sub(out_sum));
                    } else {
                        return Err(invalid(ValidationReason::MalformedPayload));
                    }
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
            // yet at its own point in the chain. Same-block UTXO chaining (spending
            // an output created by an earlier tx in the SAME block) is
            // conservatively forbidden here (`>=`, not `>`): the per-block spent-bit
            // model cannot order txs within a block, so tx-order-aware intra-block
            // resolution is deferred to the Story-7.1 UTXO cache.
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
    fn scan_candidate_chain_config(&self, tip: u32, probe: u32) -> (u32, bool) {
        let mut first_config_idx = NONE_REF;
        let mut probe_on_segment = false;
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
                break;
            }
            cur = parent;
        }
        (first_config_idx, probe_on_segment)
    }

    /// Reads the block at `idx` back from durable storage, trimmed to its exact
    /// retained length, as the owned `Block` the storage seam takes.
    ///
    /// The trim is not cosmetic: durable backends store blocks in fixed-size
    /// slots and read them back zero-padded, and every FR7/FR8 comparison here is
    /// byte-exact over the signed bytes. This is the same trim the forward pass
    /// applies, factored out because the commitment lifecycle needs it at three
    /// separate seams.
    fn read_retained_block(&self, idx: u32) -> Option<Block> {
        let padded = self.storage.read_block(idx).ok()?;
        let full = padded.serialized_bytes();
        let n = match self.blocks.get(idx).map(|entry| entry.len() as usize) {
            Some(len) if len > 0 && len <= full.len() => len,
            _ => full.len(),
        };
        Block::from_bytes(&full[..n]).ok()
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
        // `MAX_BLOCKS = 600`, taken at the `receive_block` seam where
        // `run_processing_pass`'s equally-sized `marked` buffer is already
        // released — the same budget the FR5 recovery reasons about, and never
        // live at the same time as it.
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
            // fills with an unrelated block.
            self.active_chain_head_idx = NONE_REF;
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
    fn commit_durable_chain_config(&mut self, first_config_idx: u32) -> Result<(), ()> {
        let block = self.read_retained_block(first_config_idx).ok_or(())?;
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
        let Some(block) = self.read_retained_block(idx) else {
            return ConfigPreload::Unreadable;
        };
        match BlockView::from_bytes(block.serialized_bytes())
            .ok()
            .and_then(|view| view.chain_config().map(|config| config.content() == held))
        {
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
        let Some(block) = self.read_retained_block(idx) else {
            return ConfigPreload::Unreadable;
        };
        match BlockView::from_bytes(block.serialized_bytes())
            .ok()
            .and_then(|view| view.chain_config().map(|config| config.content() == locked))
        {
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
    fn adopt_candidate_chain_config(&mut self, tip: u32, first_config_idx: u32) -> Result<(), ()> {
        let block = self.read_retained_block(first_config_idx).ok_or(())?;
        let view = BlockView::from_bytes(block.serialized_bytes()).map_err(|_| ())?;
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
    fn parent_recovery_intervals(&self) -> Option<(u64, u64)> {
        self.chain_config.active_configuration().map(|config| {
            (
                config.parent_recovery_min_emit_interval_ms() as u64,
                config.parent_recovery_per_head_retry_interval_ms() as u64,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moonblokz_chain_types::{
        CONFIG_VALUE_COUNT_SIZE, ChainConfigPayloadBuilder, MAX_BLOCK_SIZE,
    };
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

    /// The empty override set as a **content region**
    /// (`config_value_count = 0`): every parameter resolves to its code-baked
    /// default, and those defaults are exactly the constants the retired
    /// `FixedChainConfig` returned — which is why the suite's expected values
    /// are unchanged.
    const EMPTY_CONFIG_CONTENT: [u8; CONFIG_VALUE_COUNT_SIZE] = [0, 0];

    /// A second content region, valid and **distinct in bytes** but resolving
    /// identically: one literal entry declaring `vote_interest`'s own default.
    /// Used where a test needs two different chain-config contents.
    const OTHER_CONFIG_CONTENT: [u8; 5] = [1, 0, parameter::VOTE_INTEREST, 1, 5];

    /// Storage whose control plane is fine and whose block writes are not.
    ///
    /// `MemoryBackend` cannot express this: a backend large enough to
    /// initialize is large enough to hold blocks. The pair matters because
    /// genesis has two distinct storage failure modes and they refuse at
    /// different points — one before any write, one after the first.
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

        fn read_block(&self, _storage_index: u32) -> Result<Block, StorageError> {
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

    /// A configuration module already durably locked on the empty override set,
    /// standing in for "genesis has run" wherever a test needs a configured node
    /// without bootstrapping one.
    fn locked_chain_config(crypto: &Crypto, limits: BuildLimits) -> TestConfig {
        let mut config = empty_chain_config(limits);
        let mut builder = ChainConfigPayloadBuilder::new();
        config
            .load_durable(builder.build_signed(crypto))
            .ok()
            .expect("the empty override set is accepted content");
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
        4,
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
            core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 4, 16, 4, 16>>::uninit();
        let bc = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::init(
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
            blocks,
            chain_heads,
            node_info,
            vote_engine,
            last_parent_request_emit_timestamp,
            active_chain_head_idx,
            tentative_config_block_idx,
            _snake_chain_tail_idx,
        } = &*bc;

        assert_eq!(*local_node_id, 7);
        assert!(*lifecycle_phase == LifecyclePhase::Collecting);
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
        assert_eq!(*_snake_chain_tail_idx, 0);
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
        let mut slot =
            core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 4, 16, 4, 16>>::uninit();
        let built = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::init(
            &mut slot,
            crypto,
            storage,
            chain_config,
            7,
            [3u8; PUBLIC_KEY_SIZE],
            0xDEAD_BEEF,
        );
        let (crypto, storage, chain_config) = construction_backends();
        let spec = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::new(
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
            blocks,
            chain_heads,
            node_info,
            vote_engine,
            last_parent_request_emit_timestamp,
            active_chain_head_idx,
            tentative_config_block_idx,
            _snake_chain_tail_idx,
        } = &*built;
        let Blockchain {
            crypto: _,
            storage: _,
            chain_config: _,
            local_node_id: spec_local_node_id,
            node_zero_public_key: spec_node_zero_public_key,
            prng: spec_prng,
            lifecycle_phase: spec_lifecycle_phase,
            blocks: spec_blocks,
            chain_heads: spec_chain_heads,
            node_info: spec_node_info,
            vote_engine: spec_vote_engine,
            last_parent_request_emit_timestamp: spec_last_parent_request_emit_timestamp,
            active_chain_head_idx: spec_active_chain_head_idx,
            tentative_config_block_idx: spec_tentative_config_block_idx,
            _snake_chain_tail_idx: spec_snake_chain_tail_idx,
        } = &spec;

        assert_eq!(local_node_id, spec_local_node_id);
        assert_eq!(node_zero_public_key, spec_node_zero_public_key);
        assert!(prng == spec_prng);
        assert!(lifecycle_phase == spec_lifecycle_phase);
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
        assert_eq!(_snake_chain_tail_idx, spec_snake_chain_tail_idx);
    }

    /// AC2 — the neutrality proof: with an empty override set the configuration
    /// module resolves every parameter the blockchain reads to the exact
    /// constant the retired `FixedChainConfig` returned. This is what lets the
    /// rest of the suite keep its expected values unchanged, and it replaces the
    /// stub's own `fixed_returns_expected_constants`.
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
        bc.process_genesis(1_000_000_000, &EMPTY_CONFIG_CONTENT)
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
            Some(&EMPTY_CONFIG_CONTENT[..])
        );
    }

    /// Genesis is a one-shot bootstrap: a second `process_genesis` on the same
    /// node refuses with `StorageNotEmpty` (the chain now carries genesis state).
    #[test]
    fn walking_skeleton_refuses_second_genesis() {
        let (crypto, storage, chain_config) = test_backends();
        let mut bc = new_chain(crypto, storage, chain_config, 0, 0);

        let first = bc.process_genesis(1_000_000_000, &EMPTY_CONFIG_CONTENT);
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
            core::mem::MaybeUninit::<Blockchain<_, _, _, 16, 16, 4, 16, 4, 16>>::uninit();
        let bc = Blockchain::<_, _, _, 16, 16, 4, 16, 4, 16>::init(
            &mut bc_slot,
            crypto,
            BlockWriteFailsStorage,
            chain_config,
            0,
            node_zero,
            0,
        );

        let outcome = bc.process_genesis(1_000_000_000, &EMPTY_CONFIG_CONTENT);

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

        let outcome = bc.process_genesis(1_000_000_000, &EMPTY_CONFIG_CONTENT);

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
        // (> HEADER_SIZE, <= MAX_BLOCK_SIZE), smaller than Block #0.
        let content = [1u8, 0, parameter::BLOCK_SIZE_LIMIT, 2, 0x2C, 0x01];

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
        bc.process_genesis(1_000_000_000, &EMPTY_CONFIG_CONTENT)
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
        4,
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
        bc.process_genesis(1_000_000_000, &EMPTY_CONFIG_CONTENT)
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

    /// A test chain with a small active-chain window (`SNAKE_CHAIN_LENGTH = 4`) so
    /// an active-length segment fits the test harness's block storage. Same shape
    /// as `new_test_chain` otherwise (local_node_id 5, join/Collecting).
    type W4Chain = Blockchain<
        Crypto,
        MemoryBackend<{ 8 * MAX_BLOCK_SIZE + 8000 }>,
        TestConfig,
        16,
        4,
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
        let tail = chain_config_anchor_block(100, [0xAB; 32]);
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
    /// A validly-signed chain-config block carrying the **empty override set** —
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
        chain_config_block_from(seq, prev, &mut ChainConfigPayloadBuilder::new())
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

    /// A **second, equally valid** override set, distinct in bytes from the empty
    /// one: one literal entry declaring `vote_interest`'s own default value. It
    /// resolves every parameter identically to the empty set, so a node adopting
    /// it behaves the same — the only thing that differs is the content bytes,
    /// which is exactly what the FR7/FR8 byte-identity rules turn on.
    fn alt_config_builder() -> ChainConfigPayloadBuilder {
        let mut builder = ChainConfigPayloadBuilder::new();
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

    /// An override set declaring [`SMALL_BLOCK_SIZE_LIMIT`].
    fn small_limit_config_builder() -> ChainConfigPayloadBuilder {
        let mut builder = ChainConfigPayloadBuilder::new();
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

    /// AC11(b) — a non-`Invalid` failure is not exact evidence against any
    /// specific block, so exactly **one** block is deleted: the candidate head.
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
        for err in [
            ProcessingError::StorageRead,
            ProcessingError::MissingBlock,
            ProcessingError::MarkOverflow,
            // AC3 names four non-`Invalid` variants, and `Vote(_)` is the one
            // the fallback exists for: the Story-5.4 review accepted that a vote
            // failure carries no `block_idx`, and this arm is what makes that
            // imprecision safe. Cover it explicitly, not by family resemblance.
            ProcessingError::Vote(VoteEngineError::AccumulatedVoteOverflow),
        ] {
            assert_eq!(
                run(err),
                (2, true, true),
                "the head fallback deletes exactly the candidate head and keeps \
                 the shortened branch tracked"
            );
        }
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
    /// UTXO spent-bit vectors. Driven through the real
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
        // The surviving segment's spent-bits are at the clean all-zero baseline
        // (owned by the pass's entry/abort handling — recovery does not sweep
        // them a second time, and must not need to).
        for idx in [ai, ti] {
            for bit in 0..8 {
                assert_eq!(
                    bc.blocks.spent_bit(idx, bit),
                    Some(false),
                    "no spent-bit survives a failed candidate"
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
            bc.run_processing_pass(ti),
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
            bc.run_processing_pass(bi),
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
        // `new_test_chain` is durably locked on `EMPTY_CONFIG_CONTENT`; this
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
        let mut config_payload = ChainConfigPayloadBuilder::new();
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
        let mut bc = new_test_chain(); // durably locked on the empty override set
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

    /// AC3 — and the refusal is **not** retried: the deletion of the candidate
    /// head is not evidence against it, so the shortened branch still names no
    /// configuration. Retrying would eat a second good block for a structurally
    /// certain second failure.
    #[test]
    fn fr8_missing_config_block_is_not_retried() {
        // A window-anchored candidate of exactly W = 4 blocks, none of them a
        // chain-config block. Window-anchored so every block is pre-seed-trusted
        // and the *only* thing wrong with the candidate is that it names no
        // configuration — which is what makes the deletion count below
        // attributable to the retry rule and nothing else.
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
            !bc.is_ready(),
            "no configuration named → no Ready transition"
        );
        assert!(
            bc.current_phase() == LifecyclePhase::Collecting,
            "the FR5 recovery reverted the phase"
        );
        // Exactly one block deleted — the candidate head — and no retry that
        // would have taken a second good block off the branch for a structurally
        // certain second failure.
        assert_eq!(
            bc.block_tree_len(),
            3,
            "one deletion, not two: the refusal is not retryable"
        );
        assert!(
            bc.blocks.find(100, &tail.view().hash()).is_some(),
            "the deletion took the head, not the anchor"
        );
        assert!(
            bc.blocks.find(103, &b103.view().hash()).is_none(),
            "the candidate head is the block that went"
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
        let mut bc = new_test_chain(); // durably locked on the empty override set
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
            // `config_value_count`, which is 0 for the empty override set config A
            // carries and 1 for config B's.
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
            (true, 4, [0, 0]),
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
        let stray = chain_config_block_from(500, [0xEE; 32], &mut small_limit_config_builder());
        bc.receive_block(stray.view(), 0);
        assert!(
            bc.chain_config.tentative_content().is_some(),
            "the stray supplied the tentative configuration"
        );

        // (3) The candidate's own chain-config block completes the segment at
        // W = 4 and triggers FR2.
        let cfg = chain_config_anchor_block(103, b102.view().hash());
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
        let stray = chain_config_block_from(500, [0xEE; 32], &mut small_limit_config_builder());
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
            chain_config_block_from(103, b102.view().hash(), &mut small_limit_config_builder());
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

        // Restart the *same* durable store a second time, from scratch again.
        let mut second = restart(first);
        // A different `now`: it must not influence the reconstruction.
        let (second_outcome, _) = second.initialize_from_storage(9_999);

        assert_eq!(first_outcome, second_outcome);
        assert_eq!(first_len, second.blocks.len());
        assert_eq!(first_head, second.current_active_head());
    }
}
