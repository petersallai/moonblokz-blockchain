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
    APPROVAL_DEVIATION_SEQUENCE_OFFSET, APPROVAL_LATE_COUNT_SIZE, APPROVAL_LATE_ENTRY_SIZE,
    APPROVAL_M_OFFSET, APPROVAL_PREFIX_SIZE, APPROVAL_SUPPORTER_VOTE_SUM_OFFSET, ApprovalView,
    Block, BlockBuilder, BlockHeader, BlockView, ComplexTransactionView, HASH_SIZE, HEADER_SIZE,
    MAX_BLOCK_SIZE, MAX_PAYLOAD_SIZE, NODE_INFO_SIZE, NodeTransfer, PAYLOAD_TYPE_APPROVAL,
    PAYLOAD_TYPE_BALANCE, PAYLOAD_TYPE_CHAIN_CONFIG, PAYLOAD_TYPE_TRANSACTION,
    PAYLOAD_TYPE_TWIN_FACT, REGISTRATION_SIZE, Registration, TransactionView, TwinFactView,
};
use moonblokz_configuration::{
    BuildLimits, ChainConfigTrait, ChainInfoSource, chain_info, limits_are_expressible,
};
use moonblokz_crypto::{
    AggregatedSignature, AggregatedSignatureTrait, CryptoTrait, MAX_AGGREGATED_SIGNATURES,
    MULTI_SIGNATURE_SIZE, MultiSignature, MultiSignatureTrait, PUBLIC_KEY_SIZE, PublicKey,
    PublicKeyTrait, SIGNATURE_SIZE, SignatureTrait,
};
use moonblokz_storage::{StorageError, StorageTrait};
use moonblokz_vote::{VoteEngine, VoteEngineError};

use crate::approval::{
    ActiveSetCounter, ApprovalAccumulator, ApprovalStep, CIRCULATING_CURRENCY_STUB,
    DEDUPE_SALT_LABEL, MAX_SUBGROUP, NonConflictRing, RING_KIND_SUPPORT, RingCheck,
    SUPPORT_MESSAGE_SIZE, SupportDedupe, SupportMessage, SupportView, in_subgroup, node_value,
    required_signers, subgroup_seed, subgroup_size, support_body_tail, support_message_bytes,
};
use crate::available_utxo::utxo_output_at;
use crate::blocks::{AVAILABLE_UTXO_BYTES, BlockEntry, BlockTable, NONE_REF};
use crate::branch_value::{Rank, block_value, value_cap};
use crate::chain_heads::ChainHeadsTable;
use crate::intake::classify_block;
use crate::lifecycle::is_legal_transition;
use crate::node_info::{NodeInfoState, SEED_SOURCE_RELEASED};
use crate::prng::Prng;
use crate::snake_chain::{
    TailBinding, TailObligation, TailUnreadable, classify_tail_drop, tail_drop_binding,
};
use crate::staged_validation::{
    BlockStatus, SUPPORTED_VERSION, Tier1Failure, tier1_chain_config_block, tier1_gate,
    verify_signature_bytes,
};
use crate::uninit::field_slot;

// `LifecyclePhase` is owned by `lifecycle.rs` (architecture §4.2) and
// re-exported here so the crate's public surface (`api::LifecyclePhase`, and in
// turn `moonblokz_blockchain::LifecyclePhase`) is unchanged after Story 5.1
// relocated the enum out of this module.
pub use crate::lifecycle::LifecyclePhase;

mod acquisition;
mod admission;
mod calls;
mod chain_config;
mod evidence;
mod fact;
mod forward;
mod genesis;
mod outcomes;
mod proposer;
mod restart;
mod step;
mod support;
mod switch;
mod window;

use evidence::{deviation_sum, is_late, late_room, run_after, run_before, run_rules, slot_rule};
pub use outcomes::{
    BalanceQueryError, BlockQueryError, CallResult, GenesisBlocks, GenesisRejectReason,
    InitOutcome, LocalTransactionOutcome, NextCall, ParentRecoveryRequest, ReceiveBlockOutcome,
    ReceiveSupportOutcome, ReceiveTransactionOutcome, RejectReason, RestartRejectReason,
    TickOutcome, TransactionState, TxStateQueryError,
};
use step::{fees_and_utxo_outputs, is_fr36_exempt};

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

/// What lies on the active chain above a deviation `d` at `p`, from the head
/// down (FR27: until its evidence, only `d`'s creator extends `d`). Shared by
/// FR12 emission (6.4) and FR26 intake (6.5).
#[derive(PartialEq, Eq)]
enum AboveP {
    /// Only `d`'s creator, no approval block.
    Clean,
    /// An approval block (`payload_type = 4`): `d`'s evidence.
    Evidence,
    /// Another creator, and no approval block.
    Foreign,
    /// A failed read, or a walk that does not reach `d`: local, not evaluable.
    Unreadable,
}

/// `A' = A \ {proposer, u}` at `p − 1` (ADR-015): the head's active-set
/// counts with the `p − 1` correction of
/// [`Blockchain::parent_set_correction`]. The one membership predicate of
/// 6.4's emission, 6.5's intake and 6.6's accumulator.
struct APrime<'a, const MAX_NODES: usize> {
    proposer: u32,
    u: u32,
    creator_d: u32,
    above: u32,
    returning_d: u32,
    returned: &'a [bool; MAX_NODES],
}

impl<const MAX_NODES: usize> APrime<'_, MAX_NODES> {
    fn contains(&self, set: &ActiveSetCounter<MAX_NODES>, n: u32) -> bool {
        n != self.proposer
            && n != self.u
            && set.in_set_at_parent(
                n,
                self.creator_d,
                self.above,
                self.returning_d,
                self.returned.get(n as usize).copied().unwrap_or(false),
            )
    }
}

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
    /// A registration's `new_node_id`, or a balance block's `max_node_id`, is at
    /// or above the chain's `max_node_count` (DEC-228). The cap is the chain's,
    /// so every node judges it alike, whatever its `MAX_NODES`.
    NodeCountExceeded,
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
    /// FR48: the block drops a block whose essential state it does not
    /// replay — evaluated in the FR3 pass wherever the dropped block lies in
    /// the segment (Story 6.14 AC9, DEC-204).
    TailDropUnpreserved,
    /// FR16 / FR27 (Story 6.7 AC4 rule 1): a block above an open deviation run
    /// whose creator is not the deviation's creator.
    RunCreator,
    /// I-11 / FR27 (AC4 rule 2): a block above an open deviation run not in
    /// override form (`first_voted_node == creator`, `consumed_votes == 0`).
    RunHeader,
    /// FR27 (AC4 rule 3): an approval evidence block that does not close an
    /// open run by its creator, or names another deviation sequence.
    EvidencePlacement,
    /// FR27 (AC4 rule 4, D1): a run's non-evidence block above `p + H − 1`, or
    /// its evidence block above `p + H`.
    RunBound,
    /// FR48 clean slot (AC4 rule 5, D8): a block at `s ≡ H − 1 (mod H)` that
    /// is not clean.
    SlotNotClean,
    /// FR6 / FR12 / ADR-015 (Story 6.7 AC5): the evidence's `m`, its signer
    /// count against `r_eff`, or a signer outside the subgroup at `p − 1`.
    EvidenceSubgroup,
    /// FR21 / DEC-216 (AC5): `supporter_vote_sum` is not `B_k − cv(d)`.
    EvidenceVoteSum,
    /// DEC-184 (AC5): the late-node list is not the prefix that fits, in
    /// creator order at `p − 1`, or a listed vote is not its value at the tip.
    EvidenceLateList,
    /// FR6 / FR27 (AC5, D6): the aggregated signature does not verify over the
    /// support content against the signers' keys in rank order.
    EvidenceAggregate,
    /// FR71 I-43 rules 1–3 (Story 6.13 AC3): the branch's block at the proof's
    /// sequence is not by its creator on its parent, the proof is that block,
    /// or the proof's signature does not verify.
    TwinFactProof,
    /// FR71 I-43 rule 4: the proof's sequence is below the window tail, or a
    /// fact block for the same creator and sequence is already in the window.
    TwinFactWindow,
    /// FR71 I-43 rule 5 (DEC-277): a round-opening block above `s + H − 1`, or
    /// a penalty-only one at or below it.
    TwinFactKind,
    /// FR71 I-43 rule 6 (DEC-277, DEC-278): the carried subgroup is not the
    /// twin round's.
    TwinFactSubgroup,
    /// FR72 I-43 rule 7 (DEC-279): the snapshot is not the equivocator's vote
    /// after the block's interest step.
    TwinFactSnapshot,
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
    /// DEC-177 (Story 6.14 AC8): the lowest sequence from which a balance
    /// entry seeds a node's accumulated vote — `a + H` on a window-anchored
    /// candidate with earliest block `a`, 0 when complete. Before it, the
    /// FR37 liveness credit of a block depends on a creator below the segment.
    vote_seed_from: u32,
    /// The first node id registered inside the segment, `u32::MAX` while
    /// none: ids are contiguous, so every node from it on was registered here
    /// and its vote (0 at registration) is exact.
    first_segment_registration: u32,
    /// Story 6.7 D4: rules 1–4 of an open deviation run are trusted below
    /// this sequence while the run state is unknown. A window-anchored pass
    /// sets `a + H` (its anchor `a` may sit inside a run begun below it, and a
    /// run is at most `H` long); a deviation-form or evidence block settles
    /// the state and clears it. 0 otherwise.
    run_unknown_below: u32,
    /// Story 6.7: the sequence of the active-set counter's window tail — the
    /// physical tail in Ready, a chain switch's virtual one on the walk — the
    /// bottom of the `A`-at-`p − 1` correction (AC5); `u32::MAX` where the
    /// counter is not kept (the FR3 pass, genesis).
    counter_tail: u32,
    /// Story 6.7 D5: the earliest block `a` of a window-anchored FR3 pass, for
    /// the evidence's window condition `p − W ≥ a`; 0 otherwise.
    anchor: u32,
}

impl Projection {
    /// A Ready projection is always complete (D3, FR50 coverage).
    const COMPLETE: Self = Self {
        complete: true,
        roster_bounded: true,
        saw_balance_block: true,
        vote_seed_from: 0,
        first_segment_registration: u32::MAX,
        run_unknown_below: 0,
        counter_tail: u32::MAX,
        anchor: 0,
    };
}

/// What a tail advance needs from the block that becomes the new `S_tail`,
/// read once, before any mutation: its FR21 value (Story 6.1 D1) and its
/// creator, the active set's next decrement (Story 6.4 D2).
#[derive(Clone, Copy)]
struct TailStep {
    value: u64,
    creator: u32,
}

/// The verdict on a prospective extension of the active head (Story 6.0 D2).
enum Extension {
    /// The window gate and the fallible half of the step passed. `advance`
    /// is `Some` when promoting it moves the tail, carrying the new `S_tail`
    /// block's [`TailStep`].
    Valid {
        advance: Option<TailStep>,
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
    /// Applied: promote it. `value` is its FR21 value and `creator` its
    /// creator; `advance` moves the tail, carrying the new `S_tail` block's
    /// [`TailStep`].
    Applied {
        advance: Option<TailStep>,
        value: u64,
        creator: u32,
    },
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
    /// Not attempted: outside FR58's bound, an ancestor below the tail, or a
    /// dropped or referenced block not retained (DEC-159, DEC-204). Nothing
    /// changed.
    NotAdmitted,
    /// A local failure: the original chain stands, nothing was deleted.
    Kept,
    /// Exact evidence: the original chain stands and the offending block was
    /// deleted with its descendants.
    Deleted,
    /// A second fault while restoring: the walk stopped where the restore
    /// was, a chain shorter than the window and horizon every ready-state
    /// rule assumes, so the caller re-enters collecting (DEC-205); the
    /// offender, if any, was deleted.
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

/// [`Blockchain`]'s `active_open_run` when the applied head is not inside an
/// open deviation run (Story 6.7 D4). No block has sequence `u32::MAX` (FR53).
const NO_OPEN_RUN: u32 = u32::MAX;

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

/// The result of [`Blockchain::vote_projection`] (Story 6.7 AC8): the engine
/// was read and restored, nothing was read (restored, byte-identical), or the
/// restore failed (the caller escalates it at its root, DEC-205).
enum Projected {
    Done,
    Refused,
    RestoreFailed,
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
    // `W`, never over the capacity (`snake_chain.rs`). Below it lie the FR58
    // verification horizon's `H` blocks, still linked and flagged, down to the
    // active chain's root (`parent_ref == NONE_REF`), which is found by a walk
    // (Story 6.14 D1, DEC-206). The capacity is a `u32` const generic, stated
    // to the configuration module as a `u32` in `BUILD_LIMITS`.
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
    // FR12 active set `A` (Story 6.4 D2, DEC-213): per node, its blocks in the
    // active window, with the tail's creator kept for the next decrement.
    // Maintained at the ready-state window events from reads they already do;
    // built at every ready entry; invalid otherwise. `2·MAX_NODES` B + 4 B.
    active_set: ActiveSetCounter<MAX_NODES>,
    // FR12 non-conflict record and support floor `F` (Story 6.4 D8, DEC-219):
    // 208 B + 4 B. Initialized only here and never cleared, not even by a
    // re-entry to collecting; non-durable, so a restart starts empty.
    non_conflict: NonConflictRing,
    // FR26 relay-dedupe cache (Story 6.5 D2, D3; DEC-230, DEC-231): a FIFO of
    // 128 × 12 B + a 1 B cursor. Initialized only here and never cleared, not
    // even by a re-entry to collecting; non-durable, so a restart starts empty.
    support_dedupe: SupportDedupe,
    // FR27 proposer-side accumulator (Story 6.6 D2, DEC-236): the subgroup's
    // supports for the local node's own deviation, one at a time. Non-durable;
    // cleared by a re-entry to collecting and the FR5 recovery.
    approval: ApprovalAccumulator,
    // FR27 open deviation run at the applied head (Story 6.7 D4, DEC-261): the
    // sequence `p` of the deviation block whose run is open there, or
    // `NO_OPEN_RUN`. 4 B. Kept at event time from the bytes of each block the
    // per-block step commits and each committed block undone, so the Ready
    // direct extension, the stored child, the FR23 walk and the FR3 pass read
    // the run state below the block they judge without a storage read. Its
    // inverse is exact by the run rules: no deviation starts inside a run (so
    // undoing `d` leaves `NO_OPEN_RUN`), and an evidence block names its `p`.
    // Reset by a re-entry to collecting, the FR5 recovery and a new pass.
    active_open_run: u32,
    // Story 6.7 AC5 / AC8: a vote projection inside the per-block step could
    // not restore the engine (6.3's `RestoreFailed`, DEC-205). The step gives
    // no verdict; the root re-enters collecting at the end of its call, never
    // from inside the step or a switch. 1 B.
    reentry_due: bool,
    // No completeness horizon (Story 6.14 D6, DEC-211, withdrawing DEC-167):
    // a balance entry is a snapshot of its node at its position, so the undo
    // of a seed is identity on the values, and every state below it follows
    // from the exact inverses. A chain switch may walk back across the FR3
    // pass's seed points; FR58's bound keeps it above `a + H`.
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
    /// The `(creator, first_voted_node)` of a retained block's header; `None`
    /// on a failed read.
    fn header_at(&self, idx: u32) -> Option<(u32, u32)> {
        self.header_votes_at(idx)
            .map(|(creator, first_voted, _)| (creator, first_voted))
    }

    /// The `(creator, first_voted_node, consumed_votes)` of a retained block's
    /// header; `None` on a failed read. Its own read buffer (DEC-136). The one
    /// header reader (Story 6.7 AC4 needs `consumed_votes` for the override
    /// form; it absorbed 6.6's `deviation_votes`).
    #[inline(never)]
    fn header_votes_at(&self, idx: u32) -> Option<(u32, u32, u32)> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        self.view_retained(idx, &mut buf).map(|view| {
            (
                view.creator(),
                view.first_voted_node(),
                view.consumed_votes(),
            )
        })
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
            // No window, so no active set (Story 6.4 D2).
            self.active_set.invalidate();
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
}

#[cfg(test)]
mod tests;
