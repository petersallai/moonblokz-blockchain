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
    PAYLOAD_TYPE_BALANCE, PAYLOAD_TYPE_CHAIN_CONFIG, PAYLOAD_TYPE_TRANSACTION, REGISTRATION_SIZE,
    Registration, TransactionView,
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
mod genesis;
mod outcomes;
mod restart;

pub use outcomes::{
    BalanceQueryError, BlockQueryError, CallResult, GenesisBlocks, GenesisRejectReason,
    InitOutcome, LocalTransactionOutcome, NextCall, ParentRecoveryRequest, ReceiveBlockOutcome,
    ReceiveSupportOutcome, ReceiveTransactionOutcome, RejectReason, RestartRejectReason,
    TickOutcome, TransactionState, TxStateQueryError,
};

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

/// An upper bound on a balance block's entries (the payload also carries
/// its header): the owner list a committed-block undo copies before its
/// seed-source scan (Story 6.3 AC2).
const MAX_BALANCE_ENTRIES: usize = MAX_PAYLOAD_SIZE / NODE_INFO_SIZE;

/// [`Blockchain`]'s `active_open_run` when the applied head is not inside an
/// open deviation run (Story 6.7 D4). No block has sequence `u32::MAX` (FR53).
const NO_OPEN_RUN: u32 = u32::MAX;

/// FR36(b): the transaction-fee total the per-block step credited to the
/// block's creator, recomputed from the payload for the committed-block undo
/// (Story 6.3 AC2) — the sums of `apply_transaction` / `apply_complex`, whose
/// checks made them exact — and the block's UTXO-output count, its own
/// available-UTXO bits (the AC2 precondition of the undo).
fn fees_and_utxo_outputs(view: &BlockView<'_>) -> (u64, usize) {
    let Some(txs) = view.transactions() else {
        return (0, 0);
    };
    let mut outputs = 0usize;
    let is_genesis_zero = view.sequence() == 0;
    let mut total = 0u64;
    for tx in txs.iter() {
        if let Some(nt) = tx.as_node_transfer() {
            total = total.wrapping_add(nt.fee() as u64);
        } else if let Some(reg) = tx.as_registration() {
            if !is_genesis_zero {
                total = total.wrapping_add(reg.fee());
            }
        } else if let Some(cx) = tx.as_complex() {
            outputs += cx
                .outputs()
                .filter(|output| output.as_utxo().is_some())
                .count();
            if cx.input_count() == 0 {
                continue;
            }
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
    (total, outputs)
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

/// Story 6.7 D4: the open deviation run after `block` is applied on top of a
/// head whose run state is `run` (a deviation's `p`, or [`NO_OPEN_RUN`]). A
/// deviation-form block (`creator ≠ first_voted_node`) opens a run at its own
/// sequence; an evidence block (`payload_type == 4`) closes it; any other block
/// leaves it as it was (the run rules have already refused every block that
/// may not extend an open run).
fn run_after(run: u32, block: &BlockView<'_>) -> u32 {
    if block.creator() != block.first_voted_node() {
        block.sequence()
    } else if block.payload_type() == PAYLOAD_TYPE_APPROVAL {
        NO_OPEN_RUN
    } else {
        run
    }
}

/// The exact inverse of [`run_after`] for the committed `block` being undone:
/// no deviation starts inside an open run, so undoing one leaves no run; an
/// evidence block names the run it closed, which undoing it reopens.
fn run_before(run: u32, block: &BlockView<'_>) -> u32 {
    if block.creator() != block.first_voted_node() {
        NO_OPEN_RUN
    } else if block.payload_type() == PAYLOAD_TYPE_APPROVAL {
        ApprovalView::from_payload(block.payload())
            .map_or(NO_OPEN_RUN, |evidence| evidence.deviation_sequence())
    } else {
        run
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

/// DEC-216's value at `p − 1`, shared by the builder (6.6) and the evidence
/// check (6.7 AC8): `B_k = r_eff · Σ (grown(av(n)) + vote_scale)` over the
/// proposer and every registered node (`0..=last_node`, the same range on
/// every node at the same chain position) ranked above it, minus `cv(d)`,
/// with checked arithmetic; and `k`, the number of nodes ranked above the
/// proposer (`u` included). `Ok(None)` on an overflow or `k = 0` (the chain's
/// data: evidence); `Err` on an engine refusal (local). The caller checks that
/// `u` heads the order.
fn deviation_sum<const MAX_NODES: usize>(
    engine: &VoteEngine<MAX_NODES>,
    last_node: u32,
    proposer: u32,
    vote_scale: u64,
    r_eff: u64,
    cv_d: u32,
) -> Result<Option<(u64, u32)>, ()> {
    let mut sum = Some(0u64);
    let mut k = 0u32;
    for n in 0..=last_node {
        let above = engine.ranks_above(n, proposer);
        if n != proposer && !above {
            continue;
        }
        let grown = engine
            .grown(engine.accumulated_vote_of(n))
            .map_err(|_| ())?;
        sum = sum.and_then(|sum| sum.checked_add(u64::from(grown) + vote_scale));
        k += u32::from(above);
    }
    Ok(sum
        .filter(|_| k != 0)
        .and_then(|sum| sum.checked_mul(r_eff))
        .and_then(|sum| sum.checked_sub(u64::from(cv_d)))
        .map(|value| (value, k)))
}

/// DEC-195's late-list room, shared by the builder (6.6) and the evidence
/// check (6.7 AC8): the late entries that fit in `room` payload bytes beside
/// the fixed part of an evidence with subgroup `m` and `n` signers, at most
/// `u16::MAX`. `None` when the fixed part does not fit.
fn late_room(room: usize, m: usize, n: usize) -> Option<usize> {
    room.checked_sub(moonblokz_chain_types::approval_fixed_size(m, n))
        .map(|free| (free / APPROVAL_LATE_ENTRY_SIZE).min(u16::MAX as usize))
}

/// DEC-184's late node: ranked above the proposer at `p − 1`, other than `u`.
fn is_late<const MAX_NODES: usize>(
    engine: &VoteEngine<MAX_NODES>,
    n: u32,
    proposer: u32,
    u: u32,
) -> bool {
    n != u && engine.ranks_above(n, proposer)
}

/// Story 6.7 AC4 rules 1–5 for `block` on a parent whose open run is `run`
/// (`(p, creator of d)`, or `None`) under the verification horizon `h` (the
/// locked configuration's; `None` without one, when rules 4 and 5 cannot be
/// judged and are skipped).
fn run_rules(
    block: &BlockView<'_>,
    run: Option<(u32, u32)>,
    h: Option<u32>,
) -> Result<(), ValidationReason> {
    let is_evidence = block.payload_type() == PAYLOAD_TYPE_APPROVAL;
    match run {
        None if is_evidence => return Err(ValidationReason::EvidencePlacement),
        None => {}
        Some((p, creator_d)) => {
            if block.creator() != creator_d {
                return Err(ValidationReason::RunCreator);
            }
            if block.first_voted_node() != block.creator() || block.consumed_votes() != 0 {
                return Err(ValidationReason::RunHeader);
            }
            if is_evidence
                && ApprovalView::from_payload(block.payload())
                    .is_none_or(|evidence| evidence.deviation_sequence() != p)
            {
                return Err(ValidationReason::EvidencePlacement);
            }
            if let Some(h) = h {
                // Replays end by `p + H − 1`, the evidence by `p + H` (D1).
                let last = u64::from(p) + u64::from(h) - u64::from(!is_evidence);
                if u64::from(block.sequence()) > last {
                    return Err(ValidationReason::RunBound);
                }
            }
        }
    }
    slot_rule(block, h)
}

/// Story 6.7 AC4 rule 5 (D8, DEC-265): a block at `s ≡ H − 1 (mod H)` is
/// clean — an approval evidence block, or a transaction block with no
/// registration and no UTXO output (a balance output leaves no obligation) —
/// so its drop off the tail never carries an obligation. Configuration §6
/// check 21 makes the block a slot drops a slot itself and keeps genesis #0 /
/// #1 off the slots; it also guarantees `H ≥ 3`, so the `h > 1` filter only
/// keeps a `% 0` out of an unlocked caller's path.
fn slot_rule(block: &BlockView<'_>, h: Option<u32>) -> Result<(), ValidationReason> {
    let Some(h) = h.filter(|&h| h > 1) else {
        return Ok(());
    };
    if block.sequence() % h != h - 1 {
        return Ok(());
    }
    let clean = match block.payload_type() {
        PAYLOAD_TYPE_APPROVAL => true,
        PAYLOAD_TYPE_TRANSACTION => block.transactions().is_some_and(|txs| {
            txs.iter().all(|tx| {
                tx.as_registration().is_none()
                    && tx
                        .as_complex()
                        .is_none_or(|cx| cx.outputs().all(|output| output.as_utxo().is_none()))
            })
        }),
        _ => false,
    };
    if clean {
        Ok(())
    } else {
        Err(ValidationReason::SlotNotClean)
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
        let signature_verified = self.lifecycle_phase == LifecyclePhase::Ready
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
            };

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

    /// FR26 (Story 6.5) — classifies a received support message and gates its
    /// radio relay: [`ReceiveSupportOutcome::Accepted`] means relay it,
    /// [`ReceiveSupportOutcome::Rejected`] drop it. It runs in every lifecycle
    /// state (FR1's gating list is not extended), from the message bytes and
    /// the module state alone, never the transport origin: the relay sender is
    /// not part of the [`SupportView`] (DEC-229). The bridge reports `Accepted`
    /// as the radio layer's `NewSupportAdded`, and drops `Rejected` and a
    /// `SupportView::from_bytes` `None` alike.
    ///
    /// The checks, cheapest first (AC2): (v) the relay-dedupe cache, a hit is
    /// `Rejected`; then, when the deviation is **on the active chain** (ready,
    /// held there, `S_tail ≤ p ≤ S_head` by sequence; D4), the supporter id at
    /// most `max_known_node_id`, (iv-a) no approval block above it (RAM),
    /// (iii) the proposer is the deviation's creator and the deviation is in
    /// deviation form, (iv-c) no validated block of the originally-top node `u`
    /// beside it,
    /// and (iv-b) the supporter in the ADR-015 subgroup at `p − 1` within `p +
    /// H > S_head`; off the active chain, in ready state, only (iv-c); and
    /// last (ii), the signature, whenever the supporter's key is derivable.
    /// Any check that cannot be evaluated is deferred, never rejected — also
    /// on a local read failure (DEC-232, DEC-233). Supports whose deviation is
    /// not on the active chain and whose key is not derivable are relayed
    /// unverified (AR-023).
    ///
    /// **The proposer's exception** (Story 6.6 D3, DEC-237): for the tuple of
    /// the local node's open accumulator, `(p, hash(d), local_node_id)`, (iv-b)
    /// is not run; FR27's authoritative subgroup check, the rank lookup in the
    /// accumulator, replaces it, after every other check has passed. A
    /// non-member is `Rejected`, and so is a bad signature where (ii) was
    /// deferred and is now checked against the supporter's registered key (the
    /// key at `p − 1`: keys never change); a verified support is not verified
    /// again. The first support of each rank is stored until `r_eff` are held;
    /// a valid support for a held rank, or past `r_eff`, stays `Accepted`, not
    /// stored. The accumulator's liveness is checked first after the FR26
    /// checks (RAM; before a deferred verification also its reads): a dead
    /// accumulator is cleared, and the support is classified as a plain relay,
    /// (iv-b) included.
    ///
    /// The state it changes is the dedupe cache (an `Accepted` message is
    /// cached as relayed) and the accumulator. A node that refused its restart
    /// rejects everything, as `receive_block` does.
    pub fn receive_support(
        &mut self,
        support: SupportView<'_>,
        _now: u64,
    ) -> CallResult<ReceiveSupportOutcome> {
        if self.restart_refused {
            return (ReceiveSupportOutcome::Rejected, NextCall::Idle);
        }
        let (sequence, key, supporter) = (
            support.deviation_sequence(),
            self.support_dedupe.key(support.tail()),
            support.supporter(),
        );
        let outcome = if !self.support_dedupe.contains(sequence, key, supporter)
            && let Some(verified) = self.support_is_acceptable(&support)
            && self.accumulate_support(&support, verified)
        {
            self.support_dedupe.insert(sequence, key, supporter);
            ReceiveSupportOutcome::Accepted
        } else {
            ReceiveSupportOutcome::Rejected
        };
        (outcome, self.next_parent_recovery_call())
    }

    /// FR26 checks (ii)–(iv) for a support not in the dedupe cache: `None`
    /// when one fails, else whether (ii) verified the signature (`false`:
    /// deferred). See [`Self::receive_support`].
    fn support_is_acceptable(&self, support: &SupportView<'_>) -> Option<bool> {
        let (p, supporter, proposer, hash) = (
            support.deviation_sequence(),
            support.supporter(),
            support.proposer(),
            support.hash(),
        );
        // On the active chain (D4): held there, inside the window by sequence
        // (horizon blocks keep the flag).
        let on_chain = self.blocks.find(p, &hash).filter(|&idx| {
            self.blocks
                .get(idx)
                .is_some_and(BlockEntry::is_on_active_chain)
                && self
                    .active_snake_chain_window()
                    .is_ok_and(|(tail, head)| tail <= p && p <= head)
        });
        if let Some(d_idx) = on_chain {
            // The accumulator's rank lookup replaces (iv-b) only while it is
            // live: a dead one is cleared at the hook and the support is a
            // plain relay, which (iv-b) still classifies.
            let own = self.is_own_tuple(p, &hash, proposer) && self.approval_live_ram().is_some();
            if !self.on_chain_support_holds(d_idx, p, supporter, proposer, own) {
                return None;
            }
        } else if self.is_ready() && self.off_chain_u_block_stops(p, &hash) {
            return None;
        }
        match self.support_signature_holds(support, on_chain.is_some()) {
            Some(false) => None,
            verdict => Some(verdict.is_some()),
        }
    }

    /// Whether `(p, hash, proposer)` is the tuple of the local node's open
    /// accumulator (Story 6.6 D3).
    fn is_own_tuple(&self, p: u32, hash: &[u8; HASH_SIZE], proposer: u32) -> bool {
        proposer == self.local_node_id && self.approval.deviation() == Some((p, hash))
    }

    /// Story 6.6 AC5 (D3) — the accumulation step for a support every FR26
    /// check passed (`verified`: whether (ii) checked its signature). Another
    /// tuple is untouched (`true`). For the proposer's own tuple, `false`
    /// (`Rejected`) for a non-member or a bad signature. See
    /// [`Self::receive_support`].
    fn accumulate_support(&mut self, support: &SupportView<'_>, verified: bool) -> bool {
        if !self.is_own_tuple(
            support.deviation_sequence(),
            &support.hash(),
            support.proposer(),
        ) {
            return true;
        }
        let Some(d_idx) = self.approval_live_ram() else {
            self.approval.clear();
            return true;
        };
        let Some(j) = self.approval.rank_of(support.supporter()) else {
            return false;
        };
        if self.approval.is_complete() || self.approval.holds_rank(j) {
            return true;
        }
        if !verified {
            if !self.approval_live_reads(d_idx) {
                self.approval.clear();
                return true;
            }
            // A member is in `A` at `p − 1`, so it created a block and is
            // registered; a missing key is the node's own inconsistency: not
            // stored, never evidence.
            let Some(key) = self.registered_key(support.supporter()) else {
                return true;
            };
            if !self.support_verifies(support, key) {
                return false;
            }
        }
        self.approval.store(j, support.signature());
        true
    }

    /// The registered key of `node` (node 0's is a construction input).
    fn registered_key(&self, node: u32) -> Option<&[u8; PUBLIC_KEY_SIZE]> {
        if node == 0 {
            Some(&self.node_zero_public_key)
        } else {
            self.node_info.public_key_of(node)
        }
    }

    /// Story 6.6 AC6 (D5, DEC-239) — whether the open accumulator is live: the
    /// single pure predicate for its discard and its release; it never mutates.
    /// The RAM half ([`Self::approval_live_ram`]) and then the reads
    /// ([`Self::approval_live_reads`]). Only `&mut` sites clear on `false`.
    fn approval_live(&self) -> bool {
        self.approval_live_ram()
            .is_some_and(|d_idx| self.approval_live_reads(d_idx))
    }

    /// AC6's RAM half: an accumulator is open, `d` is held (its index is the
    /// result), its parent is the active block at `p − 1` inside the window,
    /// `p > F` and `p + H > S_head`, complete or not (Story 6.7 D1, DEC-258:
    /// the run bound withdrew DEC-240's lift, so a package is never carried
    /// past `p + H`, and DEC-239's complete-package floor exemption with it).
    fn approval_live_ram(&self) -> Option<u32> {
        let (p, hash) = self.approval.deviation()?;
        let d_idx = self.blocks.find(p, hash)?;
        let parent = self.blocks.get(d_idx)?.parent_ref();
        if !self.approval_parent_holds(p, parent) || p <= self.non_conflict.floor() {
            return None;
        }
        let s_head = self.blocks.get(self.active_chain_head_idx)?.sequence();
        if p.checked_add(self.verification_horizon()?)? <= s_head {
            return None;
        }
        Some(d_idx)
    }

    /// AC6's read half for the deviation at `d_idx`: no validated evidence
    /// block for any deviation at `p`, and no validated block of `u =
    /// first_voted(d)` at `p` on `p − 1` (DEC-200, DEC-183). Only validated
    /// blocks stop (D5: a planted unverified block must not silence a
    /// deviation), and a failed read never discards (local I/O is not
    /// evidence). The proposer's own evidence, once admitted, makes it false:
    /// the FR27 release.
    fn approval_live_reads(&self, d_idx: u32) -> bool {
        self.approval_live_reads_with(d_idx, self.header_at(d_idx).map(|(_, u)| u))
    }

    /// [`Self::approval_live_reads`] with `u = first_voted(d)` already read
    /// (`None`: the read failed, so only the evidence half is evaluable).
    fn approval_live_reads_with(&self, d_idx: u32, u: Option<u32>) -> bool {
        let Some(entry) = self.blocks.get(d_idx) else {
            return false;
        };
        let (p, parent) = (entry.sequence(), entry.parent_ref());
        !self.holds_own_evidence(d_idx, p)
            && self.holds_evidence_at(p) != Some(true)
            && u.is_none_or(|u| {
                self.creator_block_at(parent, p, u, [d_idx, d_idx], true) != Some(true)
            })
    }

    /// Story 6.7 AC10 (D3) — whether a held evidence block descends from the
    /// local deviation at `d_idx` (sequence `p`) and was created by the local
    /// node: a RAM scan, then one header read per candidate. The AC4 rules
    /// admit above `d` only its creator's blocks, and the first evidence
    /// closes the run, so such a block is the proposer's own evidence (also as
    /// a side block, while a heavier approval-less sibling is the head): the
    /// release. The creator check keeps out a block stored unjudged (a walk
    /// fault at intake); an unreadable header does not release.
    fn holds_own_evidence(&self, d_idx: u32, p: u32) -> bool {
        (0..MAX_BLOCKS as u32).any(|idx| {
            self.blocks.get(idx).is_some_and(|entry| {
                entry.payload_type() == PAYLOAD_TYPE_APPROVAL
                    && entry.sequence() > p
                    && self.ancestor_at(idx, p).ok().flatten() == Some(d_idx)
                    && self
                        .header_at(idx)
                        .is_some_and(|(creator, _)| creator == self.local_node_id)
            })
        })
    }

    /// Story 6.6 AC6, Story 6.7 D3 — whether a validated evidence block
    /// (`payload_type` 4, on the active chain) names a deviation at `p`:
    /// a RAM scan of the block table, then one read per candidate. `None` when
    /// none does but a read failed: the discard counts it as not held, the
    /// emission as held.
    fn holds_evidence_at(&self, p: u32) -> Option<bool> {
        let mut failed = false;
        for idx in 0..MAX_BLOCKS as u32 {
            let Some(entry) = self.blocks.get(idx) else {
                continue;
            };
            // The evidence extends the deviation's branch, so it lies above `p`;
            // only an active evidence block counts (Story 6.7 D3, DEC-260): it
            // passed Tier 3 (or the pass's trust) and descends from the active
            // `p − 1`.
            if entry.payload_type() != PAYLOAD_TYPE_APPROVAL
                || entry.sequence() <= p
                || !entry.is_on_active_chain()
            {
                continue;
            }
            match self.evidence_deviation(idx) {
                Some(Some(sequence)) if sequence == p => return Some(true),
                Some(_) => {}
                None => failed = true,
            }
        }
        (!failed).then_some(false)
    }

    /// The deviation sequence the evidence block at `idx` names; `Some(None)`
    /// when its read header is not type 4 or its payload does not frame;
    /// `None` on a failed read. Its own read buffer.
    #[inline(never)]
    fn evidence_deviation(&self, idx: u32) -> Option<Option<u32>> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf)?;
        Some(
            (view.payload_type() == PAYLOAD_TYPE_APPROVAL)
                .then(|| ApprovalView::from_payload(view.payload()))
                .flatten()
                .map(|approval| approval.deviation_sequence()),
        )
    }

    /// FR26 for a deviation `d` (at `d_idx`, sequence `p`) on the active chain:
    /// the supporter watermark, (iv-a), (iii), (iv-c) and (iv-b), cheapest
    /// first (D4, D5). For the proposer's `own` tuple (iv-b) is not run: the
    /// accumulator's rank lookup answers it (Story 6.6 D3).
    fn on_chain_support_holds(
        &self,
        d_idx: u32,
        p: u32,
        supporter: u32,
        proposer: u32,
        own: bool,
    ) -> bool {
        // Ids are contiguous: a supporter in `A` at `p − 1` is at most the
        // head's watermark. Not `public_key_of`: a pre-seed node has no key.
        if supporter > self.node_info.max_known_node_id() {
            return false;
        }
        let Some(s_head) = self
            .blocks
            .get(self.active_chain_head_idx)
            .map(BlockEntry::sequence)
        else {
            return true;
        };
        let above = s_head - p + 1;
        // (iv-a), RAM only and so first: an approval block above `d` is its
        // evidence (FR27).
        if self.active_above(d_idx, above, None) == AboveP::Evidence {
            return false;
        }
        // (iii): the signed proposer is `d`'s creator, and `d` deviates. A
        // failed read defers (iii) and (iv-b).
        let header = self.header_at(d_idx);
        if let Some((creator_d, first_voted_d)) = header
            && (proposer != creator_d || creator_d == first_voted_d)
        {
            return false;
        }
        let (Some((creator_d, u)), Some(parent)) =
            (header, self.blocks.get(d_idx).map(BlockEntry::parent_ref))
        else {
            return true;
        };
        // (iv-c): a validated block of `u` beside `d`.
        if self.creator_block_at(parent, p, u, [d_idx, d_idx], true) == Some(true) {
            return false;
        }
        // (iv-b): within `p + H > S_head` (the `p − 1` correction's dropped
        // blocks are still in the horizon), only `d`'s creator above it, a
        // valid counter and a configuration; deferred otherwise.
        if own {
            return true;
        }
        let (Some(w), Some(h), Some(configuration)) = (
            self.active_chain_length(),
            self.verification_horizon(),
            self.chain_config.active_configuration(),
        ) else {
            return true;
        };
        if !self.active_set.is_valid()
            || s_head - p >= h
            || self.active_above(d_idx, above, Some(creator_d)) != AboveP::Clean
        {
            return true;
        }
        self.in_subgroup_at(
            supporter,
            p,
            parent,
            proposer,
            u,
            creator_d,
            above,
            w,
            configuration.required_support(),
        ) != Some(false)
    }

    /// FR26 (iv-c) for a deviation not on the active chain, in ready state:
    /// whether a validated block of the originally-top node `u` stands at `p`
    /// beside it. `u` comes from (b) the deviation's own header, when it is
    /// held on the active block at `p − 1` (a forged header can only stop its
    /// own creator's supports), else (c) the validated header of the active
    /// block at `p`, when that is an approval-less deviation; otherwise the
    /// check is not evaluable (D5).
    fn off_chain_u_block_stops(&self, p: u32, hash: &[u8; HASH_SIZE]) -> bool {
        let candidate = match self.blocks.find(p, hash) {
            Some(x_idx) => {
                let Some(parent) = self.blocks.get(x_idx).map(BlockEntry::parent_ref) else {
                    return false;
                };
                if !self
                    .blocks
                    .get(parent)
                    .is_some_and(|e| e.is_on_active_chain() && e.sequence() + 1 == p)
                {
                    return false;
                }
                x_idx
            }
            None => {
                let head = self.active_chain_head_idx;
                let (Some(Some(a_idx)), Some(s_head)) = (
                    self.ancestor_at(head, p).ok(),
                    self.blocks.get(head).map(BlockEntry::sequence),
                ) else {
                    return false;
                };
                if self.active_above(a_idx, s_head - p + 1, None) != AboveP::Clean {
                    return false;
                }
                a_idx
            }
        };
        let Some(parent) = self.blocks.get(candidate).map(BlockEntry::parent_ref) else {
            return false;
        };
        match self.header_at(candidate) {
            Some((creator, u)) if creator != u => {
                self.creator_block_at(parent, p, u, [candidate, candidate], true) == Some(true)
            }
            _ => false,
        }
    }

    /// FR26 (ii): the supporter's signature over the 45 B content, when its
    /// key is derivable (D4): node 0's always; in ready state, any registered
    /// key when the deviation is on the active chain, else a key that is
    /// branch-independent at the tail (DEC-157's rule). `Some(verdict)` when
    /// verified, `None` when not derivable: deferred.
    fn support_signature_holds(&self, support: &SupportView<'_>, on_chain: bool) -> Option<bool> {
        let supporter = support.supporter();
        let key = if supporter == 0 {
            Some(&self.node_zero_public_key)
        } else if !self.is_ready() {
            None
        } else if on_chain {
            self.node_info.public_key_of(supporter)
        } else {
            self.blocks
                .get(self.snake_chain_tail_idx)
                .is_some_and(|tail| self.key_is_branch_independent(supporter, tail.sequence()))
                .then(|| self.node_info.public_key_of(supporter))
                .flatten()
        };
        Some(self.support_verifies(support, key?))
    }

    /// FR26 (ii) / FR27 — the support's signature over its 45 B content
    /// against `key`. Its own frame: the backend values never overlap a read
    /// buffer.
    #[inline(never)]
    fn support_verifies(&self, support: &SupportView<'_>, key: &[u8; PUBLIC_KEY_SIZE]) -> bool {
        #[cfg(test)]
        crate::approval::test_seams::count(&crate::approval::test_seams::VERIFICATIONS);
        let bytes = support_message_bytes(
            support.proposer(),
            support.deviation_sequence(),
            &support.hash(),
        );
        match (
            MultiSignature::new(support.signature()),
            PublicKey::new(key),
        ) {
            (Ok(signature), Ok(key)) => {
                self.crypto.verify_multi_signature(&bytes, &signature, &key)
            }
            _ => false,
        }
    }

    /// FR12 / ADR-015 (Story 6.4) — whether the local node endorses the
    /// admitted block `x` at `x_idx` (creator `x_creator`, header
    /// `first_voted_node` `x_first_voted`, from the view in hand), and the
    /// signed support message when it does. Every condition is a runtime check
    /// (AC5), RAM-only ones first; any failure is `None`, with no reason
    /// (minimal response). Issuing support changes no chain state beyond the
    /// non-conflict record and the support floor.
    ///
    /// In order: (1) `p > F`, `F` first raised to `S_head − H` (D8); (2) the
    /// grace seam, false until Story 8.5; (3) no conflicting live support in
    /// the ring; `x` signature-verified (D3) on a flagged parent at `p − 1`;
    /// (4) replay completion at `p` (Story 6.6 D6, DEC-240): the block `x`
    /// itself drops, at `p − W`, is preserved by `x`; (5) the shape (DEC-200):
    /// `d`, the active block at `p`, is `x` or another proposer's
    /// approval-less deviation, every active block above `p` is by `d`'s
    /// creator, and `x` deviates from `u`; (6) the resolution stop (DEC-183):
    /// no validated evidence block for any deviation at `p` (a failed read
    /// counts as held) and no validated block at `p` on `p − 1` by `u` (Story
    /// 6.6 D5, amending DEC-233: an unverified one no longer stops); (7) the
    /// local node is in `A'` and in the subgroup.
    ///
    /// **`u` comes from a validated header** (D3): `x`'s own `first_voted_node`
    /// when `x` is active, else `d`'s. Sound only because `p > F` and `F` is
    /// at least the ready-entry head: blocks up to it were validated with an
    /// incomplete projection, where the vote check does not pin the top;
    /// everything above it, with a complete one, which does. A non-top
    /// creator's block in normal form (`first_voted_node == creator`) passes
    /// that check — grace admission is local and unbuilt (I-10) — and is
    /// classed as no deviation here, the safe direction.
    ///
    /// Story 8.5 calls the same function when a grace expiry admits a held
    /// candidate (DEC-203). It takes `x`'s creator and `first_voted_node` as
    /// arguments, not only `x_idx` as AC3 sketched, so the intake path reads
    /// nothing for them; 8.5 reads them from the held candidate's header.
    fn evaluate_support(
        &mut self,
        x_idx: u32,
        x_creator: u32,
        x_first_voted: u32,
    ) -> Option<SupportMessage> {
        // (1) Live sequence (D8), raised first, whatever follows: `F = max(F,
        // S_head − H)`. `p > F` implies `p + H > S_head`, so the window of
        // `p − 1` is retained, and catches a head the drive or a switch moved
        // past intake's FR58 check in this same call.
        let head = self.active_chain_head_idx;
        let s_head = self.blocks.get(head)?.sequence();
        let h = self.verification_horizon()?;
        self.non_conflict.raise_floor(s_head.saturating_sub(h));
        if !self.is_ready() || !self.active_set.is_valid() {
            return None;
        }
        let w = self.active_chain_length()?;
        let required_support = self.chain_config.active_configuration()?.required_support();
        let x = self.blocks.get(x_idx)?;
        let (p, x_hash, x_parent, x_verified) = (
            x.sequence(),
            *x.hash(),
            x.parent_ref(),
            x.is_signature_verified(),
        );
        if p <= self.non_conflict.floor() {
            return None;
        }
        // (2) Grace eligibility (D3).
        if !self.grace_admits(x_creator) {
            return None;
        }
        // (3) Non-conflict (D8); `x` verified against the key at `p − 1` (D3)
        // on the active block at `p − 1`.
        let key = NonConflictRing::key_of(&x_hash);
        let ring = self
            .non_conflict
            .check(RING_KIND_SUPPORT, x_creator, p, key);
        if ring == RingCheck::Conflict || !x_verified {
            return None;
        }
        let parent = self.blocks.get(x_parent)?;
        if !parent.is_on_active_chain() || parent.sequence() + 1 != p {
            return None;
        }
        // (4) Replay completion at `p` (D6): `x`'s own drop, the block at
        // `p − W` (none while `p < W`), is preserved by `x`. Obligations that
        // come due above `p − 1` do not stop support. An unreadable or
        // released block gives none: local I/O never endorses.
        if let Some(dropped_sequence) = p.checked_sub(w) {
            let dropped = self.ancestor_at(x_parent, dropped_sequence).ok()??;
            if !self.extension_preserves(x_idx, dropped) {
                return None;
            }
        }
        // (5) Shape (DEC-200), deviation and `u`. The first storage reads.
        let d_idx = self.ancestor_at(head, p).ok()??;
        let (creator_d, u) = if d_idx == x_idx {
            (x_creator, x_first_voted)
        } else {
            let (d_creator, d_first_voted) = self.header_at(d_idx)?;
            // Another proposer's (not a twin) deviation, and `x` claims the
            // same top: a normal-form `x` (I-10) or one naming another top is
            // no deviation to endorse, the safe direction as in shape (a).
            if d_creator == x_creator
                || d_creator == d_first_voted
                || x_first_voted != d_first_voted
            {
                return None;
            }
            (d_creator, d_first_voted)
        };
        if x_creator == u {
            return None;
        }
        // Above `p`: only `d`'s creator, no approval evidence (FR27). At most
        // `H − 1` blocks, since `p + H > S_head`.
        let above = s_head - p + 1;
        if self.active_above(d_idx, above, Some(creator_d)) != AboveP::Clean {
            return None;
        }
        // (6) Resolution stop (DEC-183): a validated evidence block for any
        // deviation at `p` (a failed read counts as held, the conservative
        // side), or a validated block of `u` at `p` (D5: an unverified one
        // must not silence the deviation).
        if self.holds_evidence_at(p) != Some(false)
            || self.creator_block_at(x_parent, p, u, [x_idx, d_idx], true) != Some(false)
        {
            return None;
        }
        // (7) `A'` at `p − 1` and the subgroup (D2, ADR-015).
        if self.in_subgroup_at(
            self.local_node_id,
            p,
            x_parent,
            x_creator,
            u,
            creator_d,
            above,
            w,
            required_support,
        ) != Some(true)
        {
            return None;
        }

        // Emission (AC7): record, then sign in its own frame.
        if ring == RingCheck::Free
            && !self
                .non_conflict
                .insert(RING_KIND_SUPPORT, x_creator, p, key)
        {
            return None;
        }
        let bytes = support_message_bytes(x_creator, p, &x_hash);
        let support_signature = self.sign_support(&bytes);
        // Story 6.5 (AC3): cache the node's own support as relayed, so a
        // neighbour's echo of it is not relayed back.
        let local = self.local_node_id;
        let dedupe_key = self.support_dedupe.key(&support_body_tail(
            local,
            x_creator,
            &x_hash,
            &support_signature,
        ));
        if !self.support_dedupe.contains(p, dedupe_key, local) {
            self.support_dedupe.insert(p, dedupe_key, local);
        }
        Some(SupportMessage {
            supporter_node_id: local,
            proposer_node_id: x_creator,
            deviation_sequence: p,
            deviation_block_hash: x_hash,
            support_signature,
        })
    }

    /// FR48 / FR12 (Story 6.6 D6) — whether the block at `x_idx` preserves the
    /// obligation of `dropped`, the block it drops: no obligation (RAM), or
    /// `x` is the matching replay kind (one read, its own buffer). An
    /// unclassifiable or unreadable block: `false`.
    #[inline(never)]
    fn extension_preserves(&self, x_idx: u32, dropped: u32) -> bool {
        match classify_tail_drop(&self.blocks, &self.node_info, dropped) {
            Ok(TailObligation::None) => true,
            Ok(obligation) => {
                let mut buf = [0u8; MAX_BLOCK_SIZE];
                self.view_retained(x_idx, &mut buf)
                    .is_some_and(|x| tail_drop_binding(obligation, &x) == TailBinding::Advance)
            }
            Err(_) => false,
        }
    }

    /// The active blocks above `d_idx`, the active block at `p`, walked down from
    /// the head: `above − 1` of them, with `above = S_head − p + 1`. The approval
    /// check reads the payload-type flags only (RAM) and covers all of them
    /// first; then, given `creator`, one header read each checks that `creator`
    /// made them all (FR27). Shared by FR12 emission (6.4) and FR26 intake (6.5).
    fn active_above(&self, d_idx: u32, above: u32, creator: Option<u32>) -> AboveP {
        let head = self.active_chain_head_idx;
        let mut cur = head;
        for _ in 1..above {
            let Some(entry) = self.blocks.get(cur) else {
                return AboveP::Unreadable;
            };
            if entry.payload_type() == PAYLOAD_TYPE_APPROVAL {
                return AboveP::Evidence;
            }
            cur = entry.parent_ref();
        }
        if cur != d_idx {
            return AboveP::Unreadable;
        }
        let Some(creator) = creator else {
            return AboveP::Clean;
        };
        let mut cur = head;
        for _ in 1..above {
            match self.header_at(cur) {
                None => return AboveP::Unreadable,
                Some((c, _)) if c != creator => return AboveP::Foreign,
                Some(_) => {}
            }
            let Some(entry) = self.blocks.get(cur) else {
                return AboveP::Unreadable;
            };
            cur = entry.parent_ref();
        }
        AboveP::Clean
    }

    /// Whether a retained child of `parent` at `p`, other than the `skip`
    /// entries, was created by `creator` (DEC-183's originally-top block):
    /// `Some(true)` if one was; `None` if none was but a read failed; else
    /// `Some(false)`. With `validated_only`, only a block on the active chain or
    /// signature-verified counts (FR26 (iv-c), FR12 emission and the FR27
    /// accumulator alike: DEC-233 as amended by Story 6.6 D5, a planted
    /// unverified block must not silence a deviation). The `parent_ref` and
    /// flag filters are RAM, so only a candidate costs a read.
    fn creator_block_at(
        &self,
        parent: u32,
        p: u32,
        creator: u32,
        skip: [u32; 2],
        validated_only: bool,
    ) -> Option<bool> {
        // An unlinked block has no resolved parent: every root would match.
        if parent == NONE_REF {
            return None;
        }
        let mut failed = false;
        for idx in 0..MAX_BLOCKS as u32 {
            if skip.contains(&idx) {
                continue;
            }
            let Some(entry) = self.blocks.get(idx) else {
                continue;
            };
            if entry.parent_ref() != parent
                || entry.sequence() != p
                || (validated_only && !entry.is_on_active_chain() && !entry.is_signature_verified())
            {
                continue;
            }
            match self.header_at(idx) {
                Some((c, _)) if c == creator => return Some(true),
                Some(_) => {}
                None => failed = true,
            }
        }
        (!failed).then_some(false)
    }

    /// AC5 check 7 (6.4) and FR26 (iv-b) (6.5): whether `node` is in
    /// `A' = A \ {proposer, u}` at `p − 1` and among its `m` smallest node
    /// values. `None` when a read the correction needs fails (local: 6.4 gives
    /// no support, intake defers); `Some(false)` is the only "not a member",
    /// including a node beyond `max_known_node_id`. `A` at `p − 1` is the
    /// active set corrected on the fly (D2): the `above` active blocks in `[p,
    /// S_head]`, all by `creator_d`, leave it, and the blocks they dropped
    /// (`[p − W, S_head − W]`, in the horizon, one read each) return. Their
    /// creators are noted in a transient `[bool; MAX_NODES]` in this frame
    /// (about 1 KB at the reference build), never in the counter. The
    /// physical window is always `[max(0, S_head − W + 1), S_head]`: no
    /// switch shortens a matured window (DEC-209), and a ready entry rebuilds
    /// it.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn in_subgroup_at(
        &self,
        node: u32,
        p: u32,
        parent: u32,
        proposer: u32,
        u: u32,
        creator_d: u32,
        above: u32,
        w: u32,
        required_support: u8,
    ) -> Option<bool> {
        #[cfg(test)]
        crate::approval::test_seams::count(&crate::approval::test_seams::SUBGROUP_EVALS);
        let last_node = self.node_info.max_known_node_id().min(MAX_NODES as u32 - 1);
        // Before any index by `node`: a wire id can be anything.
        if node > last_node {
            return Some(false);
        }
        let mut returned = [false; MAX_NODES];
        let Some(returning_d) = self.parent_set_correction(
            self.active_chain_head_idx,
            p,
            self.physical_counter_tail(),
            w,
            creator_d,
            &mut returned,
        )?
        else {
            return Some(false);
        };
        let a_prime = APrime {
            proposer,
            u,
            creator_d,
            above,
            returning_d,
            returned: &returned,
        };
        let member = |n: &u32| a_prime.contains(&self.active_set, *n);
        let eligible = (0..=last_node).filter(member).count() as u32;
        Some(
            member(&node)
                && subgroup_size(required_support, eligible).is_some_and(|m| {
                    let seed = subgroup_seed(p, self.circulating_currency_at(parent), proposer);
                    in_subgroup(&seed, node, (0..=last_node).filter(member), m)
                }),
        )
    }

    /// The `A`-at-`p − 1` correction (6.4 D2), shared by every `A'` computation
    /// (6.4 emission, 6.5 intake, 6.6 open, 6.7 evidence): the active blocks
    /// in `[p, tip]`, all by `creator_d`, leave the window again (the caller's
    /// `above`), and the blocks that left the counter's window since `p − 1` —
    /// `[p − W, counter_tail − 1]`, measured from the counter's actual tail
    /// (the physical one in Ready, a chain switch's virtual one on the walk;
    /// Story 6.7 AC8), in the horizon, one read each — return. Their creators
    /// are marked in `returned`; the count of `creator_d`'s returning blocks
    /// is the result. `Some(None)`: a returning creator id beyond this build's
    /// capacity, chain data, so no member; `None`: a failed read, local, not
    /// evaluable.
    fn parent_set_correction(
        &self,
        tip: u32,
        p: u32,
        counter_tail: u32,
        w: u32,
        creator_d: u32,
        returned: &mut [bool; MAX_NODES],
    ) -> Option<Option<u32>> {
        let mut returning_d = 0u32;
        if let Some(last) = counter_tail.checked_sub(1) {
            for sequence in p.saturating_sub(w)..=last {
                let creator = self
                    .ancestor_at(tip, sequence)
                    .ok()
                    .flatten()
                    .and_then(|idx| self.header_at(idx))
                    .map(|(creator, _)| creator);
                match creator {
                    Some(c) if c == creator_d => returning_d += 1,
                    Some(c) if (c as usize) < MAX_NODES => returned[c as usize] = true,
                    Some(_) => return Some(None),
                    None => return None,
                }
            }
        }
        Some(Some(returning_d))
    }

    /// Story 6.6 AC4 (D2) — opens the FR27 accumulator for the local node's
    /// own deviation `d` at `d_idx`: computes its subgroup once, at the event,
    /// and replaces any previous accumulator. `false`, with nothing changed,
    /// unless the node is Ready with a valid active set and a configuration,
    /// `d` is the local node's block in deviation form, its parent is the
    /// active block at `p − 1` inside the window, `p + H > S_head`, `p > F`
    /// (DEC-214's soundness bound: below it the `cv` / `cvf` the evidence
    /// projection rewinds were never verified), the active chain above `p − 1`
    /// is `d` and its creator's blocks or, DEC-200's sibling case, another
    /// proposer's approval-less deviation `y@p` claiming the same `u` and its
    /// creator's blocks, and `A'` is not empty.
    ///
    /// Stories 8.3 / 8.5 call it when the local node creates a deviation
    /// block; nothing does before Epic 8.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn open_approval(&mut self, d_idx: u32) -> bool {
        let mut members = [0u32; MAX_SUBGROUP];
        let Some((p, hash, m)) = self.ranked_subgroup(d_idx, &mut members) else {
            return false;
        };
        self.approval.open(p, &hash, &members[..m])
    }

    /// AC4: the subgroup of the local deviation at `d_idx` in rank order
    /// (ascending `node_value`) into `out`; `(p, hash(d), m)`. One pass over
    /// `A'` keeps the `m` smallest values by bounded insertion into a
    /// transient `[u64; MAX_SUBGROUP]`, beside the correction's `[bool;
    /// MAX_NODES]` (its own frame).
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline(never)]
    fn ranked_subgroup(
        &self,
        d_idx: u32,
        out: &mut [u32; MAX_SUBGROUP],
    ) -> Option<(u32, [u8; HASH_SIZE], usize)> {
        if !self.is_ready() || !self.active_set.is_valid() {
            return None;
        }
        let configuration = self.chain_config.active_configuration()?;
        let (w, h) = (
            configuration.active_chain_length(),
            configuration.verification_horizon(),
        );
        let d = self.blocks.get(d_idx)?;
        let (p, hash, parent) = (d.sequence(), *d.hash(), d.parent_ref());
        if !self.approval_parent_holds(p, parent) {
            return None;
        }
        let s_head = self.blocks.get(self.active_chain_head_idx)?.sequence();
        if p.checked_add(h)? <= s_head || p <= self.non_conflict.floor() {
            return None;
        }
        let (creator_d, u) = self.header_at(d_idx)?;
        if creator_d != self.local_node_id || creator_d == u {
            return None;
        }
        // Who extends `p − 1` on the active chain: nobody (the head is `p −
        // 1`), `d`'s creator from `d` up, or the DEC-200 sibling's creator.
        let above = s_head + 1 - p;
        let creator_above = if above == 0 {
            creator_d
        } else {
            let a_idx = self.ancestor_at(self.active_chain_head_idx, p).ok()??;
            let creator_above = if a_idx == d_idx {
                creator_d
            } else {
                let (c_y, u_y) = self.header_at(a_idx)?;
                if c_y == creator_d || c_y == u_y || u_y != u {
                    return None;
                }
                c_y
            };
            if self.active_above(a_idx, above, Some(creator_above)) != AboveP::Clean {
                return None;
            }
            creator_above
        };
        let mut returned = [false; MAX_NODES];
        let returning = self.parent_set_correction(
            self.active_chain_head_idx,
            p,
            self.physical_counter_tail(),
            w,
            creator_above,
            &mut returned,
        )??;
        let a_prime = APrime {
            proposer: creator_d,
            u,
            creator_d: creator_above,
            above,
            returning_d: returning,
            returned: &returned,
        };
        let m = self.rank_subgroup(
            &a_prime,
            p,
            parent,
            creator_d,
            configuration.required_support(),
            out,
        )?;
        Some((p, hash, m))
    }

    /// The ranked subgroup core (ADR-015), shared by the proposer's open (6.6)
    /// and the evidence check (6.7 AC8): over `A'` (`a_prime`, at `p − 1`),
    /// `m = subgroup_size(required_support, |A'|)` and the `m` smallest node
    /// values under the seed of `(p, the currency after parent, proposer)`, in
    /// rank order (ascending value) into `out`. `None` when `A'` is empty. One
    /// pass by bounded insertion into a transient `[u64; MAX_SUBGROUP]` in its
    /// own frame.
    #[inline(never)]
    fn rank_subgroup(
        &self,
        a_prime: &APrime<'_, MAX_NODES>,
        p: u32,
        parent: u32,
        proposer: u32,
        required_support: u8,
        out: &mut [u32; MAX_SUBGROUP],
    ) -> Option<usize> {
        let last_node = self.node_info.max_known_node_id().min(MAX_NODES as u32 - 1);
        let member = |n: &u32| a_prime.contains(&self.active_set, *n);
        let eligible = (0..=last_node).filter(member).count() as u32;
        let m = subgroup_size(required_support, eligible)? as usize;
        if m > MAX_SUBGROUP {
            return None;
        }
        let seed = subgroup_seed(p, self.circulating_currency_at(parent), proposer);
        let mut values = [u64::MAX; MAX_SUBGROUP];
        let mut len = 0usize;
        for n in (0..=last_node).filter(member) {
            let value = node_value(&seed, n);
            if len == m && value >= values[m - 1] {
                continue;
            }
            let mut at = len.min(m - 1);
            while at > 0 && values[at - 1] > value {
                values[at] = values[at - 1];
                at -= 1;
            }
            values[at] = value;
            len = (len + 1).min(m);
        }
        for (slot, value) in out.iter_mut().zip(&values[..m]) {
            // The low word of a node value is its id (ADR-015).
            *slot = *value as u32;
        }
        Some(m)
    }

    /// The sequence of the physical window tail, the active-set counter's
    /// tail in Ready (0 before a window exists).
    fn physical_counter_tail(&self) -> u32 {
        self.blocks
            .get(self.snake_chain_tail_idx)
            .map_or(0, |entry| entry.sequence())
    }

    /// Whether `parent` is the active block at `p − 1` inside the window: the
    /// flag and the sequence, with the window bound by sequence (the flag also
    /// covers the horizon).
    fn approval_parent_holds(&self, p: u32, parent: u32) -> bool {
        self.blocks
            .get(parent)
            .is_some_and(|e| e.is_on_active_chain() && e.sequence().checked_add(1) == Some(p))
            && self
                .active_snake_chain_window()
                .is_ok_and(|(tail, head)| tail < p && p <= head + 1)
    }

    /// Story 6.6 AC7 (FR27, DEC-216, DEC-184, DEC-194, DEC-195) — builds the
    /// signed approval evidence block for the open accumulator on top of
    /// `tip_idx`, the current tip of the deviation-bearing branch (`d` or the
    /// proposer's last replay above it). `None` unless the accumulator is live
    /// and holds `r_eff` supports, the tip is `d` or above it on `d`'s branch,
    /// and every block from `d` to the tip is the local node's.
    ///
    /// It emits, admits and releases nothing: Epic 8 emits the block, which then
    /// goes through the shared acceptance path, and that admission releases the
    /// accumulator (AC6). Its only lasting effect is the vote projection's
    /// re-entry to collecting when a restore fails (D4).
    ///
    /// **Callable only from a root whose stack allows it**: `on_tick` (Epic 8's
    /// creation pull), never `receive_block`. Its `BlockBuilder`, the
    /// projection's read buffer and the aggregation (about 5 KB Schnorr, 12 KB
    /// `bls-min-sig`, 28 KB `bls-min-pk`) do not fit above `receive_block`
    /// within DEC-137's margin. Consumers: Stories 8.3 / 8.4.
    ///
    /// The aggregation's preconditions (crypto crate): every contribution was
    /// verified against its key (FR26 (ii) or the accumulator's deferred check,
    /// D3) and the signers are distinct (one support per rank, D2).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn build_evidence_block(&mut self, tip_idx: u32, now: u64) -> Option<Block> {
        let d_idx = self.approval_live_ram()?;
        let (_, u, cv_d) = self.header_votes_at(d_idx)?;
        if !self.approval.is_complete() || !self.approval_live_reads_with(d_idx, Some(u)) {
            return None;
        }
        let (p, direct) = {
            let d = self.blocks.get(d_idx)?;
            (d.sequence(), d.is_on_active_chain())
        };
        let tip = self.blocks.get(tip_idx)?;
        let (tip_seq, tip_hash) = (tip.sequence(), *tip.hash());
        if self.ancestor_at(tip_idx, p).ok()? != Some(d_idx) {
            return None;
        }
        // The engine stands at the active head: a direct-case tip is the head.
        if direct && tip_idx != self.active_chain_head_idx {
            return None;
        }
        // Story 6.7 (AC11, D1): the evidence fits the run bound `p + H`. An
        // evidence already held above `d` released the accumulator above
        // (`holds_own_evidence`, AC10).
        if u64::from(tip_seq) + 1 > u64::from(p) + u64::from(self.verification_horizon()?) {
            return None;
        }
        let configuration = self.chain_config.active_configuration()?;
        let vote_scale = u64::from(configuration.vote_scale().get());
        let (m, r_eff, _) = self.approval.counts();
        let (m, r_eff) = (usize::from(m), usize::from(r_eff));

        let room = (self.block_size_limit() as usize)
            .checked_sub(HEADER_SIZE)?
            .min(MAX_PAYLOAD_SIZE);
        #[cfg(test)]
        let room = crate::approval::test_seams::payload_room(room);
        let fixed = moonblokz_chain_types::approval_fixed_size(m, r_eff);
        let late_room = late_room(room, m, r_eff)?;
        let mut builder =
            BlockBuilder::new().header(self.post_deviation_header(tip_seq, tip_hash)?);
        let payload = builder.approval_payload_mut(room).ok()?;

        // DEC-195, little-endian: `supporter_vote_sum u64 ‖ deviation_sequence
        // u32 ‖ m u8 ‖ bitmap ‖ aggregate ‖ late_count u16 ‖ late entries`.
        payload[APPROVAL_DEVIATION_SEQUENCE_OFFSET..APPROVAL_M_OFFSET]
            .copy_from_slice(&p.to_le_bytes());
        payload[APPROVAL_M_OFFSET] = m as u8;
        let bitmap_end = APPROVAL_PREFIX_SIZE + m.div_ceil(8);
        payload[APPROVAL_PREFIX_SIZE..bitmap_end].fill(0);
        for (rank, _) in self.approval.held_in_rank_order() {
            // D7: rank `j` is bit `j % 8` of byte `j / 8`, LSB-first.
            payload[APPROVAL_PREFIX_SIZE + usize::from(rank) / 8] |= 1 << (rank % 8);
        }
        let late_count_at = fixed - APPROVAL_LATE_COUNT_SIZE;
        let aggregate_len = self.aggregate_supports(p, &mut payload[bitmap_end..late_count_at])?;
        if bitmap_end + aggregate_len != late_count_at {
            return None;
        }

        // The projection (D4): the creator order and votes at `p − 1`, then
        // the late values at the tip.
        let late_at = fixed;
        let mut late_count = 0usize;
        let local = self.local_node_id;
        let last_node = self.node_info.max_known_node_id().min(MAX_NODES as u32 - 1);
        let projected = self.vote_projection(d_idx, tip_idx, local, direct, |bc, at_tip| {
            let engine = &bc.vote_engine;
            let slot = |i: usize| late_at + APPROVAL_LATE_ENTRY_SIZE * i;
            let id_at = |payload: &[u8], i: usize| {
                let at = slot(i);
                u32::from_le_bytes([
                    payload[at],
                    payload[at + 1],
                    payload[at + 2],
                    payload[at + 3],
                ])
            };
            if at_tip {
                // DEC-184: each late vote after the evidence block's interest step.
                for i in 0..late_count {
                    let Ok(vote) = engine.grown(engine.accumulated_vote_of(id_at(payload, i)))
                    else {
                        return false;
                    };
                    payload[slot(i) + 4..slot(i) + 8].copy_from_slice(&vote.to_le_bytes());
                }
                return true;
            }
            // At `p − 1`: `u` heads the order; DEC-216's value (shared with
            // the evidence check, Story 6.7 AC8); the late nodes, the ranks
            // above the proposer but `u`, kept in creator order by bounded
            // insertion.
            if engine.top_creator() != Some(u) {
                return false;
            }
            let Ok(Some((supporter_vote_sum, _))) =
                deviation_sum(engine, last_node, local, vote_scale, r_eff as u64, cv_d)
            else {
                return false;
            };
            for n in 0..=last_node {
                if !is_late(engine, n, local, u) {
                    continue;
                }
                if late_count == late_room
                    && (late_room == 0 || !engine.ranks_above(n, id_at(payload, late_room - 1)))
                {
                    continue;
                }
                let mut at = late_count.min(late_room - 1);
                while at > 0 && engine.ranks_above(n, id_at(payload, at - 1)) {
                    payload.copy_within(slot(at - 1)..slot(at - 1) + 4, slot(at));
                    at -= 1;
                }
                payload[slot(at)..slot(at) + 4].copy_from_slice(&n.to_le_bytes());
                late_count = (late_count + 1).min(late_room);
            }
            payload[APPROVAL_SUPPORTER_VOTE_SUM_OFFSET..APPROVAL_DEVIATION_SEQUENCE_OFFSET]
                .copy_from_slice(&supporter_vote_sum.to_le_bytes());
            true
        });
        match projected {
            Projected::Done => {}
            Projected::Refused => return None,
            Projected::RestoreFailed => {
                self.reenter_after_failed_restore(now);
                return None;
            }
        }
        payload[late_count_at..fixed].copy_from_slice(&(late_count as u16).to_le_bytes());
        builder
            .approval_payload_mut(fixed + APPROVAL_LATE_ENTRY_SIZE * late_count)
            .ok()?;
        builder.build_signed(&self.crypto).ok()
    }

    /// AC7 (D1, D2, DEC-194) — aggregates the held supports, in ascending
    /// rank order with their registered keys, over the support content, and
    /// serializes the aggregate into `out`; its length. Its own frame: the
    /// parsed signatures and the crypto call never overlap a read buffer.
    #[inline(never)]
    fn aggregate_supports(&self, p: u32, out: &mut [u8]) -> Option<usize> {
        let (hash, members) = (self.approval.deviation()?.1, self.approval.members());
        let mut parsed: [Option<MultiSignature>; MAX_AGGREGATED_SIGNATURES] =
            core::array::from_fn(|_| None);
        let mut keys = [&self.node_zero_public_key; MAX_AGGREGATED_SIGNATURES];
        let mut n = 0;
        for (rank, signature) in self.approval.held_in_rank_order() {
            parsed[n] = Some(MultiSignature::new(signature).ok()?);
            keys[n] = self.registered_key(*members.get(usize::from(rank))?)?;
            n += 1;
        }
        let first = parsed[0].as_ref()?;
        let signatures: [&MultiSignature; MAX_AGGREGATED_SIGNATURES] =
            core::array::from_fn(|i| parsed[i].as_ref().unwrap_or(first));
        let message = support_message_bytes(self.local_node_id, p, hash);
        self.crypto
            .aggregate_signatures(&signatures[..n], &keys[..n], &message)
            .ok()?
            .serialize(out)
            .ok()
    }

    /// FR27 / I-11 — the header of the block the local node puts on top of its
    /// own deviation branch at `tip_seq` (`tip_hash`): the evidence block now,
    /// Epic 9's replay blocks later. The FR27 overrides (`consumed_votes = 0`,
    /// `first_voted_node = creator = local`, `consumed_votes_from_first_voted_node
    /// = 0`); the rest per FR45. `mined_amount` is FR45's `mining_reward` (ID 5)
    /// at the block's sequence, the code-baked default 0 until Story 7.2 adds
    /// its accessor here. `payload_type` is the payload setter's. `None` at
    /// `u32::MAX`.
    fn post_deviation_header(
        &self,
        tip_seq: u32,
        tip_hash: [u8; HASH_SIZE],
    ) -> Option<BlockHeader> {
        Some(BlockHeader {
            version: SUPPORTED_VERSION,
            sequence: tip_seq.checked_add(1)?,
            creator: self.local_node_id,
            mined_amount: 0,
            payload_type: 0,
            consumed_votes: 0,
            first_voted_node: self.local_node_id,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: tip_hash,
            signature: [0u8; SIGNATURE_SIZE],
        })
    }

    /// Story 6.6 AC7 (D4, DEC-238), generalized by Story 6.7 (AC8, DEC-258) —
    /// the scoped in-place rewind of the live vote engine for the deviation `d`
    /// at `d_idx`, whose run is by `creator`, and its branch tip `tip_idx`:
    /// `step(self, false)` reads the engine at `p − 1`, then `step(self, true)`
    /// at the tip, and the engine is restored before this returns. No copy of
    /// the engine is made, and no caller can leave it rewound. The builder
    /// (6.6), the evidence check (6.7) and Story 8.5 share it.
    ///
    /// `direct`, stated by the caller: the engine stands at the tip and `d ..=
    /// tip` is applied (a Ready head, a chain switch's replayed head, the FR3
    /// pass's current block); otherwise the DEC-200 sibling case — the engine
    /// stands at the active head, and `d ..= tip` is off the active chain.
    ///
    /// 1. A RAM pre-check: every block from the rewind's top (the tip, or the
    ///    active head) down to `p − 1` is held and on the path, and, in the
    ///    sibling case, every block of `d ..= tip` is held and off the chain.
    /// 2. The rewind: `undo_block` from the top down to `p`, one read each; in
    ///    the direct case each must be by `creator`.
    /// 3. `step` at `p − 1`.
    /// 4. To the tip: the direct case re-applies the undone blocks and reads
    ///    the tip; the sibling case applies `d ..= tip` (`creator`'s), runs
    ///    `step`, undoes them again and re-applies the active blocks.
    ///
    /// Any failure before the restore (a read, a refused vote step, `step`
    /// answering `false`) restores what this call did: `Refused`, and the
    /// engine is byte-identical to its state before. A failure while
    /// restoring is 6.3's `RestoreFailed`, returned to the caller, which
    /// escalates it at its root (DEC-205; never from inside the per-block step
    /// or a switch). Expected only on a transient read fault, since the call
    /// writes no storage. Power loss is harmless: the engine is RAM-only.
    fn vote_projection(
        &mut self,
        d_idx: u32,
        tip_idx: u32,
        creator: u32,
        direct: bool,
        mut step: impl FnMut(&Self, bool) -> bool,
    ) -> Projected {
        let top = if direct {
            tip_idx
        } else {
            self.active_chain_head_idx
        };
        let (Some(d), Some(top_entry), Some(tip)) = (
            self.blocks.get(d_idx),
            self.blocks.get(top),
            self.blocks.get(tip_idx),
        ) else {
            return Projected::Refused;
        };
        let (p, parent) = (d.sequence(), d.parent_ref());
        let (s_top, tip_seq) = (top_entry.sequence(), tip.sequence());
        // 1. Pre-check, RAM only (`ancestor_at` walks held entries).
        let Some(parent_seq) = p.checked_sub(1) else {
            return Projected::Refused;
        };
        if self.ancestor_at(top, parent_seq).ok() != Some(Some(parent))
            || self.ancestor_at(tip_idx, p).ok() != Some(Some(d_idx))
            || (!direct
                && (p..=tip_seq).any(|s| {
                    self.ancestor_at(tip_idx, s)
                        .ok()
                        .flatten()
                        .is_none_or(|idx| {
                            self.blocks
                                .get(idx)
                                .is_none_or(BlockEntry::is_on_active_chain)
                        })
                }))
        {
            return Projected::Refused;
        }
        let above = s_top - parent_seq;
        let at = |bc: &Self, from: u32, s: u32| bc.ancestor_at(from, s).ok().flatten();
        // 2. Rewind.
        let mut undone = 0u32;
        while undone < above {
            let Some(idx) = at(self, top, s_top - undone) else {
                break;
            };
            if !self.vote_step(idx, true, direct.then_some(creator), false) {
                break;
            }
            undone += 1;
        }
        // 3. At `p − 1`.
        let mut ok = undone == above && step(self, false);
        // 4. To the tip, and the restore.
        if ok && !direct {
            let mut applied = 0u32;
            while p + applied <= tip_seq {
                let Some(idx) = at(self, tip_idx, p + applied) else {
                    break;
                };
                if !self.vote_step(idx, false, Some(creator), true) {
                    break;
                }
                applied += 1;
            }
            ok = p + applied > tip_seq && step(self, true);
            while applied > 0 {
                let restored = at(self, tip_idx, p + applied - 1)
                    .is_some_and(|idx| self.vote_step(idx, true, None, false));
                if !restored {
                    return Projected::RestoreFailed;
                }
                applied -= 1;
            }
        }
        while undone > 0 {
            let restored = at(self, top, s_top - undone + 1)
                .is_some_and(|idx| self.vote_step(idx, false, None, false));
            if !restored {
                return Projected::RestoreFailed;
            }
            undone -= 1;
        }
        if ok && (!direct || step(self, true)) {
            Projected::Done
        } else {
            Projected::Refused
        }
    }

    /// Story 6.7 AC5 (FR6, FR9 Tier 3, FR12, FR27; DEC-172, DEC-184, DEC-216;
    /// D1, D5, D6) — the Tier-3 check of the approval evidence block `view` at
    /// `idx`, whose parent (the tip) is the block the vote engine stands at:
    /// the per-block step runs before its commit. The AC4 run rules held, so
    /// `d = ancestor_at(tip, p)` is the open run's deviation and every block in
    /// `[p, tip]` is its creator's. Cheap first, the aggregate verification
    /// last:
    ///
    /// 1. `A'` at `p − 1`: the counter corrected from its actual tail (Ready,
    ///    the walk), or built over the window at `p − 1` (the FR3 pass);
    /// 2. `m == subgroup_size(required_support, |A'|)`, `r_eff = ⌊m/2⌋ + 1`,
    ///    at least `r_eff` signers; the bitmap's ranks name `m` distinct
    ///    members, so the signers' keys are distinct (roster uniqueness, FR6) —
    ///    the precondition the crypto library does not check;
    /// 3. the vote projection: `B_k − cv(d)` against `supporter_vote_sum`, the
    ///    late list against the prefix that fits, in creator order, at `p − 1`,
    ///    and its votes against their values at the tip (DEC-184);
    /// 4. the aggregated signature over the support content, keys in rank
    ///    order.
    ///
    /// In a window-anchored FR3 pass the check is exact only when the window at
    /// `p − 1` lies in the segment (`p − W ≥ a`, judged first, before `d` is
    /// resolved) and the roster, every node's vote and every signer's key are
    /// seeded at `p − 1` (D5, DEC-177's predicate; a vote whose latest seed
    /// source lies at or above `p` was not seeded at `p − 1` as far as the pass
    /// can tell); otherwise the content is trusted. A local fault (a failed
    /// read, a refused rewind or engine step, the guard that `u` heads the
    /// order at `p − 1`, which `d`'s accepted header implies) is never
    /// evidence; outside the pass a failed restore also marks the re-entry due
    /// at the root (`reentry_due`; the pass's own local failure resets it).
    #[inline(never)]
    fn judge_evidence(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        projection: &Projection,
    ) -> Result<(), ProcessingError> {
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };
        let Some(evidence) = ApprovalView::from_payload(view.payload()) else {
            return Err(invalid(ValidationReason::MalformedPayload));
        };
        let p = evidence.deviation_sequence();
        let Some(configuration) = self.chain_config.active_configuration() else {
            return Err(ProcessingError::StorageRead);
        };
        let (w, required_support, vote_scale, limit) = (
            configuration.active_chain_length(),
            configuration.required_support(),
            u64::from(configuration.vote_scale().get()),
            configuration.block_size_limit(),
        );
        let last_node = self.node_info.max_known_node_id().min(MAX_NODES as u32 - 1);
        // D5: a window-anchored pass checks only where it can — the window
        // condition first, so a `d` below the anchor is never resolved.
        let in_pass = projection.counter_tail == u32::MAX;
        let trusted_zone = in_pass && !projection.complete;
        if trusted_zone
            && (p
                .checked_sub(w)
                .is_none_or(|bottom| bottom < projection.anchor)
                || !projection.roster_bounded
                || !(0..=last_node).all(|n| self.vote_seeded_below(n, p, projection)))
        {
            return Ok(());
        }
        let tip = self
            .blocks
            .get(idx)
            .map_or(NONE_REF, |entry| entry.parent_ref());
        let Some(d_idx) = self.ancestor_at(tip, p).ok().flatten() else {
            return Err(ProcessingError::StorageRead);
        };
        let Some(d) = self.blocks.get(d_idx) else {
            return Err(ProcessingError::StorageRead);
        };
        let (d_parent, d_hash) = (d.parent_ref(), *d.hash());
        let Some((creator_d, u, cv_d)) = self.header_votes_at(d_idx) else {
            return Err(ProcessingError::StorageRead);
        };

        // 1–2. The subgroup at `p − 1` and the signers in rank order.
        let mut members = [0u32; MAX_SUBGROUP];
        let m = match self.evidence_members(
            tip,
            p,
            d_parent,
            creator_d,
            u,
            projection,
            w,
            required_support,
            &mut members,
        ) {
            Err(()) => return Err(ProcessingError::StorageRead),
            Ok(None) => return Err(invalid(ValidationReason::EvidenceSubgroup)),
            Ok(Some(m)) => m,
        };
        let r_eff = required_signers(m);
        let n = evidence.signer_count() as usize;
        if usize::from(evidence.m()) != m || n < r_eff {
            return Err(invalid(ValidationReason::EvidenceSubgroup));
        }
        let mut signers = [0u32; MAX_AGGREGATED_SIGNATURES];
        let mut count = 0usize;
        for (byte_at, byte) in evidence.bitmap().iter().enumerate() {
            for bit in 0..8 {
                if byte >> bit & 1 == 0 {
                    continue;
                }
                // Tier 1 refused a bit at a rank `≥ m`; `n` is at most
                // `MAX_AGGREGATED_SIGNATURES` (the framing).
                let (Some(member), Some(slot)) =
                    (members[..m].get(byte_at * 8 + bit), signers.get_mut(count))
                else {
                    return Err(invalid(ValidationReason::EvidenceSubgroup));
                };
                *slot = *member;
                count += 1;
            }
        }
        if trusted_zone
            && signers[..count]
                .iter()
                .any(|&s| self.registered_key(s).is_none())
        {
            return Ok(());
        }

        // 3. The vote projection.
        let room = (limit as usize)
            .saturating_sub(HEADER_SIZE)
            .min(MAX_PAYLOAD_SIZE);
        let late_room = late_room(room, m, n).unwrap_or(0);
        let claimed = evidence.supporter_vote_sum();
        let late_count = usize::from(evidence.late_count());
        let mut verdict = None;
        let projected = self.vote_projection(d_idx, tip, creator_d, true, |bc, at_tip| {
            let engine = &bc.vote_engine;
            if at_tip {
                // A verdict at `p − 1` already stands: nothing more to read.
                if verdict.is_some() {
                    return true;
                }
                // DEC-184: each listed vote after the evidence's interest step.
                for i in 0..late_count {
                    let Some((id, vote)) = evidence.late_entry(i) else {
                        return false;
                    };
                    let Ok(grown) = engine.grown(engine.accumulated_vote_of(id)) else {
                        return false;
                    };
                    if grown != vote && verdict.is_none() {
                        verdict = Some(ValidationReason::EvidenceLateList);
                    }
                }
                return true;
            }
            if engine.top_creator() != Some(u) {
                return false;
            }
            let (sum, k) =
                match deviation_sum(engine, last_node, creator_d, vote_scale, r_eff as u64, cv_d) {
                    Ok(Some(value)) => value,
                    Ok(None) => {
                        verdict = Some(ValidationReason::EvidenceVoteSum);
                        return true;
                    }
                    Err(()) => return false,
                };
            if sum != claimed {
                verdict = Some(ValidationReason::EvidenceVoteSum);
                return true;
            }
            // The late list: the prefix of the late nodes in creator order
            // that fits. Every listed id a late node, strictly descending in
            // the order (so distinct), and exactly `L − 1` late nodes above the
            // last one — no scratch list, the same predicates as the builder.
            let expected = (k as usize - 1).min(late_room);
            let mut previous = None;
            let listed_ok = late_count == expected
                && (0..late_count).all(|i| {
                    let Some((id, _)) = evidence.late_entry(i) else {
                        return false;
                    };
                    let ok = id <= last_node
                        && is_late(engine, id, creator_d, u)
                        && previous.is_none_or(|q| engine.ranks_above(q, id));
                    previous = Some(id);
                    ok
                })
                && previous.is_none_or(|last| {
                    (0..=last_node)
                        .filter(|&n| {
                            is_late(engine, n, creator_d, u) && engine.ranks_above(n, last)
                        })
                        .count()
                        == late_count - 1
                });
            if !listed_ok {
                verdict = Some(ValidationReason::EvidenceLateList);
            }
            true
        });
        match projected {
            Projected::Done => {}
            Projected::Refused => return Err(ProcessingError::StorageRead),
            Projected::RestoreFailed => {
                self.reentry_due |= !in_pass;
                return Err(ProcessingError::StorageRead);
            }
        }
        if let Some(reason) = verdict {
            return Err(invalid(reason));
        }

        // 4. The aggregate, in its own frame (D6).
        match self.verify_evidence_aggregate(
            evidence.aggregate(),
            &signers[..count],
            creator_d,
            p,
            &d_hash,
        ) {
            Some(true) => Ok(()),
            Some(false) => Err(invalid(ValidationReason::EvidenceAggregate)),
            None => Err(ProcessingError::StorageRead),
        }
    }

    /// AC5 steps 1–2 — `A'` at `p − 1` and its ranked subgroup into `out`:
    /// `Ok(Some(m))`; `Ok(None)` when `A'` is empty; `Err` on a local fault.
    /// In Ready and on the walk the counter is corrected from its actual tail
    /// (`projection.counter_tail`); the FR3 pass has no counter, so it builds
    /// one over the window at `p − 1` (at most `W` reads, rare) and leaves it
    /// invalid again. Its own frame: the correction's `[bool; MAX_NODES]` and
    /// the ranking's `[u64; MAX_SUBGROUP]`.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn evidence_members(
        &mut self,
        tip: u32,
        p: u32,
        parent: u32,
        creator_d: u32,
        u: u32,
        projection: &Projection,
        w: u32,
        required_support: u8,
        out: &mut [u32; MAX_SUBGROUP],
    ) -> Result<Option<usize>, ()> {
        let mut returned = [false; MAX_NODES];
        let in_pass = projection.counter_tail == u32::MAX;
        let (above, returning_d) = if in_pass {
            self.build_active_set_over(parent, p.saturating_sub(w));
            if !self.active_set.is_valid() {
                return Err(());
            }
            (0, 0)
        } else {
            if !self.active_set.is_valid() {
                return Err(());
            }
            let tip_seq = self.blocks.get(tip).ok_or(())?.sequence();
            match self.parent_set_correction(
                tip,
                p,
                projection.counter_tail,
                w,
                creator_d,
                &mut returned,
            ) {
                Some(Some(returning_d)) => (tip_seq + 1 - p, returning_d),
                _ => return Err(()),
            }
        };
        let a_prime = APrime {
            proposer: creator_d,
            u,
            creator_d,
            above,
            returning_d,
            returned: &returned,
        };
        let m = self.rank_subgroup(&a_prime, p, parent, creator_d, required_support, out);
        if in_pass {
            self.active_set.invalidate();
        }
        Ok(m)
    }

    /// AC5 step 4 (D6) — whether the aggregated signature verifies over the
    /// support content of `(proposer, p, hash(d))` against the `signers`'
    /// registered keys in rank order. `Some(false)` for an aggregate or a key
    /// that does not parse; `None` when a signer has no registered key (local).
    /// Its own frame: the parsed keys and the crypto call never overlap a read
    /// buffer.
    #[inline(never)]
    fn verify_evidence_aggregate(
        &self,
        aggregate: &[u8],
        signers: &[u32],
        proposer: u32,
        p: u32,
        hash: &[u8; HASH_SIZE],
    ) -> Option<bool> {
        let Ok(aggregate) = AggregatedSignature::new(aggregate) else {
            return Some(false);
        };
        let mut keys: [Option<PublicKey>; MAX_AGGREGATED_SIGNATURES] =
            core::array::from_fn(|_| None);
        for (slot, signer) in keys.iter_mut().zip(signers) {
            match PublicKey::new(self.registered_key(*signer)?) {
                Ok(key) => *slot = Some(key),
                Err(_) => return Some(false),
            }
        }
        let first = keys[0].as_ref()?;
        let refs: [&PublicKey; MAX_AGGREGATED_SIGNATURES] =
            core::array::from_fn(|i| keys[i].as_ref().unwrap_or(first));
        let message = support_message_bytes(proposer, p, hash);
        #[cfg(test)]
        crate::approval::test_seams::count(&crate::approval::test_seams::AGGREGATE_VERIFICATIONS);
        Some(
            self.crypto
                .verify_aggregated_signature(&message, &aggregate, &refs[..signers.len()]),
        )
    }

    /// D4's failed restore, 6.3's `RestoreFailed`: re-enter collecting
    /// (DEC-205) and, when the re-entry reaches Ready again, run the restart's
    /// FR22 comparison, as [`Self::compare_and_switch`] does.
    fn reenter_after_failed_restore(&mut self, now: u64) {
        if let Some(driver_best) = self.reenter_collecting(now) {
            self.compare_and_switch([None, driver_best], now);
        }
    }

    /// One vote step of the projection (D4) on the block at `idx`: `undo_block`
    /// or `apply_block`, after an optional creator check. `false` on a failed
    /// read, a foreign creator or a refused step (atomic: nothing changed). Its
    /// own read buffer.
    #[inline(never)]
    fn vote_step(&mut self, idx: u32, undo: bool, creator: Option<u32>, check: bool) -> bool {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let Some(view) = self.view_retained(idx, &mut buf) else {
            return false;
        };
        if creator.is_some_and(|c| c != view.creator()) {
            return false;
        }
        // A block the engine has never applied (the DEC-200 sibling branch):
        // its vote header must match the engine's state (I-09; a Ready
        // projection is complete), or `undo_block`, which restores the creator
        // from that header, would not be its exact inverse.
        if check && self.vote_engine.check_header(&view, true, |_| true) != Ok(true) {
            return false;
        }
        if undo {
            self.vote_engine.undo_block(view).is_ok()
        } else {
            self.vote_engine.apply_block(view).is_ok()
        }
    }

    /// Story 6.6 AC8 (FR29, FR27, FR58; D6, D9) — what the proposer's
    /// deviation-bearing branch, whose tip is at `tip_seq`, does next.
    /// `obligation` is `classify_tail_drop` of the block the branch's next
    /// extension would drop, computed by the caller; `last_emit_ms` is when the
    /// deviation block or the branch's last replay was emitted (the caller's
    /// state: FR46's fifth tracked deadline, Story 8.4). In order:
    ///
    /// 1. no live accumulator: `Hold`;
    /// 2. an unreadable tail: `Hold` (never taken as no obligation);
    /// 3. no obligation due: `Evidence` once `r_eff` supports are held, else
    ///    `Hold` — the evidence is never paced;
    /// 4. a replay due that would leave the evidence no position by `p + H`
    ///    (`p ≤ tip_seq + 1 − H`; the run bound, complete or not, Story 6.7 D1):
    ///    `Hold` (D6), so supports keep arriving and nothing drops;
    /// 5. otherwise the replay, once FR29's `deviation_replay_insertion_delay_ms`
    ///    (read at the active head's post-state, DEC-197) has passed since
    ///    `last_emit_ms`: `Replay`, or `WaitUntil` that instant.
    ///
    /// Precedence is not re-implemented here: an evidence block can only extend
    /// where the drop is clean (Story 9.1's binding), so rule 2 / 3 only read it.
    /// Consumers: Story 8.4 (the deadline and the emission), Stories 9.2–9.5
    /// (the replay content).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn approval_step(
        &self,
        tip_seq: u32,
        obligation: Result<TailObligation, TailUnreadable>,
        last_emit_ms: u64,
        now: u64,
    ) -> ApprovalStep {
        let (Some((p, _)), true) = (self.approval.deviation(), self.approval_live()) else {
            return ApprovalStep::Hold;
        };
        let complete = self.approval.is_complete();
        match obligation {
            Err(TailUnreadable) => return ApprovalStep::Hold,
            Ok(TailObligation::None) if complete => return ApprovalStep::Evidence,
            Ok(TailObligation::None) => return ApprovalStep::Hold,
            Ok(_) => {}
        }
        let (Some(h), Some(configuration)) = (
            self.verification_horizon(),
            self.chain_config.active_configuration(),
        ) else {
            return ApprovalStep::Hold;
        };
        // Story 6.7 D1 (DEC-258): complete or not, a replay may not leave the
        // evidence no position by `p + H` (the run bound).
        if u64::from(p) + u64::from(h) <= u64::from(tip_seq) + 1 {
            return ApprovalStep::Hold;
        }
        let due = last_emit_ms.saturating_add(u64::from(
            configuration.deviation_replay_insertion_delay_ms(),
        ));
        if now >= due {
            ApprovalStep::Replay
        } else {
            ApprovalStep::WaitUntil(due)
        }
    }

    /// Story 6.4 D3 — whether the local grace expansion admits `creator` at
    /// the evaluation point. Story 8.5 implements it over the creator order at
    /// `p − 1` (Algorithm 5, the order its timers walk); until then it is
    /// `false`, so production emits no support and a ready block costs no
    /// storage read for it (AC5). Amends DEC-200's `expansion_rank()` seam.
    fn grace_admits(&self, _creator: u32) -> bool {
        #[cfg(test)]
        {
            crate::approval::test_seams::grace_admits()
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Story 6.4 D1 — `circulating_currency` after the block at `idx`, the
    /// subgroup seed's input (DEC-192): the fixed [`CIRCULATING_CURRENCY_STUB`]
    /// until Story 7.6 replaces this body with the per-position projection.
    /// The seed is grindable until then (AR-013), and the same on every node;
    /// Story 7.6 must land before Story 8.5 enables production emission.
    fn circulating_currency_at(&self, _idx: u32) -> u64 {
        CIRCULATING_CURRENCY_STUB
    }

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

    /// AC7 — signs the support content with the local node's multi-signature
    /// key, in its own frame: the backend's signature value and the signer's
    /// working set never overlap a read buffer.
    #[inline(never)]
    fn sign_support(&self, bytes: &[u8; SUPPORT_MESSAGE_SIZE]) -> [u8; MULTI_SIGNATURE_SIZE] {
        *self.crypto.multi_sign(bytes).serialize()
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

    /// Story 6.7 AC4 (D4) — the open deviation run ending at the held block
    /// `q`, by a walk over its own ancestry: `Ok(Some((p, creator of d)))`,
    /// `Ok(None)` for no open run, `Err` when it cannot be told (a failed read,
    /// or the walk reached the lowest held block inside a possible run). It
    /// stops on the RAM evidence flag (a closed run), at a normal-form block
    /// with `consumed_votes ≠ 0` or by another creator (no run), or at a
    /// deviation-form block (the run's `d`). One header read in the normal
    /// case, at most `H + 1` inside a run (the run bound). Genesis #0 is never
    /// in a run. A side block's Tier 2 check and the intake of a block whose
    /// parent is neither the active head nor Connected / Active in Ready use it
    /// (outside Ready, or a Stored parent in Ready); the active head reads
    /// `active_open_run`.
    fn deviation_run_at(&self, q: u32) -> Result<Option<(u32, u32)>, ()> {
        let steps = self
            .verification_horizon()
            .map_or(MAX_BLOCKS as u32, |h| h + 1);
        let mut cur = q;
        let mut creator = None;
        for _ in 0..steps {
            let entry = self.blocks.get(cur).ok_or(())?;
            if entry.payload_type() == PAYLOAD_TYPE_APPROVAL {
                return Ok(None);
            }
            let (sequence, parent) = (entry.sequence(), entry.parent_ref());
            if sequence == 0 {
                return Ok(None);
            }
            let (c, first_voted, consumed) = self.header_votes_at(cur).ok_or(())?;
            if creator.is_some_and(|run_creator| run_creator != c) {
                return Ok(None);
            }
            if c != first_voted {
                return Ok(Some((sequence, c)));
            }
            if consumed != 0 {
                return Ok(None);
            }
            if parent == NONE_REF {
                return Err(());
            }
            creator = Some(c);
            cur = parent;
        }
        // Longer than any run can be: not inside one.
        Ok(None)
    }

    /// Story 6.7 AC4 in the per-block step: rules 1–5 for `view` at `idx`,
    /// whose parent's run state is `active_open_run`. While a window-anchored
    /// pass does not yet know the run state (below `run_unknown_below`), rules
    /// 1–4 are trusted and a deviation-form or evidence block settles it; the
    /// slot rule always applies. A failed read of the deviation's header is a
    /// local fault, never evidence and never acceptance: the step gives no
    /// verdict (`StorageRead`), so the block is not applied.
    fn check_run_rules(
        &self,
        view: &BlockView<'_>,
        idx: u32,
        projection: &mut Projection,
    ) -> Result<(), ProcessingError> {
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };
        let h = self.verification_horizon();
        if view.sequence() < projection.run_unknown_below {
            if view.creator() != view.first_voted_node()
                || view.payload_type() == PAYLOAD_TYPE_APPROVAL
            {
                projection.run_unknown_below = 0;
            }
            return slot_rule(view, h).map_err(invalid);
        }
        let run = match self.active_open_run {
            NO_OPEN_RUN => None,
            p => {
                let parent = self.blocks.get(idx).map_or(NONE_REF, |e| e.parent_ref());
                let creator_d = self
                    .ancestor_at(parent, p)
                    .ok()
                    .flatten()
                    .and_then(|d| self.header_votes_at(d))
                    .map(|(creator, _, _)| creator);
                // An unreadable deviation header cannot be judged: a local
                // fault, so the block is neither refused nor applied.
                let Some(creator_d) = creator_d else {
                    return Err(ProcessingError::StorageRead);
                };
                Some((p, creator_d))
            }
        };
        run_rules(view, run, h).map_err(invalid)
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
        // (b2) Story 6.7 AC4: the FR27 rules of a deviation-bearing branch and
        //      the FR48 clean slot, against the run state below this block
        //      (`active_open_run`, the parent's): RAM unless a run is open.
        self.check_run_rules(view, idx, projection)?;
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
                // FR6 node cap (DEC-228): no balance block names an id at or
                // above the chain's `max_node_count`.
                if payload.max_node_id() >= self.max_node_count() {
                    return Err(invalid(ValidationReason::NodeCountExceeded));
                }
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
                // non-complete projection does not know yet. DEC-177: a seeded
                // node whose vote is not yet known has its vote seeded by its
                // first entry at or after `a + H`, not compared.
                let mut floor_seeded = false;
                let mut vote_seeded_here = false;
                for info in payload.iter() {
                    let owner = info.owner();
                    // Node ids are contiguous: an entry beyond the watermark
                    // names no node (and would occupy a slot a later
                    // registration needs empty, D1 precondition 2).
                    if owner > payload.max_node_id() {
                        return Err(invalid(ValidationReason::NodeIdOutOfRange));
                    }
                    if self.node_info.is_seeded(owner) {
                        let vote_known = self.vote_seeded(owner, projection);
                        if !vote_known && seq >= projection.vote_seed_from {
                            vote_seeded_here = true;
                        }
                        let matches = self.node_info.balance_of(owner) == info.balance()
                            && (!vote_known
                                || self.vote_engine.accumulated_vote_of(owner)
                                    == info.vote_count())
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
                // The vote half of the floor seeding, and the DEC-177 vote seed.
                // A vote-seeded entry's `vote_count` was just shown equal, so
                // re-seeding it is a no-op.
                if (floor_seeded || vote_seeded_here)
                    && let Ok(v) = BlockView::from_bytes(view.serialized_bytes())
                {
                    self.vote_engine.seed_from_balance_block(v);
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
                // DEC-177: the first registration inside a non-complete segment
                // marks every later node id as registered here.
                if !projection.complete && projection.first_segment_registration == u32::MAX {
                    for tx in txs.iter() {
                        if let Some(reg) = tx.as_registration() {
                            projection.first_segment_registration = reg.new_node_id();
                            break;
                        }
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
                // Approval evidence (payload_type 4): its Tier 3 (Story 6.7
                // AC5) runs after this step at the two Tier-3 drivers
                // (`judge_evidence_step`), off genesis' static path (D6). The
                // shared tail applies its FR37 vote effects.
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
        // DEC-177: a node's vote is judged only once it is vote-seeded — by an
        // earlier block, or by this balance block's own entry at or after
        // `a + H` (its pointer moves only at the commit).
        let seeds_here = |node: u32| {
            seq >= projection.vote_seed_from
                && view
                    .balances()
                    .is_some_and(|payload| payload.iter().any(|info| info.owner() == node))
        };
        let header = self
            .vote_engine
            .check_header(view, projection.complete, |node| {
                self.vote_seeded(node, projection) || seeds_here(node)
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

    /// Story 6.7 AC5 / AC6 (D6) — the evidence's Tier 3, after every cheap
    /// check of the per-block step ([`Self::derive_block`]) and before its
    /// commit, at the two Tier-3 drivers: a head extension (the Ready direct
    /// extension, the stored child, the FR23 replay) and the FR3 pass.
    /// Genesis never reaches it (no static path from `process_genesis` to the
    /// aggregate verification, D6's stack). Skipped once the block's signature
    /// checks are final (bit 6, D2). An evidence block carries no transaction,
    /// so a refusal leaves nothing of the step to invert.
    fn judge_evidence_step(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        projection: &Projection,
    ) -> Result<(), ProcessingError> {
        if view.payload_type() == PAYLOAD_TYPE_APPROVAL && !self.signatures_accepted(idx) {
            self.judge_evidence(view, idx, projection)
        } else {
            Ok(())
        }
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
        // Story 6.7: the block's Tier-3 signature checks are final (D2), and
        // the open deviation run moves with the head (D4).
        self.blocks.mark_signatures_accepted(idx);
        self.active_open_run = run_after(self.active_open_run, view);
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
                if !self.signatures_accepted(idx) && !self.verify_tx_signature(tx.as_bytes(), init)
                {
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
            // FR6 node cap (DEC-228): every registered id is below the chain's
            // `max_node_count`, judged from the transaction and the held
            // configuration alone, so in every projection and on every build.
            if !is_genesis_zero && node_id >= self.max_node_count() {
                return Err(invalid(ValidationReason::NodeCountExceeded));
            }
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
                    if !self.signatures_accepted(idx)
                        && !self.verify_tx_signature(tx.as_bytes(), init)
                    {
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
            // Genesis #0 does not advance the watermark (FR54(h)). The id is
            // below `max_node_count ≤ MAX_NODES` (DEC-228), so it has a slot.
            if !is_genesis_zero {
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
    /// block also needs the inverse of [`Self::commit_block`]'s effects, which
    /// [`Self::undo_committed_block`] adds around this call (Story 6.3):
    /// `VoteEngine::undo_block`, the block's own output bits, the seed-source
    /// restore by backward scan, and the creator credit. Each inverse is computed
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
                if !is_genesis_zero {
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
    /// preimage (the full block bytes with the header signature field
    /// zero-filled — exactly what `BlockBuilder::build_signed` signs; the
    /// signature is the last `SIGNATURE_SIZE` bytes of the `HEADER_SIZE` header). Returns
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
        let sig_off = HEADER_SIZE - SIGNATURE_SIZE;
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
    /// connect forks at or above `S_head − H ≥ S_tail` (DEC-207, DEC-208) — or,
    /// for a block whose parent is a flagged active-chain block, the parent's
    /// sequence (Story 6.4 D3); the chain-switch pre-pass passes the common
    /// ancestor. RAM only.
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

    /// Story 6.7 D2: whether the block at `idx` carries `BlockEntry` bit 6
    /// (its Tier-3 signature checks are final), so the per-block step does not
    /// verify its transaction signatures or its evidence again (a restore, a
    /// later walk).
    fn signatures_accepted(&self, idx: u32) -> bool {
        self.blocks
            .get(idx)
            .is_some_and(|entry| entry.is_signatures_accepted())
    }

    /// Verifies a node-transfer / registration transaction signature (AC3): the
    /// signer (the `signer_node_id`, resolved to its derived key) signs the full
    /// transaction bytes with the trailing signature field zero-filled (the
    /// `*::new_signed` convention — the signature is the last `SIGNATURE_SIZE`
    /// bytes of the fixed-size transaction). Returns `false` on an unresolvable signer key or a
    /// bad signature. Only node-transfer / registration transactions have this
    /// fixed trailing-signature layout; balance/UTXO input signatures (embedded, no
    /// `new_signed` convention) are a deferred seam.
    fn verify_tx_signature(&self, tx_bytes: &[u8], signer_node_id: u32) -> bool {
        #[cfg(test)]
        crate::approval::test_seams::count(
            &crate::approval::test_seams::TX_SIGNATURE_VERIFICATIONS,
        );
        let Some(key) = self.node_info.public_key_of(signer_node_id) else {
            return false;
        };
        let key = *key;
        let len = tx_bytes.len();
        if !(SIGNATURE_SIZE..=REGISTRATION_SIZE).contains(&len) {
            return false;
        }
        let mut preimage = [0u8; REGISTRATION_SIZE];
        preimage[..len].copy_from_slice(tx_bytes);
        for b in preimage[len - SIGNATURE_SIZE..len].iter_mut() {
            *b = 0;
        }
        verify_signature_bytes(
            &self.crypto,
            &preimage[..len],
            &tx_bytes[len - SIGNATURE_SIZE..len],
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
        output_index: u16,
        declared_amount: u64,
        trust_below_anchor: bool,
    ) -> Result<Option<[u8; PUBLIC_KEY_SIZE]>, UtxoSpendError> {
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
        output_index: u16,
    ) -> Result<Option<([u8; PUBLIC_KEY_SIZE], u64)>, UtxoSpendError> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self
            .view_retained(ref_idx, &mut buf)
            .ok_or(UtxoSpendError::StorageRead)?;
        Ok(utxo_output_at(&view, output_index))
    }

    /// FR9 Tier 2 of a side block in Ready (Story 6.1 D6): the UTXO-input
    /// structural completion of every complex transaction, along the block's
    /// own ancestry from `parent_idx`. A reference within `W` (`≥ s − W`) resolves to its
    /// block — in the window or the verification horizon — whose bytes must
    /// hold the output with the declared amount; one below the retained root
    /// is trusted pre-window history, as in the FR3 pass (DEC-129, DEC-131),
    /// which a side block inside FR58's bound never reaches once the horizon
    /// is full (Story 6.14). No available-UTXO bit is read: the bits follow the
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
        // Story 6.7 AC4 (D4): the FR27 run rules and the FR48 clean slot for a
        // block off the active head, from its own ancestry (a header walk);
        // the configuration is locked in Ready. An unreadable ancestry judges
        // only the slot rule, which reads the block alone, and is then a local
        // fault: the block stays Stored and the driver judges it again.
        let h = self.verification_horizon();
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };
        match self.deviation_run_at(parent_idx) {
            Ok(run) => run_rules(view, run, h).map_err(invalid)?,
            Err(()) => {
                slot_rule(view, h).map_err(invalid)?;
                return Err(ProcessingError::StorageRead);
            }
        }
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
            // New length `S_head + 1 − S_tail + 1` exceeds `W`.
            let full = (head_entry.sequence() + 1).saturating_sub(tail_entry.sequence()) >= w;
            // DEC-204: the block the extension drops, if any, is evaluated
            // against its binding. A dropped block that is not retained cannot
            // be evaluated: a local failure, never trust.
            match self.dropped_by_extension(head, tail, w) {
                Ok(Some(dropped)) => {
                    let Ok(obligation) = classify_tail_drop(&self.blocks, &self.node_info, dropped)
                    else {
                        return Extension::Local;
                    };
                    if tail_drop_binding(obligation, view) == TailBinding::Invalid {
                        return Extension::Invalid;
                    }
                }
                Ok(None) => {}
                Err(()) => return Extension::Local,
            }
            if full {
                // FR21 (iii): the block that becomes `S_tail` leaves every
                // sum; its value is read now, before anything is mutated, so
                // a failed read is a local failure (Story 6.1 D1).
                let Some(step) = self.new_tail_step(tail) else {
                    return Extension::Local;
                };
                advance = Some(step);
            }
        }
        // The counter's tail: without it the evidence check has no `A'`.
        let Some(counter_tail) = self.blocks.get(tail).map(|e| e.sequence()) else {
            return Extension::Local;
        };
        let mut projection = Projection {
            counter_tail,
            ..Projection::COMPLETE
        };
        match self
            .derive_block(view, idx, Some(head_hash), &mut projection)
            .and_then(|derivation| {
                self.judge_evidence_step(view, idx, &projection)
                    .map(|()| derivation)
            }) {
            Ok(derivation) => Extension::Valid {
                advance,
                derivation,
            },
            Err(err) if is_evidence(&err) => Extension::Invalid,
            Err(_) => Extension::Local,
        }
    }

    /// DEC-204 — the block an extension of `head` at `S_head + 1` drops: block
    /// `S_head + 1 − W`, wherever the walk stands — the tail when the window is
    /// full, a block below a window a chain-switch backward walk shortened
    /// otherwise (Story 6.14's horizon). `Ok(None)` while `S_head + 1 < W` (the
    /// growth phase drops nothing); `Err` when either end or the dropped block
    /// is not retained, a local failure. RAM only. Shared by the extension's
    /// FR48 gate and the FR12 replay-completion check (Story 6.4 AC5.4).
    fn dropped_by_extension(&self, head: u32, tail: u32, w: u32) -> Result<Option<u32>, ()> {
        let (Some(tail_entry), Some(head_entry)) = (self.blocks.get(tail), self.blocks.get(head))
        else {
            return Err(());
        };
        let sequence = head_entry.sequence() + 1;
        if sequence < w {
            return Ok(None);
        }
        if sequence.saturating_sub(tail_entry.sequence()) >= w {
            return Ok(Some(tail));
        }
        match self.ancestor_at(head, sequence - w) {
            Ok(Some(dropped)) => Ok(Some(dropped)),
            _ => Err(()),
        }
    }

    /// The [`TailStep`] of the block that becomes `S_tail` when the window
    /// advances past `tail`: its active-chain child. `None` on a failed read —
    /// a local failure. The tail is never the head here: that needs `W = 1`,
    /// where FR60 refuses every extension (`s_new ≥ s_head + W`).
    fn new_tail_step(&self, tail: u32) -> Option<TailStep> {
        self.tail_step_at(self.tail_successor(tail)?)
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

    /// Reads a retained block and returns its FR21 value and creator; `None`
    /// on a failed read. The read copy lives only in this frame (DEC-136).
    #[inline(never)]
    fn tail_step_at(&self, idx: u32) -> Option<TailStep> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        self.view_retained(idx, &mut buf).map(|view| TailStep {
            value: block_value::<MAX_NODES>(&view),
            creator: view.creator(),
        })
    }

    /// Promotes a block that passed the whole per-block step to the active
    /// head (AC3/AC4, D7: Stored → Active directly), refreshes its
    /// `chain_heads` entry (AC7), adds its FR21 `value` to the active value
    /// (event (i)) and, when the window gate said so, advances the tail (9.1)
    /// and subtracts the new `S_tail` block's value from every value (event
    /// (iii), Story 6.1 D1). The active set follows both window events
    /// (Story 6.4 D2): `creator` enters, the old tail's creator leaves.
    fn promote_head_extension(
        &mut self,
        idx: u32,
        value: u64,
        creator: u32,
        advance: Option<TailStep>,
    ) {
        self.blocks.set_status(idx, BlockStatus::Active);
        self.blocks.set_on_active_chain(idx, true);
        self.active_chain_head_idx = idx;
        self.chain_heads.refresh_head(&self.blocks, idx);
        self.active_branch_value += value;
        self.active_set.add(creator);
        // FR64 (Epic 11 `LogSink`): emit the head-extension event carrying the
        // promoted block's hash and sequence. Deferred — see deferred-work.md.
        if let Some(step) = advance
            && self.advance_snake_chain_tail()
        {
            self.active_branch_value = self.active_branch_value.saturating_sub(step.value);
            self.chain_heads
                .subtract_branch_value(&self.blocks, step.value);
            self.active_set.advance_tail(step.creator);
        }
        // FR58 reclamation (DEC-208): the active block at `S_head − H − 1` has
        // just left the switch bound, and its forks with it.
        if let (Some(entry), Some(h)) = (self.blocks.get(idx), self.verification_horizon()) {
            self.reclaim_out_of_bound(entry.sequence().saturating_sub(h + 1));
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
            // Story 6.7 AC8: after a failed restore the engine is not the
            // head's; no further step runs before the root re-enters.
            if self.reentry_due {
                return;
            }
            let Some(child) = self.best_stored_child() else {
                return;
            };
            // The child's read copy lives in its own frame, gone before any
            // deletion or tail advance, whose delete-set buffer (2.4 KB) must
            // not share the stack with it (D4, DEC-136).
            match self.apply_stored_child(child, self.snake_chain_tail_idx) {
                ChildStep::Applied {
                    advance,
                    value,
                    creator,
                } => {
                    self.promote_head_extension(child, value, creator, advance);
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

    /// FR22's one comparison and the FR23 switch it may run. A switch whose
    /// restore failed leaves a chain shorter than the window and horizon that
    /// every ready-state rule assumes, so the node re-enters collecting
    /// (DEC-205); a re-entry that reaches `Ready` again runs the restart's one
    /// comparison, and a second restore failure re-enters without a further
    /// one (the next FR22 trigger compares). At most two switches per call.
    fn compare_and_switch(&mut self, candidates: [Option<u32>; 2], now: u64) {
        let mut candidates = candidates;
        for comparisons_left in [true, false] {
            let Some(head) = self.switch_target(candidates) else {
                return;
            };
            // Story 6.7 AC8: an evidence check on the walk whose projection
            // could not restore the engine asks for the same re-entry.
            if !matches!(self.switch_toward(head), SwitchOutcome::RestoreFailed)
                && !self.reentry_due
            {
                return;
            }
            let Some(driver_best) = self.reenter_collecting(now) else {
                return;
            };
            if !comparisons_left {
                return;
            }
            candidates = [None, driver_best];
        }
    }

    /// DEC-205: `Ready → Collecting` over the retained tree, then the
    /// acquisition spine a restart drives (FR59 steps 2–5). Nothing durable
    /// changed — a switch writes no block bytes and defers its releases — so
    /// the tree is the node's durable footprint, and the FR2 stopping
    /// condition applies unchanged: a window-anchored segment qualifies at
    /// `W + H` (DEC-177). The derived state is discarded as the FR5 recovery
    /// discards it, the marking and statuses go back to collecting's (every
    /// block Stored, block #0 the root if retained), and `chain_heads` is
    /// rebuilt from the tree. The FR8 lock is irrevocable and stays. Returns
    /// the side-branch driver's best when the spine reached `Ready`.
    fn reenter_collecting(&mut self, now: u64) -> Option<Option<u32>> {
        // Story 6.6 AC4: the accumulator is Ready-state work.
        self.approval.clear();
        self.active_open_run = NO_OPEN_RUN;
        // Story 6.7 AC8: this re-entry is the one a failed restore asked for.
        self.reentry_due = false;
        self.node_info.reset();
        self.reset_vote_engine();
        for idx in 0..MAX_BLOCKS as u32 {
            self.blocks.clear_available_utxo(idx);
            self.blocks.set_on_active_chain(idx, false);
            self.blocks.set_status(idx, BlockStatus::Stored);
        }
        self.active_chain_head_idx = NONE_REF;
        self.snake_chain_tail_idx = NONE_REF;
        self.active_branch_value = 0;
        for idx in 0..MAX_BLOCKS as u32 {
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
        self.chain_heads.clear();
        self.chain_heads
            .rebuild_from_blocks(&mut self.blocks, now, self.active_chain_head_idx);
        self.seed_missing_parent_hashes();
        self.set_lifecycle_phase(LifecyclePhase::Collecting);
        if self.chain_config.active_configuration().is_some() {
            self.drive_dominant_chain_acquisition();
        }
        // Story 6.1 AC3: side branches are valued after the Ready entry.
        self.is_ready().then(|| self.connect_side_branches())
    }

    /// The FR23 chain switch toward `head` (FR22; Story 6.3, DEC-166..171,
    /// DEC-204): an atomic, in-place walk — back from the active head to the
    /// common ancestor by exact per-block inverses, then forward to `head`
    /// through the shared Tier-3 step — that completes, or restores the
    /// original chain exactly, or, after a second fault while restoring, stops
    /// for [`Self::compare_and_switch`] to re-enter collecting (AC6, DEC-205).
    /// It runs inside this call, so no
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
                // No projection was mutated (the pre-pass only marked the
                // signatures it verified): delete the forgery, and give the
                // entry retargeted onto its parent the value below it.
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
                return self.restore_original(ancestor, old_head, old_value, None);
            }
        }

        // AC4 — the forward replay, with the tail advances against a virtual
        // tail and released only at the commit (D3, DEC-168). Story 7.4:
        // remove each applied block's transactions from the mempool here
        // (FR32 (2)).
        //
        // Story 6.4 D2: the active set follows the virtual window — each
        // replayed block enters it, and each virtual advance removes the block
        // that leaves it, whose creator the previous advance read (the
        // physical tail's is kept). A failure unwinds those removals before the
        // restore ([`Self::abort_switch`]).
        let mut virtual_tail = self.snake_chain_tail_idx;
        let mut virtual_tail_creator = self.active_set.tail_creator();
        let mut advances = 0usize;
        let mut released_value = 0u64;
        while self.active_chain_head_idx != head {
            let Some(next) = self.next_toward(head) else {
                return self.abort_switch(ancestor, old_head, old_value, None, advances);
            };
            match self.apply_stored_child(next, virtual_tail) {
                ChildStep::Applied {
                    advance,
                    value,
                    creator,
                } => {
                    self.promote_replayed(next, value, creator);
                    if let Some(step) = advance {
                        let Some(successor) = self.tail_successor(virtual_tail) else {
                            return self
                                .abort_switch(ancestor, old_head, old_value, None, advances);
                        };
                        virtual_tail = successor;
                        advances += 1;
                        released_value = released_value.saturating_add(step.value);
                        self.active_set.remove(virtual_tail_creator);
                        virtual_tail_creator = step.creator;
                    }
                }
                ChildStep::Invalid => {
                    // `next`'s parent is the current head: its value is the
                    // active value now, before anything is undone.
                    let parent_value = self.active_branch_value;
                    return self.abort_switch(
                        ancestor,
                        old_head,
                        old_value,
                        Some((next, parent_value)),
                        advances,
                    );
                }
                ChildStep::Local => {
                    return self.abort_switch(ancestor, old_head, old_value, None, advances);
                }
            }
        }
        // The walk must land on the value the comparison ranked (FR21): a
        // mismatch means an inconsistent table — a local failure.
        if self.chain_heads.branch_value_of(head) != Some(self.active_branch_value) {
            return self.abort_switch(ancestor, old_head, old_value, None, advances);
        }
        // Every deferred release must succeed, so the commit's summed FR21
        // (iii) subtraction is exact (AC5): the physical tail is the flagged
        // root and the virtual tail lies on the new head's ancestry, the chain
        // `advance_snake_chain_tail` walks. A breach is a local failure,
        // before anything is committed.
        if advances > 0 && !self.releases_will_succeed(head, virtual_tail) {
            return self.abort_switch(ancestor, old_head, old_value, None, advances);
        }
        self.commit_switch(head, old_head, old_value, advances, released_value);
        if advances > 0 {
            self.active_set.set_tail_creator(virtual_tail_creator);
        }
        SwitchOutcome::Switched
    }

    /// A failed replay: unwinds the active set's virtual-advance removals,
    /// then restores the original chain (Story 6.4 D2).
    fn abort_switch(
        &mut self,
        ancestor: u32,
        old_head: u32,
        old_value: u64,
        offender: Option<(u32, u64)>,
        advances: usize,
    ) -> SwitchOutcome {
        self.unwind_virtual_advances(advances);
        self.restore_original(ancestor, old_head, old_value, offender)
    }

    /// Puts back the creators the replay's `advances` virtual advances removed
    /// from the active set: the physical tail's, then its successors' along
    /// the flagged chain, read again — the failure path's only reads for the
    /// active set. A failed read invalidates it (no support until the next
    /// ready entry).
    fn unwind_virtual_advances(&mut self, advances: usize) {
        if advances == 0 || !self.active_set.is_valid() {
            return;
        }
        let mut released = self.snake_chain_tail_idx;
        self.active_set.add(self.active_set.tail_creator());
        for _ in 1..advances {
            let Some((next, creator)) = self
                .tail_successor(released)
                .and_then(|next| Some((next, self.header_at(next)?.0)))
            else {
                self.active_set.invalidate();
                return;
            };
            self.active_set.add(creator);
            released = next;
        }
    }

    /// Whether the commit's deferred advances, from the physical tail up to
    /// `virtual_tail`, will all succeed: the tail is flagged and
    /// `virtual_tail` is a proper ancestor of `head`, so every block the
    /// window advances over has a flagged child on the way to `head`. The
    /// horizon releases they trigger take roots below the tail, which the walk
    /// never touched (`A ≥ S_tail`, DEC-207), so they succeed whenever the
    /// advances do. RAM only.
    fn releases_will_succeed(&self, head: u32, virtual_tail: u32) -> bool {
        let tail = self.snake_chain_tail_idx;
        let tail_is_flagged = self
            .blocks
            .get(tail)
            .is_some_and(|entry| entry.is_on_active_chain());
        tail_is_flagged
            && virtual_tail != head
            && self.blocks.get(virtual_tail).is_some_and(|entry| {
                matches!(self.ancestor_at(head, entry.sequence()), Ok(Some(idx)) if idx == virtual_tail)
            })
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
        let (Some(ancestor), Some(tail), Some(root), Some(top), Some(w), Some(h)) = (
            self.blocks.get(ancestor),
            self.blocks.get(self.snake_chain_tail_idx),
            self.blocks.get(self.horizon_root()),
            self.blocks.get(self.active_chain_head_idx),
            self.active_chain_length(),
            self.verification_horizon(),
        ) else {
            return false;
        };
        crate::reconciliation::switch_admitted(
            ancestor.sequence(),
            tail.sequence(),
            root.sequence(),
            top.sequence(),
            w,
            h,
        )
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
            through = through.saturating_add(block_value::<MAX_NODES>(&view));
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
        let creator = self.undo_committed_block(idx, &owners[..count], &sources[..count])?;
        self.active_set.remove(creator);
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
    /// registers it, walking down to the root (the lowest retained block);
    /// `SEED_SOURCE_RELEASED` when the root misses too. One scan for every
    /// owner; FR50 coverage puts each previous source within `W` of `from`,
    /// and the walk stops once every owner is found. A block that can hold
    /// neither is skipped unread. Its own read buffer (DEC-136). `Err` on a
    /// failed read or a walk that does not reach the root (a corrupt
    /// `parent_ref` cycle): a local failure.
    #[inline(never)]
    fn previous_seed_sources(&self, from: u32, owners: &[u32], out: &mut [u32]) -> Result<(), ()> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let mut remaining = owners.len();
        let mut cur = from;
        let mut ended = false;
        for _ in 0..=MAX_BLOCKS {
            if remaining == 0 || cur == NONE_REF {
                ended = true;
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
        if !ended {
            return Err(());
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
    /// inverse is the identity (O-009, DEC-025). Its own read buffer. Returns
    /// the block's creator, which leaves the active set (Story 6.4 D2).
    #[inline(never)]
    fn undo_committed_block(
        &mut self,
        idx: u32,
        owners: &[u32],
        sources: &[u32],
    ) -> Result<u32, ()> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf).ok_or(())?;
        let value = block_value::<MAX_NODES>(&view);
        let remaining_value = self.active_branch_value.checked_sub(value).ok_or(())?;
        // AC2 precondition, a real check: undone top-down, the block's bits are
        // exactly its own outputs, all set (every later spend of them is undone
        // already).
        let (fees, outputs) = fees_and_utxo_outputs(&view);
        if (0..AVAILABLE_UTXO_BYTES * 8)
            .any(|bit| self.blocks.utxo_available(idx, bit) != Some(bit < outputs))
        {
            return Err(());
        }
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
            self.node_info
                .debit(view.creator(), view.mined_amount() as u64 + fees);
        }
        self.invert_transactions(&view, idx, usize::MAX);
        self.active_branch_value = remaining_value;
        self.active_open_run = run_before(self.active_open_run, &view);
        Ok(view.creator())
    }

    /// Promotes a block the replay (or the restore) just applied: Connected →
    /// Active (FR9), on the active chain, the new head; its FR21 value joins
    /// the active value and its `creator` the active set (Story 6.4 D2). The
    /// tail is left to the commit (D3).
    fn promote_replayed(&mut self, idx: u32, value: u64, creator: u32) {
        self.blocks.set_status(idx, BlockStatus::Active);
        self.blocks.set_on_active_chain(idx, true);
        self.active_chain_head_idx = idx;
        self.active_branch_value += value;
        self.active_set.add(creator);
    }

    /// AC5 — the commit, after which nothing fails: FR19 event (iii) first
    /// (the release step's fragment reclamation reads current caches), the
    /// FR21 (iv) value hand-over before any release (a release may delete the
    /// old head), then the deferred tail advances and their FR21 (iii)
    /// subtraction, and last the FR58 reclamation of every block that left the
    /// switch bound between the old head and the new one — the demoted branch
    /// included once its common ancestor did (DEC-208). No comparison follows
    /// (FR22 (d)). Story 7.4 adds the mempool window expiry (FR32 (3)).
    fn commit_switch(
        &mut self,
        head: u32,
        old_head: u32,
        old_value: u64,
        advances: usize,
        released_value: u64,
    ) {
        let old_head_seq = self.blocks.get(old_head).map(|entry| entry.sequence());
        self.chain_heads.recompute_all_caches(&self.blocks);
        // The active value is never an entry (DEC-144); the old head, if an
        // entry still names it, carries the old active value.
        self.chain_heads.set_branch_value(head, 0);
        self.chain_heads.set_branch_value(old_head, old_value);
        for _ in 0..advances {
            if !self.advance_snake_chain_tail() {
                // Unreachable by construction — the replay advanced the
                // virtual tail along the same flagged chain. FR64: log the
                // invariant breach. Deferred — see deferred-work.md. The
                // active set no longer matches the window (Story 6.4 D2).
                self.active_set.invalidate();
                return;
            }
        }
        self.active_branch_value = self.active_branch_value.saturating_sub(released_value);
        self.chain_heads
            .subtract_branch_value(&self.blocks, released_value);
        // The old head's bound was `S_head_old − H`: everything from there up to
        // the new bound crossed it with this switch.
        if let (Some(seq), Some(h)) = (old_head_seq, self.verification_horizon()) {
            self.reclaim_out_of_bound(seq.saturating_sub(h));
        }
    }

    /// AC6 — restores the original chain after a failed walk: undoes every
    /// block above the original chain's path (never below `ancestor`),
    /// re-applies the original branch up to `old_head` by the same step (its
    /// blocks are marked, so no signature is verified again), and, for exact
    /// evidence at `offender`, deletes it with its descendants. Any error
    /// while restoring stops it where it is (a restore failure), whatever its
    /// kind.
    fn restore_original(
        &mut self,
        ancestor: u32,
        old_head: u32,
        old_value: u64,
        offender: Option<(u32, u64)>,
    ) -> SwitchOutcome {
        while !self.on_path_to(old_head) {
            if self.active_chain_head_idx == ancestor || self.undo_active_head().is_err() {
                return self.stop_restore(offender);
            }
        }
        let tail = self.snake_chain_tail_idx;
        while self.active_chain_head_idx != old_head {
            let Some(next) = self.next_toward(old_head) else {
                return self.stop_restore(offender);
            };
            match self.apply_stored_child(next, tail) {
                ChildStep::Applied {
                    advance,
                    value,
                    creator,
                } => {
                    // Its effects are committed: promote it either way. The
                    // original chain fit the window, so an advance means an
                    // inconsistent window — stop (the caller re-enters collecting,
                    // DEC-205).
                    self.promote_replayed(next, value, creator);
                    if advance.is_some() {
                        return self.stop_restore(offender);
                    }
                }
                _ => return self.stop_restore(offender),
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

    /// AC6 restore failure: the walk stops where the restore reached — on
    /// the original chain, or on a prefix of the new one when an undo failed.
    /// Every step is atomic, so nothing is half-applied, but the chain is
    /// shorter than the window and horizon the ready-state rules assume: the
    /// caller re-enters collecting (DEC-205), which rebuilds every derived
    /// structure from the tree. Nothing of the original chain is deleted; the
    /// offender, if any, is still exact evidence and goes first.
    fn stop_restore(&mut self, offender: Option<(u32, u64)>) -> SwitchOutcome {
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
        // Every FR21 sum adds at most `MAX_BLOCKS` values, each at most
        // `value_cap` (an evidence block's clamp, Story 6.7 D7, DEC-264; any
        // other block's `u32` header value is below it), so plain `u64`
        // additions cannot overflow. It bounds the build: `MAX_BLOCKS ·
        // MAX_NODES` stays below about 8.6 · 10⁷.
        const { assert!((MAX_BLOCKS as u128) * (value_cap::<MAX_NODES>() as u128) <= u64::MAX as u128) };
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
            branch += block_value::<MAX_NODES>(&view);
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
            active += block_value::<MAX_NODES>(&self.view_retained(cur, &mut buf).ok_or(())?);
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
            value: block_value::<MAX_NODES>(&view),
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
                    value: block_value::<MAX_NODES>(&view),
                    creator: view.creator(),
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
    fn promote_candidate_active(&mut self, candidate_tip_idx: u32, window_value: u64) {
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
    /// storage reads) and is then advanced by the ordinary window step until
    /// the window is `W` long, which lands it on `max(anchor_seq, S_head − W +
    /// 1)`. A chain shorter than `W` advances nothing — the bootstrap growth
    /// phase, where a genesis-anchored tail stays at block #0 (Story 9.1 AC2).
    ///
    /// The blocks the tail passes enter the FR58 verification horizon, and only
    /// those beyond `H` below the tail are released (Story 6.14 AC6): a
    /// segment longer than `W + H` (a restart can hold more) enters Ready
    /// holding `W + H` blocks. The released blocks go even when they carry an
    /// FR49/FR50/FR51 obligation (Ratified Decision 4, 2026-10-10): the segment
    /// passed FR3/FR6 as a whole, the state they seed is in the derived
    /// projections, and the FR3 pass has already evaluated the FR48 binding of
    /// every block whose dropped block lay in the segment (DEC-204). Each block
    /// the window passes is still classified, so the record is uniform with a
    /// steady-state advance — the result feeds only the AR16 log (Epic 11), so
    /// neither an obligation nor an unreadable block stops the trim (Project
    /// Lead, 2026-10-13).
    ///
    /// `W` is read now (FR56). A Ready node is durably locked, so it is always
    /// there; were it not, the window is the whole active chain and nothing is
    /// released — never the `SNAKE_CHAIN_LENGTH_MAX` capacity in its place
    /// (Story 5.11 Ratified Decision 2).
    ///
    /// Before the trim every `chain_heads` entry is recomputed against the new
    /// marking (O-024 ruling): without it the adopted chain's own head stays
    /// Stored and keeps requesting the anchor's parent. Then the FR58
    /// reclamation runs over the whole adopted chain (DEC-208): every branch
    /// forked below `S_head − H` and every Stored fragment that can never
    /// connect, including a genesis island the adopted chain does not contain
    /// (DEC-127).
    ///
    /// **Cost.** The tail is found by walking to the root and then advancing,
    /// not by a `W − 1`-step walk, so the trim is literally the steady-state
    /// step. Each block the window passes costs one storage read (transaction
    /// blocks only) and one O(`MAX_BLOCKS`) child scan; each release another
    /// scan. The reclamation costs one `delete_subtree_with_followup` per fork
    /// and per fragment, each O(`MAX_BLOCKS`²) through `mark_subtree`. The
    /// common case — a live join of exactly `W + H` blocks — releases nothing
    /// and deletes nothing.
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
        // here, at once (DEC-127).
        self.chain_heads.recompute_all_caches(&self.blocks);
        // FR58 reclamation over the whole adopted chain (DEC-208), before the
        // trim: the releases below then meet only the active path.
        if let Some(root_seq) = self.blocks.get(root).map(|entry| entry.sequence()) {
            self.reclaim_out_of_bound(root_seq);
        }

        let (Some(root_seq), Some(head_seq)) = (
            self.blocks.get(root).map(|entry| entry.sequence()),
            self.blocks
                .get(self.active_chain_head_idx)
                .map(|entry| entry.sequence()),
        ) else {
            self.active_set.invalidate();
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
        // Story 6.4: the FR12 state of a ready entry — the support floor
        // reaches the head (D8: DEC-198's restart floor, also for the DEC-205
        // re-entry, whose ring survives), and the active set is built over the
        // window just established (D2).
        self.non_conflict.raise_floor(head_seq);
        self.build_active_set();
    }

    /// Story 6.4 D2: builds the active set by one walk over the window, head
    /// to tail (at most `W` reads, one buffer in this frame, DEC-136). A failed
    /// read leaves it invalid: no support until the next ready entry.
    fn build_active_set(&mut self) {
        match self.blocks.get(self.snake_chain_tail_idx) {
            Some(tail) => {
                let bottom = tail.sequence();
                self.build_active_set_over(self.active_chain_head_idx, bottom);
            }
            None => self.active_set.invalidate(),
        }
    }

    /// The active set over the window `[bottom, top]`, walked from `top` down
    /// by `parent_ref` (at most `W` reads, one buffer in this frame, DEC-136):
    /// the ready entry's window, or the FR3 pass's window at an evidence
    /// block's `p − 1` (Story 6.7 AC7). A failed read leaves it invalid.
    #[inline(never)]
    fn build_active_set_over(&mut self, top: u32, bottom: u32) {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        self.active_set.start_build(0);
        let mut cur = top;
        for _ in 0..MAX_BLOCKS {
            let Some(view) = self.view_retained(cur, &mut buf) else {
                break;
            };
            let creator = view.creator();
            self.active_set.add(creator);
            if view.sequence() <= bottom {
                self.active_set.set_tail_creator(creator);
                return;
            }
            match self.blocks.get(cur) {
                Some(entry) if entry.parent_ref() != NONE_REF => cur = entry.parent_ref(),
                _ => break,
            }
        }
        self.active_set.invalidate();
    }

    /// FR58 reclamation (DEC-159, DEC-208): deletes, whole, everything whose
    /// divergence from the active chain lies at `D ≤ S_head − H` and so can
    /// never become active:
    /// - every branch forked at an active block at sequence `from ..= S_head −
    ///   H − 1` — the blocks that left the bound since the previous sweep;
    /// - every Stored fragment whose missing parent lies at `q ≤ S_head − H`
    ///   (DEC-161 as tightened by DEC-208): the retained active block at `q`
    ///   would have linked it at admission, so the missing parent is off the
    ///   active chain and the fragment diverges at or below `q`; and, on a
    ///   young chain where that bound is below #0, one whose missing parent
    ///   is at or below the tail, which can never arrive.
    ///
    /// Runs at every Ready head extension (`from = S_head − H − 1`), at a chain
    /// switch's commit (from the old head's bound) and at Ready entry (from the
    /// root). It needs current `chain_heads` caches — a Stored head's
    /// tail-point is then never an active block — and walks the active chain by
    /// `parent_ref`, with no storage read. Without a configuration (never in
    /// Ready) it does nothing. Cost: one O(`MAX_BLOCKS`) child scan per block
    /// that crossed the bound, one O(`MAX_BRANCH_COUNT`) fragment pass, and one
    /// `delete_subtree_with_followup` per deletion, one at a time.
    fn reclaim_out_of_bound(&mut self, from: u32) {
        let (Some(head), Some(h)) = (
            self.blocks
                .get(self.active_chain_head_idx)
                .map(|entry| entry.sequence()),
            self.verification_horizon(),
        ) else {
            return;
        };
        if let Some(top) = head.checked_sub(h + 1)
            && from <= top
            && let Ok(Some(mut cur)) = self.ancestor_at(self.active_chain_head_idx, top)
        {
            for _ in 0..MAX_BLOCKS {
                let Some(entry) = self.blocks.get(cur) else {
                    break;
                };
                if entry.sequence() < from {
                    break;
                }
                let parent = entry.parent_ref();
                self.delete_forks_at(cur);
                cur = parent;
            }
        }
        // A missing parent at or below the tail can never arrive either: FR60
        // refuses it below the tail, and at the tail itself it would be the
        // tail's sibling — out of the bound once the chain has matured, a
        // second genesis before (the young chain's tail is #0). So a young
        // chain still reclaims what Story 9.1 did.
        let tail = self
            .blocks
            .get(self.snake_chain_tail_idx)
            .map_or(0, |entry| entry.sequence());
        let limit = head
            .saturating_add(1)
            .saturating_sub(h)
            .max(tail.saturating_add(1));
        for slot in 0..MAX_BRANCH_COUNT {
            let Some(tail_point) = self.chain_heads.stored_head_tail(slot) else {
                continue;
            };
            if self
                .blocks
                .get(tail_point)
                .is_some_and(|entry| entry.sequence() <= limit)
            {
                self.delete_subtree_with_followup(tail_point);
            }
        }
    }

    /// Deletes, whole, every branch forked at the active block `block`: each
    /// child that is not on the active path.
    fn delete_forks_at(&mut self, block: u32) {
        for idx in 0..MAX_BLOCKS as u32 {
            if self
                .blocks
                .get(idx)
                .is_some_and(|child| child.parent_ref() == block && !child.is_on_active_chain())
            {
                self.delete_subtree_with_followup(idx);
            }
        }
    }

    /// The lowest retained active-chain block, below the tail by at most `H`:
    /// the root, whose `parent_ref` is `NONE_REF` (D1, DEC-206). Derived by a
    /// RAM walk, so no index names it.
    fn horizon_root(&self) -> u32 {
        let mut root = self.snake_chain_tail_idx;
        for _ in 0..MAX_BLOCKS {
            match self.blocks.get(root) {
                Some(entry) if entry.parent_ref() != NONE_REF => root = entry.parent_ref(),
                _ => break,
            }
        }
        root
    }

    /// FR48 window advance (Story 9.1 AC5; Story 6.14 AC3): moves the tail one
    /// block up the active chain. Returns `false`, changing nothing, when there
    /// is nothing to advance over — no tail, or the tail is the head.
    ///
    /// The block the tail leaves enters the FR58 verification horizon: it
    /// keeps its entry, `parent_ref`, `Active` status, `is_on_active_chain`
    /// flag, available-UTXO bits and every seed-source pointer that names it
    /// (D1, DEC-206). Horizon blocks contribute nothing to the derived state
    /// or the FR21 value — the window is the two indices — but a chain switch
    /// resolves the dropped and referenced blocks below `S_tail` against them
    /// (DEC-204). The block that leaves the horizon is then released
    /// ([`Self::release_beyond_horizon`]).
    ///
    /// The caller decides *whether* to advance: the Ready-entry trim
    /// ([`Self::establish_snake_chain_window`]), Story 6.0's forward
    /// extension, which advances once per head extension past length `W` after
    /// [`crate::snake_chain::tail_drop_binding`] allows it, and a chain
    /// switch's commit. No fork is deleted here: under DEC-207 the dropped
    /// block lies below `S_head − H − 1`, so its forks left FR58's bound
    /// earlier and were reclaimed then ([`Self::reclaim_out_of_bound`],
    /// DEC-208). The FR21 subtraction of event (iii) is the caller's.
    ///
    /// **Cost.** One O(`MAX_BLOCKS`) child scan, plus the release's.
    pub(crate) fn advance_snake_chain_tail(&mut self) -> bool {
        let dropped = self.snake_chain_tail_idx;
        // Runtime, not debug-only: advancing over a block off the active path
        // would move the window onto a branch.
        if dropped == self.active_chain_head_idx
            || !self
                .blocks
                .get(dropped)
                .is_some_and(|entry| entry.is_on_active_chain())
        {
            return false;
        }
        let Some(new_tail) = self.tail_successor(dropped) else {
            return false;
        };
        self.snake_chain_tail_idx = new_tail;
        self.release_beyond_horizon();
        true
    }

    /// The FR58 horizon release (D1, DEC-206): while more than `H` blocks lie
    /// below the tail, the root — the block that leaves the horizon — is
    /// released as Story 9.1 released the dropped tail:
    /// 1. its `is_on_active_chain` is cleared and its slot freed with the lazy
    ///    [`BlockTable::delete`] — the durable bytes stay until the slot is
    ///    reused (Ratified Decision 3);
    /// 2. index hygiene: nodes seeded from it stay seeded but stop naming the
    ///    slot (`SEED_SOURCE_RELEASED`), and a tentative provenance naming it is
    ///    dropped (never in practice: a Ready node is durably locked);
    /// 3. its one flagged child is unlinked (`parent_ref = NONE_REF`) and
    ///    becomes the new root.
    ///
    /// No fork is deleted: nothing but the active path lies at or below
    /// `S_head − H` (DEC-208), so the root's only child is its successor.
    /// Without a configuration `H` counts as 0. Cost: one root walk and one
    /// O(`MAX_BLOCKS`) child scan per release.
    fn release_beyond_horizon(&mut self) {
        let Some(tail_seq) = self
            .blocks
            .get(self.snake_chain_tail_idx)
            .map(|entry| entry.sequence())
        else {
            return;
        };
        let h = self.verification_horizon().unwrap_or(0);
        let mut root = self.horizon_root();
        for _ in 0..MAX_BLOCKS {
            let Some(root_seq) = self.blocks.get(root).map(|entry| entry.sequence()) else {
                return;
            };
            if tail_seq.saturating_sub(root_seq) <= h {
                return;
            }
            let Some(successor) = self.tail_successor(root) else {
                return;
            };
            self.blocks.set_on_active_chain(root, false);
            self.blocks.delete(root);
            self.node_info.release_seed_source(root);
            if self.tentative_config_block_idx == root {
                self.tentative_config_block_idx = NONE_REF;
                self.chain_config.discard_tentative();
            }
            self.blocks.set_parent_ref(successor, NONE_REF);
            root = successor;
        }
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
            .map(|config| config.active_chain_length())
    }

    /// FR58's verification horizon `H` (DEC-160) the held configuration —
    /// tentative or durable — declares, or `None` while the node holds none.
    /// Read where it is needed and never cached (FR56); acceptance holds it
    /// to `1 ≤ H < W` and `W + 2·H ≤ MAX_BLOCKS`.
    pub(crate) fn verification_horizon(&self) -> Option<u32> {
        self.chain_config
            .active_configuration()
            .map(|config| config.verification_horizon())
    }

    /// The chain's node cap `max_node_count` (DEC-228) the held configuration
    /// declares. Never cached (FR56).
    ///
    /// The per-block step runs only with a configuration held (the FR3 pass is
    /// gated on one, Story 5.8; Ready holds the durable one). Should it ever
    /// run without one, the build's own `MAX_NODES` bounds the ids instead, so
    /// the watermark can never name a node with no slot; acceptance keeps every
    /// chain's cap at or below it.
    fn max_node_count(&self) -> u32 {
        self.chain_config
            .active_configuration()
            .map_or(MAX_NODES as u32, |config| config.max_node_count())
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
    /// loaded, and this build's block capacity `MAX_BLOCK_SIZE` until then.
    ///
    /// The fallback is not a policy choice standing in for a chain value — it is
    /// this build's capacity (DEC-225, amending DEC-105): a larger block cannot be
    /// framed here at all, and `BlockView::from_bytes` refuses it before intake,
    /// so the fallback never judges a block as evidence. Two builds with
    /// different capacities never disagree on whether a block is acceptable:
    /// a block above the smaller build's capacity is refused by both — as
    /// evidence on a larger build locked to a chain whose limit it exceeds, as
    /// a local refusal on the smaller one, which cannot frame it. Acceptance
    /// refuses a chain whose limit a build cannot hold (§6 check 5).
    ///
    /// Read this where the configuration in force is known to be the one the work
    /// commits to — the FR54 genesis path, which is about to lock the very
    /// configuration it is measuring against. Anything that can **reject or
    /// delete** a block must read [`Self::enforceable_block_size_limit`] instead.
    fn block_size_limit(&self) -> u32 {
        self.chain_config
            .active_configuration()
            .map_or(MAX_BLOCK_SIZE as u32, |config| config.block_size_limit())
    }

    /// The block-size limit that may be **enforced** against an arriving or
    /// retained block: the chain's value once the configuration is durably
    /// locked, and this build's block capacity before that (DEC-225).
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
    fn enforceable_block_size_limit(&self) -> u32 {
        self.chain_config
            .durable_content()
            .and_then(|_| self.chain_config.active_configuration())
            .map_or(MAX_BLOCK_SIZE as u32, |config| config.block_size_limit())
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
    /// The head extension (Story 6.0) and the chain switch (Story 6.3) keep
    /// `node_info` — the watermark included — at the active head's state;
    /// Story 7.2 completes the per-block update set (FR35).
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
mod tests;
