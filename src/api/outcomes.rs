//! Public outcome and error types of the `Blockchain` API (AR4 single-outcome
//! results), re-exported from `api` so `crate::api::X` paths are unchanged.

use super::*;

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

/// Single-outcome classification returned by [`Blockchain::receive_block`]
/// (FR10; single-outcome scheduling-pull pattern, AR4). Exactly one variant is
/// produced per submitted block, and the response carries no descriptive
/// payload beyond the [`RejectReason`] discriminant (FR10 minimal-response
/// convention). Classification is deterministic in the block bytes + current
/// authoritative state and is independent of transport origin.
///
/// Epic 4 realizes the three terminal variants; Story 6.4 adds
/// [`Self::AcceptedAndSendSupport`], which carries an **owned**
/// [`SupportMessage`] (D4), so the enum still has no lifetime. The remaining
/// `AcceptedAndSend*` addendum variant of architecture §3.2,
/// `AcceptedAndSendBlock(BlockView<'_>)`, is added with its payload type by
/// Epic 8; that borrowing variant introduces the `<'a>` lifetime when it lands.
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
    /// FR12 — the block was admitted as [`Self::AcceptedSilently`] would be, and
    /// it is a deviating block the local node endorses: the bridge sends the
    /// support message to its proposer. Issuing support changes no chain
    /// state.
    AcceptedAndSendSupport(SupportMessage),
}

/// FR26 — the classification of a received support message (Story 6.5,
/// DEC-229). It carries nothing else (FR10 minimal response), and it gates the
/// radio relay.
///
/// The bridge maps it, and a [`SupportView::from_bytes`] `None`, onto the radio
/// layer: `Accepted` is reported as `MessageProcessingResult::NewSupportAdded`,
/// which queues the message for relay; `Rejected` and `None` are dropped, with
/// no relay. The bridge itself is AR12's.
// Same derive discipline as `ReceiveBlockOutcome`.
#[cfg_attr(test, derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum ReceiveSupportOutcome {
    /// Every applicable FR26 check holds: relay the message.
    Accepted,
    /// An applicable check failed, or the message is already known: drop it.
    Rejected,
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
