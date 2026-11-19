//! `on_tick`, the transaction entry points and the read-only queries (FR14,
//! FR19, FR40-FR44, FR55).

use super::*;

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
    pub(super) fn next_parent_recovery_call(&self) -> NextCall {
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
    pub(super) fn active_snake_chain_window(&self) -> Result<(u32, u32), SnakeChainWindowError> {
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
    /// private `blocks` field); `api`'s own tests read `self.blocks.len()`.
    #[cfg(test)]
    pub(crate) fn block_tree_len(&self) -> usize {
        self.blocks.len()
    }
}
