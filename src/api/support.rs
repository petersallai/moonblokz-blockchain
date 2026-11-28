//! FR12 support emission and FR26 support intake (Stories 6.4, 6.5).

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
    const MEMPOOL_COMPACT_BYTES: usize,
    const MEMPOOL_MAX_ENTRIES: usize,
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
        MEMPOOL_COMPACT_BYTES,
        MEMPOOL_MAX_ENTRIES,
    >
{
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
        // A round-opening fact block (a failed read defers to its arm, whose
        // membership read then defers too); a penalty-only one is an ordinary
        // deviation (code review P1).
        let twin = on_chain.is_some_and(|idx| self.is_twin_round(idx));
        if let Some(e_idx) = on_chain.filter(|_| twin) {
            // Story 6.13 AC5: a twin round's support — membership in the
            // block's carried subgroup; the deviation's (iii) and (iv-c) do not
            // apply.
            if !self.on_chain_twin_support_holds(e_idx, p, supporter, proposer) {
                return None;
            }
        } else if let Some(d_idx) = on_chain {
            // The accumulator's rank lookup replaces (iv-b) only while it is
            // live: a dead one is cleared at the hook and the support is a
            // plain relay, which (iv-b) still classifies.
            let own = self.is_own_tuple(p, &hash, proposer) && self.approval_live_ram().is_some();
            if !self.on_chain_support_holds(d_idx, p, supporter, proposer, own) {
                return None;
            }
        } else if let Some(x_idx) = self
            .blocks
            .find(p, &hash)
            .filter(|&idx| self.is_twin_round(idx))
        {
            // A held twin round off the active chain (a retry beside the
            // first opener): its carried subgroup decides. The (iv-c) stop
            // does not apply — the top's own opener at `p` is the round it
            // retries, not a reason to stop (code review P3).
            if self.twin_member(x_idx, supporter, proposer) == Some(false) {
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
    pub(super) fn registered_key(&self, node: u32) -> Option<&[u8; PUBLIC_KEY_SIZE]> {
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
    pub(super) fn approval_live(&self) -> bool {
        self.approval_live_ram()
            .is_some_and(|d_idx| self.approval_live_reads(d_idx))
    }

    /// AC6's RAM half: an accumulator is open, `d` is held (its index is the
    /// result), its parent is the active block at `p − 1` inside the window,
    /// `p > F` and `p + H > S_head`, complete or not (Story 6.7 D1, DEC-258:
    /// the run bound withdrew DEC-240's lift, so a package is never carried
    /// past `p + H`, and DEC-239's complete-package floor exemption with it).
    pub(super) fn approval_live_ram(&self) -> Option<u32> {
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
    pub(super) fn approval_live_reads_with(&self, d_idx: u32, u: Option<u32>) -> bool {
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
    pub(super) fn evidence_deviation(&self, idx: u32) -> Option<Option<u32>> {
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
    pub(super) fn evaluate_support(
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
        // Story 6.13 AC5: a round-opening fact block's round has its own
        // arm. A penalty-only one in deviation form is an ordinary deviation
        // (code review P1); a failed read supports nothing.
        if self.blocks.get(x_idx)?.payload_type() == PAYLOAD_TYPE_TWIN_FACT
            && self.opens_round_at(x_idx).ok()?
        {
            return self.evaluate_twin_support(x_idx, x_creator, x_first_voted);
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
    pub(super) fn extension_preserves(&self, x_idx: u32, dropped: u32) -> bool {
        match self.tail_obligation(dropped, true) {
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
    pub(super) fn active_above(&self, d_idx: u32, above: u32, creator: Option<u32>) -> AboveP {
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
    pub(super) fn creator_block_at(
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
    pub(super) fn in_subgroup_at(
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
    pub(super) fn parent_set_correction(
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

    /// AC7 — signs the support content with the local node's multi-signature
    /// key, in its own frame: the backend's signature value and the signer's
    /// working set never overlap a read buffer.
    #[inline(never)]
    pub(super) fn sign_support(
        &self,
        bytes: &[u8; SUPPORT_MESSAGE_SIZE],
    ) -> [u8; MULTI_SIGNATURE_SIZE] {
        *self.crypto.multi_sign(bytes).serialize()
    }
}
