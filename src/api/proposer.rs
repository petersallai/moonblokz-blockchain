//! Proposer side of approval: the accumulator, the evidence block, the vote
//! projection and the approval step, with the grace seam, the circulating-
//! currency stub and the re-entry after a failed restore (Story 6.6).

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
    pub(super) fn rank_subgroup(
        &self,
        a_prime: &APrime<'_, MAX_NODES>,
        p: u32,
        parent: u32,
        proposer: u32,
        required_support: u8,
        out: &mut [u32; MAX_SUBGROUP],
    ) -> Option<usize> {
        let seed = subgroup_seed(p, self.circulating_currency_at(parent), proposer);
        self.rank_members(
            |n| a_prime.contains(&self.active_set, n),
            &seed,
            required_support,
            out,
        )
    }

    /// The ranked subgroup core under a given `seed` over the voting set
    /// `member` (ADR-015): the deviation's ([`Self::rank_subgroup`]) and the
    /// twin round's (Story 6.13 T4 (c)). `m = subgroup_size(required_support,
    /// |set|)` and the `m` smallest node values in rank order into `out`; `None`
    /// for an empty set.
    pub(super) fn rank_members(
        &self,
        member: impl Fn(u32) -> bool,
        seed: &[u8; HASH_SIZE],
        required_support: u8,
        out: &mut [u32; MAX_SUBGROUP],
    ) -> Option<usize> {
        let last_node = self.node_info.max_known_node_id().min(MAX_NODES as u32 - 1);
        let member = |n: &u32| member(*n);
        let eligible = (0..=last_node).filter(member).count() as u32;
        let m = subgroup_size(required_support, eligible)? as usize;
        if m > MAX_SUBGROUP {
            return None;
        }
        let seed = *seed;
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
    pub(super) fn physical_counter_tail(&self) -> u32 {
        self.blocks
            .get(self.snake_chain_tail_idx)
            .map_or(0, |entry| entry.sequence())
    }

    /// Whether `parent` is the active block at `p − 1` inside the window: the
    /// flag and the sequence, with the window bound by sequence (the flag also
    /// covers the horizon).
    pub(super) fn approval_parent_holds(&self, p: u32, parent: u32) -> bool {
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
            let Ok(Some((supporter_vote_sum, _))) = deviation_sum(
                engine,
                last_node,
                local,
                vote_scale,
                r_eff as u64,
                cv_d,
                false,
            ) else {
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
    pub(super) fn vote_projection(
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

    /// D4's failed restore, 6.3's `RestoreFailed`: re-enter collecting
    /// (DEC-205) and, when the re-entry reaches Ready again, run the restart's
    /// FR22 comparison, as [`Self::compare_and_switch`] does.
    pub(super) fn reenter_after_failed_restore(&mut self, now: u64) {
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
        // FR72: the credit drop at this block (Story 6.13 AC6).
        let drop = fact::credit_drop::<_, MAX_BLOCKS, MAX_NODES>(
            &self.blocks,
            &self.storage,
            self.verification_horizon(),
            idx,
        );
        if !drop.reads_hold(&view) {
            return false;
        }
        let excluded = |node| drop.excluded(node);
        let stepped = if undo {
            self.vote_engine.undo_block(view, excluded).is_ok()
        } else {
            self.vote_engine.apply_block(view, excluded).is_ok()
        };
        if drop.faulted() {
            // The engine's result is not trusted: escalate (DEC-205).
            self.reentry_due |= self.is_ready();
            return false;
        }
        stepped
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
    pub(super) fn grace_admits(&self, _creator: u32) -> bool {
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
    pub(super) fn circulating_currency_at(&self, _idx: u32) -> u64 {
        CIRCULATING_CURRENCY_STUB
    }
}
