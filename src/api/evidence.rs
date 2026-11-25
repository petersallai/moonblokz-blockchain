//! FR27 run rules and the Tier-3 check of incoming approval evidence (Story 6.7).

use super::*;

/// Whether `block` opens a run (Story 6.7 D4; Story 6.13 T2, DEC-276): a
/// deviation-form block (`creator ≠ first_voted_node`), or a round-opening twin
/// fact block (`payload_type == 5` naming a subgroup, `m ≥ 1`). Tier 3 binds
/// `m ≥ 1` to the position `q ≤ s + H − 1`.
pub(super) fn opens_run(block: &BlockView<'_>) -> bool {
    block.creator() != block.first_voted_node()
        || (block.payload_type() == PAYLOAD_TYPE_TWIN_FACT
            && TwinFactView::from_payload(block.payload()).is_some_and(|proof| proof.m() > 0))
}

/// Story 6.7 D4: the open run after `block` is applied on top of a head whose
/// run state is `run` (the run-opening block's `p`, or [`NO_OPEN_RUN`]). A
/// run-opening block ([`opens_run`]) opens a run at its own sequence; an
/// evidence block (`payload_type == 4`) closes it; any other block leaves it as
/// it was (the run rules have already refused every block that may not extend
/// an open run).
pub(super) fn run_after(run: u32, block: &BlockView<'_>) -> u32 {
    if opens_run(block) {
        block.sequence()
    } else if block.payload_type() == PAYLOAD_TYPE_APPROVAL {
        NO_OPEN_RUN
    } else {
        run
    }
}

/// The exact inverse of [`run_after`] for the committed `block` being undone:
/// no run starts inside an open run, so undoing a run-opening block leaves no
/// run; an evidence block names the run it closed, which undoing it reopens.
pub(super) fn run_before(run: u32, block: &BlockView<'_>) -> u32 {
    if opens_run(block) {
        NO_OPEN_RUN
    } else if block.payload_type() == PAYLOAD_TYPE_APPROVAL {
        ApprovalView::from_payload(block.payload())
            .map_or(NO_OPEN_RUN, |evidence| evidence.deviation_sequence())
    } else {
        run
    }
}

/// DEC-216's value at `p − 1`, shared by the builder (6.6) and the evidence
/// check (6.7 AC8): `B_k = r_eff · Σ (grown(av(n)) + vote_scale)` over the
/// proposer and every registered node (`0..=last_node`, the same range on
/// every node at the same chain position) ranked above it, minus `cv(d)`,
/// with checked arithmetic; and `k`, the number of nodes ranked above the
/// proposer (`u` included). `Ok(None)` on an overflow or, for a deviation,
/// `k = 0` (the chain's data: evidence); `Err` on an engine refusal (local).
/// The caller checks that `u` heads the order. A twin run's opener may be the
/// top itself (`top_allowed`, Story 6.13 AC4): its `k` is 0.
pub(super) fn deviation_sum<const MAX_NODES: usize>(
    engine: &VoteEngine<MAX_NODES>,
    last_node: u32,
    proposer: u32,
    vote_scale: u64,
    r_eff: u64,
    cv_d: u32,
    top_allowed: bool,
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
        .filter(|_| k != 0 || top_allowed)
        .and_then(|sum| sum.checked_mul(r_eff))
        .and_then(|sum| sum.checked_sub(u64::from(cv_d)))
        .map(|value| (value, k)))
}

/// DEC-195's late-list room, shared by the builder (6.6) and the evidence
/// check (6.7 AC8): the late entries that fit in `room` payload bytes beside
/// the fixed part of an evidence with subgroup `m` and `n` signers, at most
/// `u16::MAX`. `None` when the fixed part does not fit.
pub(super) fn late_room(room: usize, m: usize, n: usize) -> Option<usize> {
    room.checked_sub(moonblokz_chain_types::approval_fixed_size(m, n))
        .map(|free| (free / APPROVAL_LATE_ENTRY_SIZE).min(u16::MAX as usize))
}

/// DEC-184's late node: ranked above the proposer at `p − 1`, other than `u`.
pub(super) fn is_late<const MAX_NODES: usize>(
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
pub(super) fn run_rules(
    block: &BlockView<'_>,
    run: Option<(u32, u32)>,
    h: Option<u32>,
) -> Result<(), ValidationReason> {
    let is_evidence = block.payload_type() == PAYLOAD_TYPE_APPROVAL;
    match run {
        None if is_evidence => return Err(ValidationReason::EvidencePlacement),
        None => {}
        Some((p, creator_d)) => {
            // D8 (Story 6.13, DEC-281): a run's positions are its proposer's
            // replays and its evidence; no twin fact block inside another run.
            if block.payload_type() == PAYLOAD_TYPE_TWIN_FACT {
                return Err(ValidationReason::EvidencePlacement);
            }
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
pub(super) fn slot_rule(block: &BlockView<'_>, h: Option<u32>) -> Result<(), ValidationReason> {
    let Some(h) = h.filter(|&h| h > 1) else {
        return Ok(());
    };
    if block.sequence() % h != h - 1 {
        return Ok(());
    }
    let clean = match block.payload_type() {
        // A twin fact block's drop carries no obligation either (FR71, D8).
        PAYLOAD_TYPE_APPROVAL | PAYLOAD_TYPE_TWIN_FACT => true,
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
    pub(super) fn judge_evidence(
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

        // 1–2. The subgroup at `p − 1` and the signers in rank order. A twin
        // run's subgroup is the one its opener carries (Story 6.13 AC4, D11),
        // checked when the opener was applied. A penalty-only fact block
        // (`m = 0`) in deviation form opens an ordinary deviation run, so its
        // evidence takes the deviation's subgroup (code review P1).
        let mut members = [0u32; MAX_SUBGROUP];
        let carried = if d.payload_type() == PAYLOAD_TYPE_TWIN_FACT {
            match self.fact_members(d_idx, &mut members) {
                Some(m) => m,
                None => return Err(ProcessingError::StorageRead),
            }
        } else {
            0
        };
        let twin = carried > 0;
        let m = if twin {
            carried
        } else {
            match self.evidence_members(
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
            }
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
            let (sum, k) = match deviation_sum(
                engine,
                last_node,
                creator_d,
                vote_scale,
                r_eff as u64,
                cv_d,
                twin,
            ) {
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
            let expected = (k as usize).saturating_sub(1).min(late_room);
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
        // Built in place: a `from_fn` temporary was copied in (Story 12.2,
        // DEC-302).
        let mut keys: [Option<PublicKey>; MAX_AGGREGATED_SIGNATURES] =
            [const { None }; MAX_AGGREGATED_SIGNATURES];
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
    pub(super) fn deviation_run_at(&self, q: u32) -> Result<Option<(u32, u32)>, ()> {
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
            if c != first_voted
                || (entry.payload_type() == PAYLOAD_TYPE_TWIN_FACT && self.opens_round_at(cur)?)
            {
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
    pub(super) fn check_run_rules(
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
            if opens_run(view) || view.payload_type() == PAYLOAD_TYPE_APPROVAL {
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

    /// Story 6.7 AC5 / AC6 (D6) — the evidence's Tier 3, after every cheap
    /// check of the per-block step ([`Self::derive_block`]) and before its
    /// commit, at the two Tier-3 drivers: a head extension (the Ready direct
    /// extension, the stored child, the FR23 replay) and the FR3 pass.
    /// Genesis never reaches it (no static path from `process_genesis` to the
    /// aggregate verification, D6's stack). Skipped once the block's signature
    /// checks are final (bit 6, D2). An evidence block carries no transaction,
    /// so a refusal leaves nothing of the step to invert. A twin fact block's
    /// check (Story 6.13 AC3, I-43) runs at the same sites under the same
    /// gate; it carries no transaction either.
    pub(super) fn judge_evidence_step(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        projection: &Projection,
    ) -> Result<(), ProcessingError> {
        if self.signatures_accepted(idx) {
            return Ok(());
        }
        match view.payload_type() {
            PAYLOAD_TYPE_APPROVAL => self.judge_evidence(view, idx, projection),
            PAYLOAD_TYPE_TWIN_FACT => self.judge_twin_fact(view, idx, projection),
            _ => Ok(()),
        }
    }
}
