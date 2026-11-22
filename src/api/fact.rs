//! The twin fact block (FR70–FR72, Story 6.13): the FR72 credit drop the vote
//! step reads, and the block's Tier-3 check (I-43).

use super::*;
use crate::approval::{RING_KIND_TWIN, twin_seed};
use moonblokz_chain_types::calculate_hash;

/// A twin round as its round-opening fact block names it (Story 6.13 AC5).
struct TwinRound {
    c: u32,
    s: u32,
    key: u32,
    local_member: bool,
}

/// What a check that may reach below a window-anchored pass's segment found.
enum Reach {
    Holds,
    Fails,
    /// The block it needs lies below the held chain (the pass's anchor).
    Below,
    /// A read failed: the node's own fault.
    Local,
}

/// FR72 (Story 6.13 AC6; DEC-279, DEC-280): whether `node` gets no step-2
/// credit in the block whose parent is `parent`, because a twin fact block in
/// the `H` blocks below that block, `[b − H, b − 1]`, names it. A RAM walk over
/// the cached payload type and equivocator: no read, no state. `h` is the
/// chain's verification horizon; without one no fact block can exist.
pub(super) fn credit_excluded<const MAX_BLOCKS: usize>(
    blocks: &BlockTable<MAX_BLOCKS>,
    parent: u32,
    h: Option<u32>,
    node: u32,
) -> bool {
    let Some(h) = h else {
        return false;
    };
    let mut cur = parent;
    for _ in 0..h {
        let Some(entry) = blocks.get(cur) else {
            return false;
        };
        if entry.equivocator() == Some(node) {
            return true;
        }
        cur = entry.parent_ref();
    }
    false
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
    /// Story 6.13 AC3 (FR71 I-43; DEC-277, DEC-278, DEC-279) — the Tier-3 check
    /// of the twin fact block `view` at `idx`, whose parent (the tip) is the
    /// block the vote engine stands at. With `s` and `c` the proof header's
    /// sequence and creator, `P` the twins' parent and `q` the block's own
    /// sequence:
    ///
    /// 1. the branch's block `x` at `s` has creator `c` and parent `P`;
    /// 2. the proof differs from `x` (header bytes or payload hash);
    /// 3. the proof's FR70 signature verifies under `c`'s key;
    /// 4. `s ≥ S_tail` at the block, and no other fact block for `(c, s)` lies
    ///    in the parent's window;
    /// 5. the block opens a round (`m ≥ 1`) exactly when `q ≤ s + H − 1`;
    /// 6. a round's carried subgroup is the twin round's: `A` at `P` without
    ///    `c`, the seed of `(s, currency(P), c, j)` with `j` the creator's rank
    ///    at `q − 1` (D11: computed here, where `A` at `P` is retained);
    /// 7. the snapshot is `c`'s vote after the block's interest step.
    ///
    /// In a window-anchored FR3 pass with earliest block `a` a rule is checked
    /// only where its inputs lie in the segment (rule 1 at `s ≥ a`, 3 with `c`
    /// seeded, 4 at `q − W ≥ a`, 6 at `P − W + 1 ≥ a` with the roster and
    /// every vote known, 7 with `c`'s vote seeded); elsewhere it is trusted,
    /// as DEC-262 trusts an evidence block. A local fault is never evidence.
    #[inline(never)]
    pub(super) fn judge_twin_fact(
        &mut self,
        view: &BlockView<'_>,
        idx: u32,
        projection: &Projection,
    ) -> Result<(), ProcessingError> {
        let invalid = |reason| ProcessingError::Invalid {
            block_idx: idx,
            reason,
        };
        let Some(proof) = TwinFactView::from_payload(view.payload()) else {
            return Err(invalid(ValidationReason::MalformedPayload));
        };
        let Some(configuration) = self.chain_config.active_configuration() else {
            return Err(ProcessingError::StorageRead);
        };
        let (w, h, required_support) = (
            configuration.active_chain_length(),
            configuration.verification_horizon(),
            configuration.required_support(),
        );
        let (q, s, c) = (view.sequence(), proof.sequence(), proof.creator());
        let trusted_zone = projection.counter_tail == u32::MAX && !projection.complete;
        let tip = self
            .blocks
            .get(idx)
            .map_or(NONE_REF, |entry| entry.parent_ref());

        // 4a, 5. Pure arithmetic first.
        if u64::from(s) + u64::from(w) <= u64::from(q) {
            return Err(invalid(ValidationReason::TwinFactWindow));
        }
        let opens_round = u64::from(q) < u64::from(s) + u64::from(h);
        if opens_round != (proof.m() > 0) {
            return Err(invalid(ValidationReason::TwinFactKind));
        }
        // 1–2. The branch's own twin.
        match self.fact_own_twin(tip, &proof) {
            Reach::Holds => {}
            Reach::Fails => return Err(invalid(ValidationReason::TwinFactProof)),
            Reach::Below if trusted_zone => {}
            Reach::Below | Reach::Local => return Err(ProcessingError::StorageRead),
        }
        // 3. The proof's signature.
        let key = if c == 0 {
            Some(self.node_zero_public_key)
        } else {
            self.node_info.public_key_of(c).copied()
        };
        match key {
            Some(key) if !self.verify_fact_proof(&proof, &key) => {
                return Err(invalid(ValidationReason::TwinFactProof));
            }
            Some(_) => {}
            None if trusted_zone => {}
            None => return Err(ProcessingError::StorageRead),
        }
        // 4b. One fact block per `(c, s)` in the parent's window.
        match self.fact_unique(tip, w, c, s) {
            Ok(true) => {}
            Ok(false) => return Err(invalid(ValidationReason::TwinFactWindow)),
            Err(()) => return Err(ProcessingError::StorageRead),
        }
        // 6. The round's subgroup.
        if opens_round {
            let last_node = self.node_info.max_known_node_id().min(MAX_NODES as u32 - 1);
            let checkable = !trusted_zone
                || (s
                    .checked_sub(w)
                    .is_some_and(|bottom| bottom >= projection.anchor)
                    && projection.roster_bounded
                    && (0..=last_node).all(|n| self.vote_seeded_below(n, q, projection)));
            if checkable {
                let j = (0..=last_node)
                    .filter(|&n| self.vote_engine.ranks_above(n, view.creator()))
                    .count() as u32;
                match self.fact_subgroup_holds(tip, &proof, j, w, required_support, projection) {
                    Ok(true) => {}
                    Ok(false) => return Err(invalid(ValidationReason::TwinFactSubgroup)),
                    Err(()) => return Err(ProcessingError::StorageRead),
                }
            }
        }
        // 7. The snapshot, as I-09 checks `consumed_votes`.
        if projection.complete || self.vote_seeded(c, projection) {
            let grown = self
                .vote_engine
                .grown(self.vote_engine.accumulated_vote_of(c))
                .map_err(ProcessingError::Vote)?;
            if grown != proof.snapshot() {
                return Err(invalid(ValidationReason::TwinFactSnapshot));
            }
        }
        Ok(())
    }

    /// I-43 rules 1–2: the branch's block at the proof's sequence, read once
    /// in its own frame, is by the proof's creator on the proof's parent, and
    /// the proof is not that block (equal header bytes and payload hash are
    /// the same block; a block hash cannot be computed from a proof).
    #[inline(never)]
    fn fact_own_twin(&self, tip: u32, proof: &TwinFactView<'_>) -> Reach {
        let x = match self.ancestor_at(tip, proof.sequence()) {
            Ok(Some(x)) => x,
            Ok(None) => return Reach::Below,
            Err(_) => return Reach::Local,
        };
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let Some(own) = self.view_retained(x, &mut buf) else {
            return Reach::Local;
        };
        if own.creator() != proof.creator() || own.previous_hash() != proof.parent_hash() {
            return Reach::Fails;
        }
        let same = own.serialized_bytes()[..HEADER_SIZE] == *proof.proof_header()
            && calculate_hash(own.payload()) == *proof.proof_payload_hash();
        if same { Reach::Fails } else { Reach::Holds }
    }

    /// I-43 rule 3: the proof's FR70 signature under `key`, in its own frame.
    #[inline(never)]
    fn verify_fact_proof(&self, proof: &TwinFactView<'_>, key: &[u8; PUBLIC_KEY_SIZE]) -> bool {
        verify_signature_bytes(
            &self.crypto,
            &proof.proof_signing_preimage(),
            proof.proof_signature(),
            key,
        )
    }

    /// I-43 rule 4b: no fact block for `(c, s)` in the window ending at `tip`
    /// (`W` entries). A RAM walk over the cached equivocator; one read per
    /// fact block naming `c`, for its proof's sequence. `Err` on a failed read.
    #[inline(never)]
    pub(super) fn fact_unique(&self, tip: u32, w: u32, c: u32, s: u32) -> Result<bool, ()> {
        let mut cur = tip;
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        for _ in 0..w {
            let Some(entry) = self.blocks.get(cur) else {
                return Ok(true);
            };
            if entry.equivocator() == Some(c) {
                let view = self.view_retained(cur, &mut buf).ok_or(())?;
                if TwinFactView::from_payload(view.payload()).is_some_and(|p| p.sequence() == s) {
                    return Ok(false);
                }
            }
            cur = entry.parent_ref();
        }
        Ok(true)
    }

    /// I-43 rule 6 (DEC-277, DEC-278): whether the proof's carried subgroup is
    /// round `j`'s — `A` at `P` without `c`, ranked under the twin seed. In
    /// Ready and on the walk `A` at `P` is the counter corrected exactly: the
    /// active blocks `[s, q − 1]` leave (by creator, `leaving`), and the blocks
    /// `[s − W, tail − 1]` that left the counter since `P` return
    /// (`returned`); `n` is in `A` at `P` iff `returned(n) ∨ count(n) >
    /// leaving(n)`. At most `2(H − 1)` header reads, all retained (`q ≤ s + H −
    /// 1`). The FR3 pass has no counter, so it builds one over the window at
    /// `P` and leaves it invalid again. Its own frame: the two per-node arrays
    /// and the ranked list.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn fact_subgroup_holds(
        &mut self,
        tip: u32,
        proof: &TwinFactView<'_>,
        j: u32,
        w: u32,
        required_support: u8,
        projection: &Projection,
    ) -> Result<bool, ()> {
        let (s, c) = (proof.sequence(), proof.creator());
        let parent = s.checked_sub(1).ok_or(())?;
        let p_idx = self.ancestor_at(tip, parent).ok().flatten().ok_or(())?;
        let mut leaving = [0u8; MAX_NODES];
        let mut returned = [false; MAX_NODES];
        let in_pass = projection.counter_tail == u32::MAX;
        if in_pass {
            self.build_active_set_over(p_idx, s.saturating_sub(w));
        } else {
            let tip_seq = self.blocks.get(tip).ok_or(())?.sequence();
            for sequence in s..=tip_seq {
                let creator = self.creator_at(tip, sequence)? as usize;
                let slot = leaving.get_mut(creator).ok_or(())?;
                *slot = slot.saturating_add(1);
            }
            if let Some(last) = projection.counter_tail.checked_sub(1) {
                for sequence in s.saturating_sub(w)..=last {
                    let creator = self.creator_at(tip, sequence)? as usize;
                    *returned.get_mut(creator).ok_or(())? = true;
                }
            }
        }
        if !self.active_set.is_valid() {
            return Err(());
        }
        let set = &self.active_set;
        let member = |n: u32| {
            n != c && (returned[n as usize] || set.count_of(n) > u16::from(leaving[n as usize]))
        };
        let seed = twin_seed(s, self.circulating_currency_at(p_idx), c, j);
        let mut members = [0u32; MAX_SUBGROUP];
        let m = self.rank_members(member, &seed, required_support, &mut members);
        if in_pass {
            self.active_set.invalidate();
        }
        let m = m.unwrap_or(0);
        Ok(usize::from(proof.m()) == m
            && members[..m]
                .iter()
                .enumerate()
                .all(|(i, &n)| proof.member(i) == Some(n)))
    }

    /// The creator of the active-walk ancestor of `tip` at `sequence`, by one
    /// header read; `Err` when it is not held or not readable.
    fn creator_at(&self, tip: u32, sequence: u32) -> Result<u32, ()> {
        let idx = self.ancestor_at(tip, sequence).ok().flatten().ok_or(())?;
        self.header_at(idx).map(|(creator, _)| creator).ok_or(())
    }

    /// Story 6.13 AC5 (FR12, DEC-277) — the twin round's support for the
    /// admitted block `x`, a twin fact block. Only a validated one on the
    /// active chain (its parent on the node's chain, so a late twin's side,
    /// which no majority stands on, gathers nothing), a round-opening one,
    /// above the support floor, whose carried subgroup holds the local node.
    /// A retry (a deviation-form fact block) needs grace admission, as any
    /// deviation. One support per round: the ring entry `(c, s, round key)`.
    /// No support once an approval for a twin round of `(c, s)` is held. The
    /// signed content is the deviation's, with `x`'s creator as proposer.
    pub(super) fn evaluate_twin_support(
        &mut self,
        x_idx: u32,
        x_creator: u32,
        x_first_voted: u32,
    ) -> Option<SupportMessage> {
        let x = self.blocks.get(x_idx)?;
        if !x.is_on_active_chain() || !x.is_signature_verified() {
            return None;
        }
        let (q, x_hash) = (x.sequence(), *x.hash());
        if x_creator != x_first_voted && !self.grace_admits(x_creator) {
            return None;
        }
        let round = self.twin_round_of(x_idx)?;
        if round.s <= self.non_conflict.floor()
            || !round.local_member
            || self
                .non_conflict
                .holds(RING_KIND_TWIN, round.c, round.s, round.key)
            || self.holds_twin_approval(round.c, round.s) != Some(false)
            || !self
                .non_conflict
                .insert(RING_KIND_TWIN, round.c, round.s, round.key)
        {
            return None;
        }
        let bytes = support_message_bytes(x_creator, q, &x_hash);
        let support_signature = self.sign_support(&bytes);
        let local = self.local_node_id;
        let dedupe_key = self.support_dedupe.key(&support_body_tail(
            local,
            x_creator,
            &x_hash,
            &support_signature,
        ));
        if !self.support_dedupe.contains(q, dedupe_key, local) {
            self.support_dedupe.insert(q, dedupe_key, local);
        }
        Some(SupportMessage {
            supporter_node_id: local,
            proposer_node_id: x_creator,
            deviation_sequence: q,
            deviation_block_hash: x_hash,
            support_signature,
        })
    }

    /// The round a round-opening twin fact block at `idx` opens: its `c` and
    /// `s`, the round key (the first 4 bytes of the digest of its carried
    /// members, the same on both sides of a split in one round) and whether
    /// the local node is a member. `None` for a penalty-only block or a failed
    /// read. Its own frame.
    #[inline(never)]
    fn twin_round_of(&self, idx: u32) -> Option<TwinRound> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf)?;
        let proof = TwinFactView::from_payload(view.payload())?;
        let m = usize::from(proof.m());
        if m == 0 {
            return None;
        }
        let mut members = [0u8; 4 * MAX_SUBGROUP];
        let mut local_member = false;
        for i in 0..m {
            let member = proof.member(i)?;
            local_member |= member == self.local_node_id;
            members[4 * i..4 * i + 4].copy_from_slice(&member.to_le_bytes());
        }
        let digest = calculate_hash(&members[..4 * m]);
        Some(TwinRound {
            c: proof.creator(),
            s: proof.sequence(),
            key: u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]),
            local_member,
        })
    }

    /// FR26 on the active chain for a twin round's support (Story 6.13 AC5):
    /// `p` is the round-opening block `e_idx`; the signed proposer is its
    /// creator, no approval evidence lies above it, and the supporter is in
    /// its carried subgroup. A failed read defers the membership check, as
    /// (iv-b) is deferred.
    pub(super) fn on_chain_twin_support_holds(
        &self,
        e_idx: u32,
        p: u32,
        supporter: u32,
        proposer: u32,
    ) -> bool {
        let Some(s_head) = self
            .blocks
            .get(self.active_chain_head_idx)
            .map(BlockEntry::sequence)
        else {
            return true;
        };
        if self.active_above(e_idx, s_head - p + 1, None) == AboveP::Evidence {
            return false;
        }
        self.twin_member(e_idx, supporter, proposer).unwrap_or(true)
    }

    /// Whether `node` is in the carried subgroup of the round-opening fact
    /// block at `idx` and `proposer` is its creator; `None` on a failed read.
    /// Its own frame.
    #[inline(never)]
    fn twin_member(&self, idx: u32, node: u32, proposer: u32) -> Option<bool> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf)?;
        let proof = TwinFactView::from_payload(view.payload())?;
        Some(
            view.creator() == proposer
                && (0..usize::from(proof.m())).any(|i| proof.member(i) == Some(node)),
        )
    }

    /// The twin round's stop (Story 6.13 AC5): whether any held approval
    /// evidence closes a run opened by a fact block for `(c, s)`, on any
    /// branch. A RAM scan for type-4 entries, then reads for each; `None` on a
    /// failed read (the conservative side: no support).
    fn holds_twin_approval(&self, c: u32, s: u32) -> Option<bool> {
        let mut failed = false;
        for idx in 0..MAX_BLOCKS as u32 {
            let Some(entry) = self.blocks.get(idx) else {
                continue;
            };
            if entry.payload_type() != PAYLOAD_TYPE_APPROVAL || entry.sequence() <= s {
                continue;
            }
            let opener = match self.evidence_deviation(idx) {
                Some(Some(q)) => self.ancestor_at(idx, q).ok().flatten(),
                Some(None) => None,
                None => {
                    failed = true;
                    None
                }
            };
            let Some(opener) = opener else {
                continue;
            };
            if self.blocks.get(opener).and_then(BlockEntry::equivocator) != Some(c) {
                continue;
            }
            match self.fact_sequence(opener) {
                Some(seq) if seq == s => return Some(true),
                Some(_) => {}
                None => failed = true,
            }
        }
        (!failed).then_some(false)
    }

    /// The proof sequence of the twin fact block at `idx`; `None` on a failed
    /// read or a payload that does not frame. Its own frame.
    #[inline(never)]
    fn fact_sequence(&self, idx: u32) -> Option<u32> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf)?;
        TwinFactView::from_payload(view.payload()).map(|proof| proof.sequence())
    }

    /// Story 6.13 AC7 (DEC-276): whether the candidate segment above
    /// `x_sequence`, from `head` down, carries an approval evidence that
    /// closes a run opened by a twin fact block whose proof is the active twin
    /// `y`. A RAM walk over the cached payload type; reads only for approval
    /// entries. A failed read is no approval, so the hold stays. No approval
    /// state is kept: the candidate's own blocks say it.
    pub(super) fn approved_against(&self, head: u32, x_sequence: u32, y: u32) -> bool {
        let mut cur = head;
        while let Some(entry) = self.blocks.get(cur) {
            if entry.sequence() <= x_sequence {
                break;
            }
            if entry.payload_type() == PAYLOAD_TYPE_APPROVAL
                && let Some(Some(q)) = self.evidence_deviation(cur)
                && q > x_sequence
                && let Ok(Some(opener)) = self.ancestor_at(cur, q)
                && self
                    .blocks
                    .get(opener)
                    .is_some_and(|e| e.payload_type() == PAYLOAD_TYPE_TWIN_FACT)
                && self.fact_proves(opener, y) == Some(true)
            {
                return true;
            }
            cur = entry.parent_ref();
        }
        false
    }

    /// Whether the twin fact block at `fact` is round-opening and proves the
    /// block at `twin` (its header bytes and payload hash); `None` on a failed
    /// read. One buffer, read twice, in its own frame.
    #[inline(never)]
    fn fact_proves(&self, fact: u32, twin: u32) -> Option<bool> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let (header, payload_hash) = {
            let view = self.view_retained(twin, &mut buf)?;
            let mut header = [0u8; HEADER_SIZE];
            header.copy_from_slice(&view.serialized_bytes()[..HEADER_SIZE]);
            (header, calculate_hash(view.payload()))
        };
        let view = self.view_retained(fact, &mut buf)?;
        let proof = TwinFactView::from_payload(view.payload())?;
        Some(
            proof.m() > 0
                && *proof.proof_header() == header[..]
                && *proof.proof_payload_hash() == payload_hash[..],
        )
    }

    /// The ranked subgroup the round-opening twin fact block at `idx` carries,
    /// into `out` (Story 6.13 AC4, D11); its `m`, 0 for a penalty-only block;
    /// `None` on a failed read. Its own frame.
    #[inline(never)]
    pub(super) fn fact_members(&self, idx: u32, out: &mut [u32; MAX_SUBGROUP]) -> Option<usize> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf)?;
        let proof = TwinFactView::from_payload(view.payload())?;
        let m = usize::from(proof.m());
        for (i, slot) in out.iter_mut().enumerate().take(m) {
            *slot = proof.member(i)?;
        }
        Some(m)
    }

    /// Whether the held twin fact block at `idx` opens a round (`m ≥ 1`, Story
    /// 6.13 T2); `Err` on a failed read. Its own read buffer.
    #[inline(never)]
    pub(super) fn opens_round_at(&self, idx: u32) -> Result<bool, ()> {
        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let view = self.view_retained(idx, &mut buf).ok_or(())?;
        Ok(TwinFactView::from_payload(view.payload()).is_some_and(|proof| proof.m() > 0))
    }
}
